from hashlib import sha256
from base64 import urlsafe_b64encode
import socket
import socks
import ssl
import os
import datetime
import curses
import re
import threading
import time
import json

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.exceptions import InvalidSignature
from secrets import token_hex
from base64 import b64encode, b64decode

IRC_LINE_RE = re.compile(r"^:(?P<nick>[^!]+)!\S+ PRIVMSG (?P<target>[^ ]+) :(?P<msg>.*)$")
PING_RE = re.compile(r"^PING :(.+)$")
ERROR_RE = re.compile(r"^ERROR :(.+)$")
WELCOME_RE = re.compile(r"^:\S+ 001 ")
ENC_PREFIX = "!enc "
KEY_PREFIX = "!key "
DH_PREFIX = "!dh "
MAX_RETRIES = 5
PAD_BUCKETS = [64, 128, 256, 512, 1024, 2048, 4096, 8192]
DATA_DIR = os.path.expanduser("~/.config/onion-chat")
SIG_LEN = 64
DH_PUB_LEN = 32
NONCE_LEN = 12


def _pad(plaintext: bytes) -> bytes:
    need = len(plaintext) + 1
    bucket = next((b for b in PAD_BUCKETS if b >= need), PAD_BUCKETS[-1])
    pad_len = bucket - need
    return bytes([pad_len]) + plaintext + os.urandom(pad_len)


def _unpad(padded: bytes) -> bytes:
    if not padded:
        return padded
    pad_len = padded[0]
    if pad_len + 1 > len(padded):
        return padded
    return padded[1: len(padded) - pad_len]


def _ed2x_priv(ed_priv: Ed25519PrivateKey) -> X25519PrivateKey:
    raw = ed_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return X25519PrivateKey.from_private_bytes(raw[:32])


def _ed2x_pub(ed_pub: Ed25519PublicKey) -> X25519PublicKey:
    raw = ed_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return X25519PublicKey.from_public_bytes(raw)


def _x_pub_raw(x_priv: X25519PrivateKey) -> bytes:
    return x_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _x_pub_b64(x_priv: X25519PrivateKey) -> str:
    pub = x_priv.public_key()
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64encode(raw).decode("ascii")


def _load_x_pub(raw: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(raw)


def _kdf_chain_key(base: bytes, info: bytes) -> tuple[bytes, bytes]:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=info)
    out = hkdf.derive(base)
    return out[:32], out[32:]


class Identity:
    def __init__(self, priv: Ed25519PrivateKey):
        self.priv = priv
        self.pub = priv.public_key()
        raw = self.pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.fingerprint = sha256(raw).hexdigest()[:16]
        self.pub_b64 = b64encode(raw).decode("ascii")

    def sign(self, data: bytes) -> bytes:
        return self.priv.sign(data)

    @classmethod
    def load_or_create(cls, path: str) -> "Identity":
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            with open(path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
        else:
            priv = Ed25519PrivateKey.generate()
            with open(path, "wb") as f:
                f.write(priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            os.chmod(path, 0o600)
        return cls(priv)


class Session:
    def __init__(self, root_key: bytes, send_key: bytes, recv_key: bytes):
        self.root_key = root_key
        self.send_key = send_key
        self.recv_key = recv_key
        self.send_count = 0
        self.recv_count = 0

    def next_send(self) -> bytes:
        self.send_key, msg_key = _kdf_chain_key(self.send_key, b"send")
        self.send_count += 1
        return msg_key

    def next_recv(self) -> bytes:
        self.recv_key, msg_key = _kdf_chain_key(self.recv_key, b"recv")
        self.recv_count += 1
        return msg_key


class GroupSession:
    def __init__(self, group_key: bytes, my_seed: bytes):
        self.group_key = group_key
        self.my_seed = my_seed
        self.send_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=group_key,
            info=b"send-" + my_seed,
        ).derive(b"")
        self.recv_keys: dict[str, bytes] = {}
        self.send_count = 0
        self.recv_counts: dict[str, int] = {}

    def next_send(self) -> tuple[bytes, int]:
        self.send_key, msg_key = _kdf_chain_key(self.send_key, b"chain-" + self.my_seed)
        self.send_count += 1
        return msg_key, self.send_count

    def recv_at(self, peer_seed: bytes, counter: int) -> bytes | None:
        key = self.recv_keys.get(peer_seed)
        if key is None:
            key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=self.group_key,
                info=b"send-" + peer_seed,
            ).derive(b"")
            self.recv_keys[peer_seed] = key
            self.recv_counts[peer_seed] = 0
        current = self.recv_counts[peer_seed]
        if counter <= current:
            return None
        msg_key = None
        while current < counter:
            key, mk = _kdf_chain_key(key, b"chain-" + peer_seed)
            current += 1
            if current == counter:
                msg_key = mk
        self.recv_keys[peer_seed] = key
        self.recv_counts[peer_seed] = current
        return msg_key

    def next_recv(self, peer_seed: bytes) -> tuple[bytes, int]:
        key = self.recv_keys.get(peer_seed)
        if key is None:
            key = HKDF(
                algorithm=hashes.SHA256(), length=32, salt=self.group_key,
                info=b"send-" + peer_seed,
            ).derive(b"")
            self.recv_keys[peer_seed] = key
            self.recv_counts[peer_seed] = 0
        key, msg_key = _kdf_chain_key(key, b"chain-" + peer_seed)
        self.recv_keys[peer_seed] = key
        self.recv_counts[peer_seed] = self.recv_counts.get(peer_seed, 0) + 1
        return msg_key, self.recv_counts[peer_seed]


class Crypto:
    def __init__(self, group_key: bytes, identity: Identity):
        self.group_key = group_key
        self.identity = identity
        self.hmac_key = group_key
        self.x_priv = _ed2x_priv(identity.priv)
        self.peer_x_pubs: dict[str, X25519PublicKey] = {}
        self.sessions: dict[str, Session] = {}
        my_seed = os.urandom(16)
        self.group = GroupSession(group_key, my_seed)

    def _mac(self, data: bytes) -> bytes:
        h = HMAC(self.hmac_key, hashes.SHA256())
        h.update(data)
        return h.finalize()

    def _verify_mac(self, data: bytes, mac: bytes) -> bool:
        h = HMAC(self.hmac_key, hashes.SHA256())
        h.update(data)
        try:
            h.verify(mac)
            return True
        except Exception:
            return False

    def make_key_announce(self, nick: str) -> str:
        pub_raw = b64decode(self.identity.pub_b64)
        mac = self._mac(nick.encode("utf-8") + pub_raw)
        return KEY_PREFIX + self.identity.pub_b64 + " " + b64encode(mac).decode("ascii")

    def verify_key_announce(self, nick: str, body: str) -> bytes | None:
        parts = body.split(" ")
        if len(parts) != 2:
            return None
        try:
            pub_raw = b64decode(parts[0])
            mac = b64decode(parts[1])
        except Exception:
            return None
        if not self._verify_mac(nick.encode("utf-8") + pub_raw, mac):
            return None
        return pub_raw

    def _establish_session(self, peer_nick: str, peer_x: X25519PublicKey) -> Session:
        my_x = X25519PrivateKey.generate()
        shared = my_x.exchange(peer_x)
        root_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=self.group_key,
            info=b"session-root",
        ).derive(shared)
        send_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=root_key,
            info=b"send-" + self.identity.fingerprint.encode(),
        ).derive(b"")
        recv_key = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=root_key,
            info=b"recv-" + self.identity.fingerprint.encode(),
        ).derive(b"")
        sess = Session(root_key, send_key, recv_key)
        sess.my_ephemeral = my_x
        self.sessions[peer_nick] = sess
        return sess

    def encrypt(self, plaintext: str) -> str:
        msg_key, counter = self.group.next_send()
        padded = _pad(plaintext.encode("utf-8"))
        nonce = os.urandom(NONCE_LEN)
        aesgcm = AESGCM(msg_key)
        ct = aesgcm.encrypt(nonce, padded, None)
        sig = self.identity.sign(nonce + ct)
        payload = (
            b64encode(self.group.my_seed).decode("ascii")
            + "." + str(counter)
            + "." + b64encode(nonce + ct + sig).decode("ascii")
        )
        return ENC_PREFIX + payload

    def decrypt(self, blob: str, sender_pub: Ed25519PublicKey | None
                ) -> tuple[str | None, str | None]:
        if not blob.startswith(ENC_PREFIX):
            return None, None
        body = blob[len(ENC_PREFIX):]
        try:
            seed_b64, counter_b64, ct_b64 = body.split(".", 2)
            counter = int(counter_b64)
            raw = b64decode(ct_b64)
        except Exception:
            return None, None
        if len(raw) < NONCE_LEN + SIG_LEN:
            return None, None
        nonce, ct, sig = raw[:NONCE_LEN], raw[NONCE_LEN:-SIG_LEN], raw[-SIG_LEN:]
        if sender_pub is not None:
            try:
                sender_pub.verify(sig, nonce + ct)
            except InvalidSignature:
                return None, "bad-signature"
            except Exception:
                return None, "bad-signature"
        try:
            seed = b64decode(seed_b64)
        except Exception:
            return None, None
        msg_key = self.group.recv_at(seed, counter)
        if msg_key is None:
            return None, "replay-or-dup"
        try:
            aesgcm = AESGCM(msg_key)
            padded = aesgcm.decrypt(nonce, ct, None)
            return _unpad(padded).decode("utf-8", "replace"), None
        except Exception:
            return None, "decrypt-failed"


def _load_pubkey(raw: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(raw)


class IRCClient:
    def __init__(self, ui: "ChatUI", host: str, port: int, nick: str,
                 channel: str, proxy_host: str, proxy_port: int, crypto: Crypto,
                 use_tls: bool = True, use_onion: bool = False):
        self.ui = ui
        self.host = host
        self.port = port
        self.nick = nick
        self.channel = channel
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.crypto = crypto
        self.use_tls = use_tls
        self.use_onion = use_onion
        self.sock: socks.socksocket | None = None
        self.connected = False
        self.running = True
        self.fatal = False
        self.peer_keys: dict[str, Ed25519PublicKey] = {}
        self._announced = False
        self._announce_timer = 0.0

    def connect(self):
        last_err = ""
        attempts = 0
        while self.running and attempts < MAX_RETRIES:
            attempts += 1
            try:
                self.sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.set_proxy(socks.PROXY_TYPE_SOCKS5, self.proxy_host, self.proxy_port, rdns=True)
                self.sock.settimeout(120)
                self.sock.connect((self.host, self.port))
                if self.use_tls:
                    ctx = ssl.create_default_context()
                    if self.use_onion:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)
                self.sock.settimeout(5)
                self._send_raw(f"NICK {self.nick}")
                self._send_raw(f"USER {self.nick} 0 * :{self.nick}")
                if not self._wait_for_welcome():
                    continue
                self._send_raw(f"JOIN {self.channel}")
                self.connected = True
                self._announced = False
                self.ui.system(f"* connected to {self.host}:{self.port} (TLS)")
                self.ui.system(f"* joined {self.channel}")
                self.ui.system(f"* your fingerprint: {self.crypto.identity.fingerprint}")
                return True
            except Exception as e:
                err = str(e)
                if err != last_err:
                    self.ui.system(f"* connect error: {err}, retrying ({attempts}/{MAX_RETRIES})...")
                    last_err = err
                try:
                    if self.sock:
                        self.sock.close()
                except Exception:
                    pass
                self.sock = None
                for _ in range(20):
                    if not self.running:
                        return False
                    time.sleep(0.5)
        self.fatal = True
        self.ui.system("* giving up after max retries. type /reconnect to retry.")
        return False

    def _wait_for_welcome(self) -> bool:
        deadline = time.time() + 30
        buf = b""
        while time.time() < deadline and self.running and self.sock:
            try:
                chunk = self.sock.recv(4096)
            except socket.timeout:
                continue
            except Exception:
                return False
            if not chunk:
                return False
            buf += chunk
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                text = line.decode("utf-8", "replace")
                if WELCOME_RE.match(text):
                    return True
                em = ERROR_RE.match(text)
                if em:
                    self.ui.system(f"* server error: {em.group(1)}")
                    return False
                self._handle(text)
        return False

    def _send_raw(self, data: str):
        if not self.sock:
            return
        try:
            self.sock.sendall((data + "\r\n").encode("utf-8", "replace"))
        except Exception:
            self.connected = False

    def send_privmsg(self, target: str, msg: str):
        enc = self.crypto.encrypt(msg)
        self._send_raw(f"PRIVMSG {target} :{enc}")

    def announce_key(self, target: str):
        ann = self.crypto.make_key_announce(self.nick)
        self._send_raw(f"PRIVMSG {target} :{ann}")
        self._announced = True

    def request_keys(self, target: str):
        self._send_raw(f"PRIVMSG {target} :{KEY_PREFIX}req")

    def _run_loop(self):
        while self.running:
            if self.fatal:
                time.sleep(0.5)
                continue
            if not self.connect():
                continue
            buf = b""
            while self.running and self.sock:
                if self.connected and not self._announced:
                    self.announce_key(self.channel)
                    self.request_keys(self.channel)
                try:
                    chunk = self.sock.recv(4096)
                except socket.timeout:
                    continue
                except Exception:
                    self.ui.system("* connection lost, reconnecting...")
                    self.connected = False
                    break
                if not chunk:
                    self.ui.system("* disconnected, reconnecting...")
                    self.connected = False
                    break
                buf += chunk
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    self._handle(line.decode("utf-8", "replace"))

    def _handle(self, line: str):
        m = IRC_LINE_RE.match(line)
        if m:
            target = m.group("target")
            sender = m.group("nick")
            msg = m.group("msg")
            display = target if target.startswith("#") else sender
            if sender == self.nick:
                return
            if msg.startswith(KEY_PREFIX):
                body = msg[len(KEY_PREFIX):]
                if body == "req":
                    if self._announced:
                        self.announce_key(display)
                    return
                raw = self.crypto.verify_key_announce(sender, body)
                if raw is None:
                    self.ui.system(f"* {sender}: invalid key announcement (imposter or wrong channel secret)")
                    return
                try:
                    pub = _load_pubkey(raw)
                except Exception:
                    return
                fp = sha256(raw).hexdigest()[:16]
                prev = self.peer_keys.get(sender)
                if prev is None:
                    self.ui.system(f"* {sender} fingerprint: {fp}")
                else:
                    old_fp = sha256(
                        prev.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
                    ).hexdigest()[:16]
                    if old_fp != fp:
                        self.ui.system(f"* WARNING: {sender} fingerprint changed {old_fp} -> {fp}")
                self.peer_keys[sender] = pub
                return
            if msg.startswith(ENC_PREFIX):
                pub = self.peer_keys.get(sender)
                if pub is None:
                    self.ui.system(f"* encrypted msg from {sender} but no key known — requesting...")
                    self.request_keys(display)
                    return
                dec, err = self.crypto.decrypt(msg, pub)
                if dec is not None:
                    self.ui.add_line(display, sender, dec)
                elif err == "bad-signature":
                    self.ui.system(f"* {sender}: signature verification FAILED — possible forgery")
                else:
                    self.ui.system(f"* {sender}: decrypt failed (wrong channel secret?)")
                return
            return
        m = PING_RE.match(line)
        if m:
            self._send_raw(f"PONG :{m.group(1)}")
            return
        em = ERROR_RE.match(line)
        if em:
            self.ui.system(f"* server error: {em.group(1)}")
            return

    def start(self):
        threading.Thread(target=self._run_loop, daemon=True).start()

    def stop(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass


class ChatUI:
    STATUS = "*status*"

    def __init__(self, stdscr: curses.window, nick: str, channel: str, server: str,
                 port: int, use_tls: bool, crypto: "Crypto", identity: "Identity",
                 proxy_host: str, proxy_port: int):
        self.stdscr = stdscr
        self.nick = nick
        self.channel = channel
        self.server = server
        self.port = port
        self.use_tls = use_tls
        self.crypto = crypto
        self.identity = identity
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.current = channel
        self.buffers: dict[str, list[tuple[str, str, str]]] = {self.STATUS: [], channel: []}
        self.input = ""
        self.cursor = 0
        self.running = True
        self.lock = threading.Lock()
        self.irc: IRCClient | None = None
        self._setup()

    def _setup(self):
        curses.curs_set(1)
        self.stdscr.timeout(50)
        self.h, self.w = self.stdscr.getmaxyx()

    def add_line(self, target: str, nick: str, msg: str, kind: str = "msg"):
        buf = self.buffers.setdefault(target, [])
        ts = datetime.datetime.now().strftime("%H:%M")
        buf.append((ts, nick, msg if kind == "msg" else f"* {msg}"))
        if len(buf) > 1000:
            del buf[:200]

    def system(self, text: str, target: str | None = None):
        self.add_line(target or self.current, "", text, kind="sys")

    def draw(self):
        self.h, self.w = self.stdscr.getmaxyx()
        log_h = self.h - 3
        self.stdscr.erase()
        self._draw_log(log_h)
        self._draw_status(log_h)
        self._draw_input(log_h + 2)
        self.stdscr.refresh()

    def _draw_log(self, log_h: int):
        buf = self.buffers.get(self.current, [])
        start = max(0, len(buf) - log_h)
        for i, (ts, nick, msg) in enumerate(buf[start:], start=0):
            y = i
            if y >= log_h:
                break
            line = f"[{ts}] "
            if nick:
                color = 2 if nick == self.nick else 3
                line += f"<{nick}> {msg}"
                self._safe_addstr(y, 0, line[: self.w], curses.color_pair(color))
            else:
                self._safe_addstr(y, 0, line + msg, curses.color_pair(5))

    def _draw_status(self, y: int):
        if self.current == self.STATUS:
            bar = f" [*status*] MENU -- {self.server} -- nick={self.nick} "
        else:
            mode = "CHANNEL" if self.current.startswith("#") else "QUERY"
            bar = f" [{self.current}] {mode} -- {self.server} -- nick={self.nick} "
        self._safe_addstr(y, 0, bar.ljust(self.w)[: self.w], curses.color_pair(4) | curses.A_REVERSE)

    def _draw_input(self, y: int):
        if self.current == self.STATUS:
            prompt = ">>> "
            color = curses.color_pair(4)
        else:
            prompt = f"{self.nick}> "
            color = curses.color_pair(2)
        text = self.input
        maxw = self.w - len(prompt) - 1
        vis = text[max(0, self.cursor - maxw): self.cursor + maxw]
        self._safe_addstr(y, 0, prompt, color)
        self._safe_addstr(y, len(prompt), vis[:maxw])
        try:
            self.stdscr.move(y, len(prompt) + min(self.cursor, maxw))
        except curses.error:
            pass

    def _safe_addstr(self, y, x, s, attr=0):
        if y < 0 or x < 0 or y >= self.h or x >= self.w:
            return
        try:
            self.stdscr.addnstr(y, x, s, self.w - x, attr)
        except curses.error:
            pass

    def handle_key(self, ch: int) -> bool:
        if ch == -1:
            return False
        if ch == 24:
            names = list(self.buffers.keys())
            if len(names) > 1:
                idx = names.index(self.current) if self.current in names else 0
                self.current = names[(idx + 1) % len(names)]
            return True
        if ch in (curses.KEY_ENTER, 10, 13):
            return self._submit()
        if ch in (curses.KEY_BACKSPACE, 8, 127):
            if self.cursor > 0:
                self.input = self.input[: self.cursor - 1] + self.input[self.cursor:]
                self.cursor -= 1
            return True
        if ch == curses.KEY_LEFT and self.cursor > 0:
            self.cursor -= 1
            return True
        if ch == curses.KEY_RIGHT and self.cursor < len(self.input):
            self.cursor += 1
            return True
        if ch == curses.KEY_HOME or ch == 1:
            self.cursor = 0
            return True
        if ch == curses.KEY_END or ch == 5:
            self.cursor = len(self.input)
            return True
        if ch == 21:
            self.input, self.cursor = "", 0
            return True
        if ch == 23:
            i = self.cursor
            while i > 0 and self.input[i - 1] == " ":
                i -= 1
            while i > 0 and self.input[i - 1] != " ":
                i -= 1
            self.input = self.input[:i] + self.input[self.cursor:]
            self.cursor = i
            return True
        if 32 <= ch <= 126:
            self.input = self.input[: self.cursor] + chr(ch) + self.input[self.cursor:]
            self.cursor += 1
            return True
        return False

    def _submit(self) -> bool:
        line = self.input.strip()
        self.input, self.cursor = "", 0
        if not line:
            return True
        if line.startswith("/"):
            return self._command(line[1:])
        if self.current == self.STATUS:
            self.system(f"* press /menu for settings or Ctrl+X to switch to channel")
            return True
        self.add_line(self.current, self.nick, line)
        if self.irc and self.irc.connected:
            self.irc.send_privmsg(self.current, line)
        return True

    def _command(self, cmd: str) -> bool:
        parts = cmd.split(maxsplit=1)
        name = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else ""
        if name == "exit":
            self.running = False
            return True
        if name == "quit":
            self.running = False
            return True
        if name == "menu" or name == "status":
            self.current = self.STATUS
            self._show_menu()
            return True
        if name == "help":
            self.system("commands:")
            self.system("  /menu            open settings menu")
            self.system("  /join #channel   join/switch to channel")
            self.system("  /query nick      open private chat")
            self.system("  /close           close current buffer")
            self.system("  /clear           clear current buffer")
            self.system("  /buffers         list open buffers")
            self.system("  /nick <nick>     change nickname (reconnects)")
            self.system("  /set <key> <val> set: server, port, tls, channel, info, secret, nick")
            self.system("  /connect         reconnect with current settings")
            self.system("  /reconnect       force reconnect")
            self.system("  /exit            quit onion-chat")
            self.system("Ctrl+X switches buffers")
            return True
        if name == "join" and arg:
            self.current = arg if arg.startswith("#") else f"#{arg}"
            self.buffers.setdefault(self.current, [])
            if self.irc and self.irc.connected:
                self.irc.channel = self.current
                self.irc._send_raw(f"JOIN {self.current}")
            return True
        if name == "query" and arg:
            self.current = arg
            self.buffers.setdefault(self.current, [])
            return True
        if name == "close":
            if self.current != self.STATUS:
                del self.buffers[self.current]
                self.current = self.STATUS
            return True
        if name == "buffers":
            for name_ in self.buffers:
                mark = " *" if name_ == self.current else ""
                self.system(f"  {name_}{mark}")
            return True
        if name == "clear":
            self.buffers[self.current] = []
            return True
        if name == "nick" and arg:
            self.nick = arg
            self.system(f"* nick set to {arg}, use /connect to apply")
            return True
        if name == "set" and arg:
            return self._set_setting(arg)
        if name == "connect":
            self._do_connect()
            return True
        if name == "reconnect":
            if self.irc:
                self.irc.fatal = False
                try:
                    if self.irc.sock:
                        self.irc.sock.close()
                except Exception:
                    pass
                self.irc.connected = False
                self.system("* forcing reconnect...")
            return True
        self.system(f"unknown command: /{cmd}  (try /help)")
        return True

    def _set_setting(self, arg: str) -> bool:
        kv = arg.split(maxsplit=1)
        if len(kv) != 2:
            self.system("* usage: /set <key> <value>")
            self.system("* keys: server, port, tls, channel, info, secret, nick")
            return True
        key, val = kv[0].lower(), kv[1]
        if key == "server":
            self.server = val
            self.system(f"* server = {val}")
        elif key == "port":
            try:
                self.port = int(val)
                self.system(f"* port = {self.port}")
            except ValueError:
                self.system("* port must be a number")
        elif key == "tls":
            self.use_tls = val not in ("0", "off", "false", "no")
            self.system(f"* tls = {self.use_tls}")
        elif key == "channel":
            self.channel = val if val.startswith("#") else f"#{val}"
            self.system(f"* channel = {self.channel}")
        elif key == "info":
            self._new_info = val
            self.system(f"* info set (apply with /connect)")
        elif key == "secret":
            self._new_secret = val
            self.system(f"* secret set (apply with /connect)")
        elif key == "nick":
            self.nick = val
            self.system(f"* nick = {val}")
        else:
            self.system(f"* unknown key: {key}")
            return True
        return True

    def _show_menu(self):
        self.system("=== settings menu ===")
        self.system(f"  server:  {self.server}")
        self.system(f"  port:    {self.port}")
        self.system(f"  tls:     {self.use_tls}")
        self.system(f"  channel: {self.channel}")
        self.system(f"  nick:    {self.nick}")
        self.system(f"  identity fingerprint: {self.identity.fingerprint}")
        self.system("use /set <key> <value> to change, /connect to apply")

    def _do_connect(self):
        if self.irc:
            self.irc.stop()
            self.irc = None
        if getattr(self, "_new_info", None) and getattr(self, "_new_secret", None):
            info_b = self._new_info.encode("utf-8")
            salt = compute_salt(info_b)
            hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info_b)
            enc_key = hkdf.derive(self._new_secret.encode())
            self.crypto = Crypto(enc_key, self.identity)
            self._new_info = None
            self._new_secret = None
            self.system("* crypto keys updated")
        use_onion = self.server.endswith(".onion")
        self.irc = IRCClient(self, self.server, self.port, self.nick, self.channel,
                             self.proxy_host, self.proxy_port, self.crypto, self.use_tls, use_onion)
        self.system(f"* connecting to {self.server}:{self.port}"
                    + (f" (TLS)" if self.use_tls else " (plaintext)"))
        self.irc.start()

    def get_input(self) -> str | None:
        return None

def compute_salt(info: bytes, nonce_len: int = 16) -> bytes:
    a = info[:nonce_len]
    b = info[nonce_len:]
    sorted_nonces = sorted([a, b])
    return sorted_nonces[0] + sorted_nonces[1]

def prepare_message(channel: str, message: str) -> str:
    timestamp = datetime.datetime.now()\
        .strftime("%Y-%m-%d %H:%M:%S")
    return f"PRIVMSG {channel}: [{timestamp}] @> {message}"


def _show_share_dialog(stdscr: curses.window, secret_file: str, channel: str):
    curses.curs_set(0)
    stdscr.timeout(-1)
    h, w = stdscr.getmaxyx()
    lines = [
        "### CHANNEL INVITE - share with people you want to chat ###",
        f"CHANNEL: {channel}",
        f"SECRET file: {secret_file}",
        "",
        "Send the SECRET file out-of-band (e.g. via OnionShare).",
        "Do NOT paste it in scrollback or logs.",
        "",
        "Press any key to continue...",
    ]
    box_w = max(len(l) for l in lines) + 4
    box_h = len(lines) + 2
    box_w = min(box_w, w)
    box_h = min(box_h, h)
    by = (h - box_h) // 2
    bx = (w - box_w) // 2
    win = curses.newwin(box_h, box_w, by, bx)
    win.keypad(True)
    win.bkgd(curses.color_pair(5))
    win.border(0)
    for i, l in enumerate(lines):
        try:
            win.addstr(1 + i, 2, l[: box_w - 4], curses.color_pair(5) | curses.A_BOLD)
        except curses.error:
            pass
    win.refresh()
    win.getch()
    del win
    stdscr.timeout(50)
    curses.curs_set(1)
    stdscr.touchwin()
    stdscr.refresh()


def _write_secret_file(path: str, info: str, secret: str, channel: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = {"INFO": info, "SECRET_PHRASE": secret, "CHANNEL": channel}
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    os.chmod(path, 0o600)


def _run(stdscr: curses.window):
    secret_path = os.environ.get("SECRET_FILE") or os.path.join(DATA_DIR, "channel-secret.json")
    env_info = os.environ.get("INFO")
    env_secret = os.environ.get("SECRET_PHRASE")
    env_channel = os.environ.get("CHANNEL")

    if env_info and env_secret and env_channel:
        info = env_info
        S = env_secret
        channel = env_channel
    elif os.path.exists(secret_path):
        with open(secret_path) as f:
            d = json.load(f)
        info = d["INFO"]
        S = d["SECRET_PHRASE"]
        channel = d["CHANNEL"]
    else:
        info = token_hex(16)
        S = token_hex(32)
        channel = "#" + token_hex(16)
        _write_secret_file(secret_path, info, S, channel)

    info_b = info.encode("utf-8")
    salt = compute_salt(info_b)

    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_WHITE, -1)
    curses.init_pair(2, curses.COLOR_CYAN, -1)
    curses.init_pair(3, curses.COLOR_GREEN, -1)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    curses.init_pair(5, curses.COLOR_RED, -1)

    if not (env_info and env_secret and env_channel) and not os.environ.get("SECRET_FILE"):
        _show_share_dialog(stdscr, secret_path, channel)

    TOR_PROXY_HOST = "127.0.0.1"
    TOR_PROXY_PORT = 9050

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info_b)
    enc_key = hkdf.derive(S.encode())

    server = os.environ.get("IRC_SERVER") or "irc.oftc.net"
    port = int(os.environ.get("IRC_PORT") or "6697")
    use_tls = (os.environ.get("IRC_TLS") or "1") not in ("0", "false", "no")
    nick = os.environ.get("NICK") or f"anon{token_hex(8)}"

    identity = Identity.load_or_create(os.path.join(DATA_DIR, "identity.pem"))
    crypto = Crypto(enc_key, identity)
    ui = ChatUI(stdscr, nick, channel, server, port, use_tls, crypto, identity,
                TOR_PROXY_HOST, TOR_PROXY_PORT)
    irc = IRCClient(ui, server, port, nick, channel, TOR_PROXY_HOST, TOR_PROXY_PORT,
                    crypto, use_tls, server.endswith(".onion"))
    ui.irc = irc
    ui.system(f"* connecting to {server}:{port} via Tor {TOR_PROXY_HOST}:{TOR_PROXY_PORT}"
              + (f" (TLS)" if use_tls else " (plaintext)"))
    ui.system(f"* channel: {channel}")
    ui.system(f"* identity: {identity.fingerprint}")
    if not (env_info and env_secret and env_channel):
        ui.system(f"* channel secret file: {secret_path}")
    ui.system(f"* /help for commands, /menu for settings, Ctrl+X switches buffers")
    irc.start()
    while ui.running:
        ch = stdscr.getch()
        if ch != -1:
            ui.handle_key(ch)
        ui.draw()
    irc.stop()
    curses.endwin()


def main():
    curses.wrapper(_run)


if __name__ == "__main__":
    main()
