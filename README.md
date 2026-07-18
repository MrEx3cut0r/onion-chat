# onion-chat

Anonymous encrypted IRC chat over Tor.

- AES-256-GCM + Ed25519 signatures
- Per-sender ratchet chain (PFS/PCS)
- Message padding against traffic analysis
- Identity keys persisted in `~/.config/onion-chat/`

## Install

```bash
pip install -e .
```

Requires Tor on `127.0.0.1:9050`.

## Run

```bash
onion-chat
```

First run generates `~/.config/onion-chat/channel-secret.json`. Share it with peers out-of-band (OnionShare/USB/in person). Never paste it in logs.

To join a peer's channel, place their `channel-secret.json` in `~/.config/onion-chat/` and run.

## Env

| Var | Default |
|---|---|
| `IRC_SERVER` | `irc.oftc.net` |
| `IRC_PORT` | `6697` |
| `IRC_TLS` | `1` |
| `NICK` | `anon<random>` |
| `INFO` | from file |
| `SECRET_PHRASE` | from file |
| `CHANNEL` | from file |
| `SECRET_FILE` | `~/.config/onion-chat/channel-secret.json` |

## Keys

| File | Purpose |
|---|---|
| `~/.config/onion-chat/identity.pem` | Ed25519 identity key (persistent, 0600) |
| `~/.config/onion-chat/channel-secret.json` | Channel + INFO + SECRET_PHRASE (0600) |

## Commands

Type in any buffer.

| Command | Action |
|---|---|
| `/help` | list commands |
| `/menu` | open settings menu (`*status*`) |
| `/join #chan` | join/switch channel |
| `/query nick` | open private chat |
| `/close` | close current buffer |
| `/clear` | clear current buffer |
| `/buffers` | list open buffers |
| `/nick <name>` | change nickname |
| `/set <key> <val>` | change setting (see below) |
| `/connect` | apply settings and connect |
| `/reconnect` | force reconnect |
| `/exit` | quit |

`Ctrl+X` switches between buffers.

### `/set` keys

| Key | Values |
|---|---|
| `server` | IRC server |
| `port` | IRC port |
| `tls` | `0`/`1` |
| `channel` | `#name` |
| `nick` | nickname |
| `info` | HKDF info (applied with `/connect`) |
| `secret` | HKDF secret (applied with `/connect`) |

`/connect` reuses the existing channel key unless both `info` and `secret` are set via `/set`.