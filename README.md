# onion-chat

Fully anonymous encrypted IRC chat over Tor.

- AES-256-GCM + Ed25519 signatures
- Per-sender ratchet chain (PFS/PCS)
- Message padding against traffic analysis
- Identity keys persisted in `~/.config/onion-chat/`

## Install

```bash
pip install -e .
```

## Run

```bash
onion-chat
```

First run generates `~/.config/onion-chat/channel-secret.json` — share it with peers out-of-band (OnionShare/USB/in person). Never paste it in logs.

To join a peer's channel, place their `channel-secret.json` in `~/.config/onion-chat/` and run.

## Env

| Var | Default |
|---|---|
| `IRC_SERVER` | `irc.oftc.net` |
| `IRC_PORT` | `6697` |
| `IRC_TLS` | `1` |

## Commands

`/join #chan` · `/query nick` · `/clear` · `/reconnect` · `/quit`

Requires Tor on `127.0.0.1:9050`.
