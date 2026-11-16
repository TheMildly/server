# server
Mildly for servers, personal workhouse for everything

Mildly Server is the personal server the Mildly app pairs with. One command installs it on
any Linux machine you control; from then on it runs your apps in containers (Docker or
Podman, your choice), lets the AI models you use in Mildly build and run apps there, gives
your sites an address with HTTPS, and opens a terminal from the app. Only your devices can
talk to it: every request is sealed end to end and signed by a key that never leaves the
device.

## Install

```bash
curl -fsSL https://github.com/TheMildly/server/releases/latest/download/install.sh | sudo sh
```

The installer asks which container runtime to use (or keeps the one you have), offers a free
address under `dedyn.io`, and ends with a 12-digit code and a QR code. In the app: Settings →
Personal server → type the code or scan it.

Options: `--runtime docker|podman`, `--binary PATH` (an engine you downloaded yourself),
`--free-names EMAIL`, `--no-free-names`.

## Commands

| Command | What |
| --- | --- |
| `mildly-server pair` | A fresh pairing code, for another first device or after a reset |
| `mildly-server free-names --email ADDRESS` | Free `name.dedyn.io` addresses through deSEC (one confirmation email) |
| `mildly-server free-names --token TOKEN` | The same with a deSEC account you already have |
| `mildly-server version` | The installed version |

Settings are in `/etc/mildly/config.toml`, state in `/var/lib/mildly`. The service is
`mildly` (`systemctl status mildly`, `journalctl -u mildly`).

## For developers

```bash
cargo build
cargo run -- run --config ./config.toml   # an empty file is a valid config; set data_dir to somewhere writable
```

How it works (trust model, pairing, API, containers, addresses, install, order of work):
[`docs/SERVER.md`](docs/SERVER.md).

Mildly Server is closed source: permission to use only. See [`LICENSE.md`](LICENSE.md).
