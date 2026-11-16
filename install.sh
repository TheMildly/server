#!/bin/sh
# Mildly Server installer (docs/SERVER.md, section 8).
#
#   curl -fsSL https://github.com/TheMildly/server/releases/latest/download/install.sh \
#     | sudo sh -s -- [--runtime docker|podman] [--binary PATH]
#                     [--free-names EMAIL | --no-free-names]
#
# Installs the container runtime you choose (Docker Engine or Podman), the Mildly engine, a
# systemd service, opens the API and web ports when a firewall is on, offers a free web address
# (name.dedyn.io, through a deSEC account for this server) and prints the first pairing code.
# Without --runtime it keeps the runtime already installed, else asks, else uses Docker.
# The engine binary comes from --binary, or from $MILDLY_DOWNLOAD/mildly-server-<arch>
# (the releases of github.com/TheMildly/server by default).
set -eu

RUNTIME=""
BINARY="${MILDLY_BINARY:-}"
DOWNLOAD="${MILDLY_DOWNLOAD:-https://github.com/TheMildly/server/releases/latest/download}"
FREE_EMAIL=""
FREE_ASK=1
PORT=7680
DISCOVERY=7681

say() { printf '\n  %s\n' "$*"; }
fail() { printf '\n  Mildly could not be installed: %s\n\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --runtime) RUNTIME="${2:-}"; shift 2 ;;
    --runtime=*) RUNTIME="${1#*=}"; shift ;;
    --binary) BINARY="${2:-}"; shift 2 ;;
    --binary=*) BINARY="${1#*=}"; shift ;;
    --free-names) FREE_EMAIL="${2:-}"; shift 2 ;;
    --free-names=*) FREE_EMAIL="${1#*=}"; shift ;;
    --no-free-names) FREE_ASK=0; shift ;;
    *) fail "unknown option $1 (use --runtime docker|podman, --binary PATH, --free-names EMAIL)" ;;
  esac
done

[ "$(id -u)" = 0 ] || fail "run it as root, for example: curl -fsSL <installer> | sudo sh"
[ "$(uname -s)" = Linux ] || fail "the server runs on Linux"
case "$(uname -m)" in
  x86_64 | amd64) ARCH=x86_64 ;;
  aarch64 | arm64) ARCH=aarch64 ;;
  *) fail "this processor ($(uname -m)) is not supported yet" ;;
esac
command -v systemctl >/dev/null 2>&1 || fail "systemd is needed to keep the engine running"

# ---------- which runtime ----------
if [ -z "$RUNTIME" ]; then
  if command -v docker >/dev/null 2>&1; then
    RUNTIME=docker
  elif command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
  elif [ -r /dev/tty ]; then
    printf '\n  Which container runtime should run your apps?\n    1) Docker Engine (default)\n    2) Podman\n  Choose 1 or 2: '
    read -r answer </dev/tty || answer=1
    [ "$answer" = 2 ] && RUNTIME=podman || RUNTIME=docker
  else
    RUNTIME=docker
  fi
fi
case "$RUNTIME" in docker | podman) ;; *) fail "--runtime must be docker or podman" ;; esac

install_packages() {
  if command -v apt-get >/dev/null 2>&1; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q "$@"
  elif command -v yum >/dev/null 2>&1; then yum install -y -q "$@"
  elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install "$@"
  elif command -v pacman >/dev/null 2>&1; then pacman -Sy --noconfirm "$@"
  else fail "no supported package manager to install $*"
  fi
}

if [ "$RUNTIME" = docker ]; then
  if ! command -v docker >/dev/null 2>&1; then
    say "Installing Docker Engine…"
    command -v curl >/dev/null 2>&1 || install_packages curl
    curl -fsSL https://get.docker.com | sh
  fi
  systemctl enable --now docker >/dev/null
  SOCKET=/var/run/docker.sock
else
  if ! command -v podman >/dev/null 2>&1; then
    say "Installing Podman…"
    install_packages podman
  fi
  systemctl enable --now podman.socket >/dev/null
  SOCKET=/run/podman/podman.sock
fi

# ---------- the engine ----------
say "Installing the Mildly engine…"
if [ -n "$BINARY" ]; then
  [ -f "$BINARY" ] || fail "no engine binary at $BINARY"
  install -m 0755 "$BINARY" /usr/local/bin/mildly-server
else
  tmp=$(mktemp)
  curl -fsSL "$DOWNLOAD/mildly-server-$ARCH" -o "$tmp" || fail "could not download the engine from $DOWNLOAD"
  install -m 0755 "$tmp" /usr/local/bin/mildly-server
  rm -f "$tmp"
fi

mkdir -p /etc/mildly /var/lib/mildly
chmod 0700 /var/lib/mildly
if [ ! -f /etc/mildly/config.toml ]; then
  cat >/etc/mildly/config.toml <<EOF
# Mildly Server settings. See docs/SERVER.md.
listen = "0.0.0.0:$PORT"
discovery_port = $DISCOVERY
runtime = "$RUNTIME"
socket = "$SOCKET"
EOF
fi

cat >/etc/systemd/system/mildly.service <<'EOF'
[Unit]
Description=Mildly Server
After=network-online.target docker.service podman.socket
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mildly-server run
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# ---------- reachability ----------
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  # The API, LAN discovery, and the web for sites under the server's address.
  for rule in "$PORT/tcp" "$DISCOVERY/udp" 80/tcp 443/tcp 443/udp; do ufw allow "$rule" >/dev/null; done
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  for rule in "$PORT/tcp" "$DISCOVERY/udp" 80/tcp 443/tcp 443/udp; do firewall-cmd --permanent --add-port="$rule" >/dev/null; done
  firewall-cmd --reload >/dev/null
fi

systemctl daemon-reload
systemctl enable mildly >/dev/null 2>&1
systemctl restart mildly

# The engine makes its admin socket once it is up; then ask it for a code.
i=0
while [ ! -S /var/lib/mildly/admin.sock ] && [ $i -lt 60 ]; do sleep 0.5; i=$((i + 1)); done
[ -S /var/lib/mildly/admin.sock ] || fail "the engine did not start (journalctl -u mildly)"

say "Mildly Server is running with $RUNTIME."

# ---------- a free web address ----------
# deSEC gives each account one free name.dedyn.io; the server gets its own account. deSEC
# sends one email to confirm it. Later, or with an account you have: mildly-server free-names
if [ -z "$FREE_EMAIL" ] && [ "$FREE_ASK" = 1 ] && [ -r /dev/tty ]; then
  printf '\n  Sites on this server can get a free address (name.dedyn.io) with HTTPS.\n'
  printf '  deSEC, a non-profit DNS service, hands these out and emails you once to confirm.\n'
  printf '  Email for deSEC (Enter to skip): '
  read -r FREE_EMAIL </dev/tty || FREE_EMAIL=""
fi
if [ -n "$FREE_EMAIL" ]; then
  /usr/local/bin/mildly-server free-names --email "$FREE_EMAIL" || say "Free names are off for now. Try again later with: mildly-server free-names --email $FREE_EMAIL"
fi

/usr/local/bin/mildly-server pair
