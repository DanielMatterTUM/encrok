#!/bin/sh
# encrok installer — static musl binary into a bin dir, optional systemd service.
#
#   curl -fsSL https://encrok.deploy.zeugs.online/install.sh | sh
#   curl -fsSL https://encrok.deploy.zeugs.online/install.sh | sh -s -- --client --server wss://TAG.deploy.zeugs.online/_endpoint --key SECRET --local-port 3000 --service
#
# Options:
#   --prefix DIR        install dir (default: /usr/local/bin, or ~/.local/bin if not writable)
#   --version V         pin a version (default: latest)
#   --base-url URL      asset base (default https://encrok.deploy.zeugs.online)
#   --client/--proxy    mode for the generated service config
#   --server/--key/--local-port/--mapping/--host/--listen/--ws-listen/--tls-insecure
#                       written into the service config file
#   --config FILE       use this existing YAML config for the service instead of generating one
#   --service           install + enable a systemd unit (system unit as root, user unit otherwise)
set -eu

BASE_URL="https://encrok.deploy.zeugs.online"
VERSION="latest"
PREFIX=""
SERVICE=0
GEN=0
CONFIG=""
MODE=""
TLS_INSEC=0
SERVER=""
KEY=""
LISTEN=""
WS_LISTEN=""
LOCAL_PORT=""
MAPPINGS=""
HOSTNAME_=""

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --version) VERSION="$2"; shift 2;;
    --base-url) BASE_URL="$2"; shift 2;;
    --service) SERVICE=1; shift;;
    --client) MODE="client"; shift;;
    --proxy) MODE="proxy"; shift;;
    --server) SERVER="$2"; shift 2;;
    --key) KEY="$2"; shift 2;;
    --listen) LISTEN="$2"; shift 2;;
    --ws-listen) WS_LISTEN="$2"; shift 2;;
    --local-port) LOCAL_PORT="$2"; shift 2;;
    --mapping) MAPPINGS="$MAPPINGS $2"; shift 2;;
    --host) HOSTNAME_="$2"; shift 2;;
    --tls-insecure) TLS_INSEC=1; shift;;
    --config) CONFIG="$2"; shift 2;;
    *) echo "encrok install: unbekannte Option: $1" >&2; exit 2;;
  esac
done

ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ASSET="encrok-x86_64-linux-musl";;
  aarch64|arm64) ASSET="encrok-aarch64-linux-musl";;
  *) echo "encrok install: nicht unterstützte Architektur: $ARCH" >&2; exit 1;;
esac

if [ -z "$PREFIX" ]; then
  if [ -w /usr/local/bin ]; then PREFIX=/usr/local/bin
  else PREFIX="$HOME/.local/bin"; mkdir -p "$PREFIX"; fi
fi
DEST="$PREFIX/encrok"

DL=""
if [ "$VERSION" = "latest" ]; then
  # GitHub-Releases haben eine saubere TLS-Kette (deploy-Gateway liefert nur das Leaf)
  DL="https://github.com/DanielMatterTUM/encrok/releases/latest/download/$ASSET"
else
  DL="https://github.com/DanielMatterTUM/encrok/releases/download/v$VERSION/$ASSET"
fi

echo "encrok: $DL -> $DEST"
TMP=$(mktemp)
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$DL" -o "$TMP"
else
  wget -qO "$TMP" "$DL"
fi
if head -c 60 "$TMP" | grep -qi "html\|404"; then
  echo "encrok install: Download lieferte HTML statt Binary (Version existiert?)" >&2
  exit 1
fi
chmod +x "$TMP"
if [ -w "$DEST" ] || { [ -e "$DEST" ] && [ ! -w "$DEST" ] && [ "$(id -u)" != 0 ]; }; then
  echo "encrok: $DEST existiert und ist nicht schreibbar — mit root erneut versuchen oder --prefix nutzen." >&2
  exit 1
fi
mv "$TMP" "$DEST" 2>/dev/null || { install -m 0755 "$TMP" "$DEST" && rm -f "$TMP"; }
"$DEST" --help >/dev/null 2>&1 || { echo "encrok install: Binary läuft nicht ($ARCH?)" >&2; exit 1; }
echo "encrok: installiert: $("$DEST" --version 2>/dev/null | head -1) -> $DEST"

[ "$SERVICE" = 1 ] || exit 0

# ---- systemd service ----
UID_N=$(id -u)
if [ -n "$CONFIG" ]; then
  START_CMD="$DEST $CONFIG"
else
  [ -n "$MODE" ] || { echo "encrok service: --proxy/--client oder --config nötig" >&2; exit 2; }
  if [ "$MODE" = "client" ]; then
    [ -n "$SERVER" ] && [ -n "$KEY" ] && [ -n "$LOCAL_PORT$MAPPINGS" ] || {
      echo "encrok service (client): --server --key und --local-port/--mapping nötig" >&2; exit 2; }
    GEN=1
  else
    [ -n "$KEY" ] || { echo "encrok service (proxy): --key nötig" >&2; exit 2; }
    GEN=1
  fi
fi

if [ "$GEN" = 1 ]; then
  if [ "$UID_N" = 0 ]; then CFG=/etc/encrok.yaml; else CFG="$HOME/.config/encrok/config.yaml"; mkdir -p "$(dirname "$CFG")"; fi
  {
    echo "mode: $MODE"
    [ "$MODE" = proxy ] && echo "key: \"$KEY\""
    [ "$MODE" = proxy ] && [ -n "$LISTEN" ] && echo "listen: \"$LISTEN\""
    [ "$MODE" = proxy ] && [ -n "$WS_LISTEN" ] && echo "ws_listen: \"$WS_LISTEN\""
    if [ "$MODE" = client ]; then
      echo "server: \"$SERVER\""
      echo "key: \"$KEY\""
      [ -n "$HOSTNAME_" ] && echo "host: $HOSTNAME_"
      [ "$TLS_INSEC" = 1 ] && echo "tls_insecure: true"
      [ -n "$LOCAL_PORT" ] && echo "local_port: $LOCAL_PORT"
      if [ -n "$MAPPINGS" ]; then
        echo "mappings:"
        for m in $MAPPINGS; do echo "  - \"$m\""; done
      fi
    fi
  } > "$CFG"
  chmod 600 "$CFG"
  echo "encrok: Config geschrieben: $CFG"
  START_CMD="$DEST $CFG"
fi

UNIT=/etc/systemd/system/encrok.service
if [ "$UID_N" = 0 ]; then
  cat > "$UNIT" <<EOF
[Unit]
Description=encrok reverse tunnel
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$START_CMD
Restart=always
RestartSec=5
DynamicUser=yes
StateDirectory=encrok

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now encrok.service
  echo "encrok: systemd service aktiv: systemctl status encrok"
else
  mkdir -p "$HOME/.config/systemd/user"
  UNIT="$HOME/.config/systemd/user/encrok.service"
  cat > "$UNIT" <<EOF
[Unit]
Description=encrok reverse tunnel
After=network-online.target

[Service]
ExecStart=$START_CMD
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now encrok.service
  loginctl enable-linger "$(id -un)" 2>/dev/null || true
  echo "encrok: user service aktiv: systemctl --user status encrok (Linger aktiviert)"
fi
