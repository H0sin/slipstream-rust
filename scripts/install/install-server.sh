#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  slipstream-server  —  install & manage
#
#  Repo: https://github.com/alisamani1378/slipstream-server-installer
#
#  First run (install):
#    curl -sSL https://raw.githubusercontent.com/alisamani1378/slipstream-server-installer/main/install.sh | sudo bash
#
#  After install, manage with:
#    slipstream  status|start|stop|restart|logs|edit|update|uninstall
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

RELEASE_BASE="https://github.com/alisamani1378/slipstream-server-installer/raw/main"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/slipstream"
CONF_FILE="$CONF_DIR/server.conf"
SERVICE_NAME="slipstream-server"
MANAGE_CMD="/usr/local/bin/slipstream"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; }
ask()   { echo -en "${CYAN}[?]${NC} $1: "; }

# ── Helpers ──────────────────────────────────────────────────────────
# Build repeated --domain flags from comma-separated string.
build_domain_args() {
  local IFS=','
  for d in $1; do
    d="$(echo "$d" | xargs)"
    [[ -n "$d" ]] && printf -- '--domain %s ' "$d"
  done
}

# Free port 53 by disabling systemd-resolved stub listener.
free_port_53() {
  local port="${1:-}"
  [[ "$port" != "53" ]] && return 0

  if ss -ulnp 2>/dev/null | grep -q ':53 '; then
    local pid_info
    pid_info="$(ss -ulnp 2>/dev/null | grep ':53 ' | head -1)"
    if echo "$pid_info" | grep -qi 'systemd-resolve'; then
      warn "systemd-resolved is using port 53 — disabling stub listener..."
      mkdir -p /etc/systemd/resolved.conf.d
      cat > /etc/systemd/resolved.conf.d/no-stub.conf <<'EODNS'
[Resolve]
DNSStubListener=no
EODNS
      ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null || true
      systemctl restart systemd-resolved
      sleep 1
      info "systemd-resolved stub listener disabled — port 53 is free."
    else
      warn "Port 53 is in use by another process:"
      echo "  $pid_info"
      warn "You may need to stop it manually before slipstream can bind."
    fi
  fi
}

# ═════════════════════════════════════════════════════════════════════
#  Management mode  (slipstream status|start|stop|restart|logs|uninstall)
# ═════════════════════════════════════════════════════════════════════
if [[ "${1:-}" != "" ]]; then
  case "$1" in
    status)
      systemctl status "$SERVICE_NAME" --no-pager
      ;;
    start)
      systemctl start "$SERVICE_NAME"
      info "Server started."
      ;;
    stop)
      systemctl stop "$SERVICE_NAME"
      info "Server stopped."
      ;;
    restart)
      systemctl restart "$SERVICE_NAME"
      info "Server restarted."
      ;;
    logs)
      journalctl -u "$SERVICE_NAME" -f --no-pager
      ;;
    edit)
      if [[ ! -f "$CONF_FILE" ]]; then
        err "Config not found at $CONF_FILE — is slipstream installed?"
        exit 1
      fi
      source "$CONF_FILE"
      # Back-compat: old config may have DOMAIN= instead of DOMAINS=
      DOMAINS="${DOMAINS:-${DOMAIN:-}}"
      echo ""
      echo -e "${CYAN}Current configuration:${NC}"
      echo -e "  1) Domains:      $DOMAINS"
      echo -e "  2) Target:       $TARGET_ADDR"
      echo -e "  3) DNS port:     $DNS_PORT"
      echo -e "  4) Cert path:    $CERT_PATH"
      echo -e "  5) Key path:     $KEY_PATH"
      echo ""
      ask "Enter field numbers to edit (e.g. 1 3) or 'all', empty to cancel"
      read -r EDIT_CHOICE < /dev/tty
      [[ -z "$EDIT_CHOICE" ]] && { info "No changes."; exit 0; }
      if [[ "$EDIT_CHOICE" == *"1"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Domains — comma-separated (e.g. t1.ex.com,t2.ex.com) [$DOMAINS]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && DOMAINS="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"2"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Target address [$TARGET_ADDR]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && TARGET_ADDR="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"3"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "DNS port [$DNS_PORT]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && DNS_PORT="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"4"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Cert path [$CERT_PATH]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && CERT_PATH="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"5"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Key path [$KEY_PATH]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && KEY_PATH="$NEW_VAL"
      fi
      free_port_53 "$DNS_PORT"
      DOMAIN_ARGS=$(build_domain_args "$DOMAINS")
      cat > "$CONF_FILE" <<EOFCONF
DOMAINS=$DOMAINS
TARGET_ADDR=$TARGET_ADDR
DNS_PORT=$DNS_PORT
CERT_PATH=$CERT_PATH
KEY_PATH=$KEY_PATH
EOFCONF
      cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOFSVC
[Unit]
Description=slipstream DNS tunnel server
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/slipstream-server --dns-listen-port $DNS_PORT --target-address $TARGET_ADDR $DOMAIN_ARGS --cert $CERT_PATH --key $KEY_PATH
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOFSVC
      systemctl daemon-reload
      systemctl restart "$SERVICE_NAME"
      info "Config updated and server restarted."
      ;;
    update)
      [[ $EUID -ne 0 ]] && { err "Run as root: sudo slipstream update"; exit 1; }
      echo ""
      info "Updating slipstream-server binary..."
      TMP_BIN=$(mktemp)
      if curl -sSL --max-time 120 "${RELEASE_BASE}/slipstream-server" -o "$TMP_BIN"; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        mv -f "$TMP_BIN" "$BIN_DIR/slipstream-server"
        chmod +x "$BIN_DIR/slipstream-server"
        systemctl start "$SERVICE_NAME"
        info "Binary updated and server restarted."
        # Also update the management script itself
        curl -sSL --max-time 30 "${RELEASE_BASE}/install.sh" -o "$MANAGE_CMD" 2>/dev/null && chmod +x "$MANAGE_CMD" || true
      else
        rm -f "$TMP_BIN"
        err "Download failed. Server unchanged."
        exit 1
      fi
      ;;
    uninstall)
      echo ""
      ask "Are you sure? This removes slipstream-server completely. (y/n)"
      read -r CONFIRM < /dev/tty
      if [[ "$CONFIRM" == "y" ]]; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
        rm -f "$BIN_DIR/slipstream-server"
        rm -f "$MANAGE_CMD"
        info "Server uninstalled. Config kept at $CONF_DIR"
      else
        info "Cancelled."
      fi
      ;;
    *)
      echo "Usage: slipstream {status|start|stop|restart|logs|edit|update|uninstall}"
      exit 1
      ;;
  esac
  exit 0
fi

# ═════════════════════════════════════════════════════════════════════
#  No arguments — show help if already installed, else install
# ═════════════════════════════════════════════════════════════════════
if [[ -f "$BIN_DIR/slipstream-server" ]] && [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
  echo ""
  echo -e "${CYAN}slipstream-server management${NC}"
  echo ""
  if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
    DOMAINS="${DOMAINS:-${DOMAIN:-}}"
    echo -e "  Domains: ${GREEN}$DOMAINS${NC}"
    echo -e "  Target:  $TARGET_ADDR"
    echo -e "  Port:    $DNS_PORT"
    echo ""
  fi
  echo -e "  ${YELLOW}Commands:${NC}"
  echo -e "  slipstream status     Show service status"
  echo -e "  slipstream start      Start the server"
  echo -e "  slipstream stop       Stop the server"
  echo -e "  slipstream restart    Restart the server"
  echo -e "  slipstream logs       Follow live logs"
  echo -e "  slipstream edit       Edit configuration"
  echo -e "  slipstream update     Download latest binary"
  echo -e "  slipstream uninstall  Remove slipstream"
  echo ""
  exit 0
fi

# ── Install mode ─────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { err "Run as root: sudo bash"; exit 1; }

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}     slipstream-server installer${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# ── Download binary ──────────────────────────────────────────────────
info "Downloading slipstream-server..."
curl -sSL --max-time 120 "${RELEASE_BASE}/slipstream-server" -o "$BIN_DIR/slipstream-server"
chmod +x "$BIN_DIR/slipstream-server"
info "Binary → $BIN_DIR/slipstream-server"

# ── Configuration ────────────────────────────────────────────────────
mkdir -p "$CONF_DIR"

ask "Tunnel domains — comma-separated (e.g. t.example.com or t1.ex.com,t2.ex.com)"
read -r DOMAINS < /dev/tty
[[ -z "$DOMAINS" ]] && { err "At least one domain is required."; exit 1; }

ask "Target address [default: 127.0.0.1:443]"
read -r TARGET_ADDR < /dev/tty
TARGET_ADDR="${TARGET_ADDR:-127.0.0.1:443}"

ask "DNS listen port [default: 53]"
read -r DNS_PORT < /dev/tty
DNS_PORT="${DNS_PORT:-53}"

ask "TLS cert path [default: $CONF_DIR/cert.pem]"
read -r CERT_PATH < /dev/tty
CERT_PATH="${CERT_PATH:-$CONF_DIR/cert.pem}"

ask "TLS key path  [default: $CONF_DIR/key.pem]"
read -r KEY_PATH < /dev/tty
KEY_PATH="${KEY_PATH:-$CONF_DIR/key.pem}"

FIRST_DOMAIN="$(echo "$DOMAINS" | cut -d',' -f1 | xargs)"
if [[ ! -f "$CERT_PATH" ]] || [[ ! -f "$KEY_PATH" ]]; then
  warn "Generating self-signed certificate..."
  apt-get install -y -qq openssl > /dev/null 2>&1 || true
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$KEY_PATH" -out "$CERT_PATH" -days 3650 -nodes \
    -subj "/CN=$FIRST_DOMAIN" 2>/dev/null
  info "Cert → $CERT_PATH"
fi

# Free port 53 if needed.
free_port_53 "$DNS_PORT"

DOMAIN_ARGS=$(build_domain_args "$DOMAINS")

# Save config for reference.
cat > "$CONF_FILE" <<EOF
DOMAINS=$DOMAINS
TARGET_ADDR=$TARGET_ADDR
DNS_PORT=$DNS_PORT
CERT_PATH=$CERT_PATH
KEY_PATH=$KEY_PATH
EOF

# ── systemd service ─────────────────────────────────────────────────
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=slipstream DNS tunnel server
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/slipstream-server --dns-listen-port $DNS_PORT --target-address $TARGET_ADDR $DOMAIN_ARGS --cert $CERT_PATH --key $KEY_PATH
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
info "Server running on UDP port $DNS_PORT"

# ── Install management command ───────────────────────────────────────
SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]:-}" 2>/dev/null || echo "")"
if [[ -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]]; then
  cp -f "$SCRIPT_PATH" "$MANAGE_CMD"
else
  curl -sSL --max-time 30 "${RELEASE_BASE}/install.sh" -o "$MANAGE_CMD"
fi
chmod +x "$MANAGE_CMD"

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Done!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Domains: $DOMAINS"
echo -e "  Target:  $TARGET_ADDR"
echo -e "  Port:    $DNS_PORT"
echo -e "  Cert:    $CERT_PATH"
echo ""
echo -e "  ${YELLOW}Management:${NC}"
echo -e "  slipstream status"
echo -e "  slipstream restart"
echo -e "  slipstream logs"
echo -e "  slipstream edit"
echo -e "  slipstream update"
echo -e "  slipstream stop"
echo -e "  slipstream uninstall"
echo ""
