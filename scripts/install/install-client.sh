#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  slipstream-client  —  install & manage
#
#  This script + the binary sit on an IRANIAN web server.
#  Other Iranian servers install with:
#    curl -sSL http://IRAN_WEBSERVER_IP:PORT/install-client.sh | sudo bash
#
#  After install, manage with:
#    slipstream-cli  status|start|stop|restart|logs|edit|uninstall
# ─────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Distribution server URL (set this to YOUR Iranian web server) ────
DEFAULT_DOWNLOAD_BASE="http://188.121.121.25:8443"

BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/slipstream"
CONF_FILE="$CONF_DIR/client.conf"
SERVICE_NAME="slipstream-client"
MANAGE_CMD="/usr/local/bin/slipstream-cli"

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

# Build repeated --resolver flags from comma-separated string.
build_resolver_args() {
  local IFS=','
  for r in $1; do
    r="$(echo "$r" | xargs)"
    [[ -n "$r" ]] && printf -- '--resolver %s ' "$r"
  done
}

# ═════════════════════════════════════════════════════════════════════
#  Management mode  (slipstream-cli status|start|stop|restart|logs|edit|uninstall)
# ═════════════════════════════════════════════════════════════════════
if [[ "${1:-}" != "" ]]; then
  case "$1" in
    status)
      systemctl status "$SERVICE_NAME" --no-pager
      ;;
    start)
      systemctl start "$SERVICE_NAME"
      info "Client started."
      ;;
    stop)
      systemctl stop "$SERVICE_NAME"
      info "Client stopped."
      ;;
    restart)
      systemctl restart "$SERVICE_NAME"
      info "Client restarted."
      ;;
    logs)
      journalctl -u "$SERVICE_NAME" -f --no-pager
      ;;
    edit)
      if [[ ! -f "$CONF_FILE" ]]; then
        err "Config not found at $CONF_FILE — is slipstream-client installed?"
        exit 1
      fi
      source "$CONF_FILE"
      # Back-compat: old config may have DOMAIN/RESOLVER instead of DOMAINS/RESOLVERS
      DOMAINS="${DOMAINS:-${DOMAIN:-}}"
      RESOLVERS="${RESOLVERS:-${RESOLVER:-}}"
      echo ""
      echo -e "${CYAN}Current configuration:${NC}"
      echo -e "  1) Domains:      $DOMAINS"
      echo -e "  2) Resolvers:    $RESOLVERS"
      echo -e "  3) Listen port:  $LISTEN_PORT"
      echo -e "  4) Listen host:  $LISTEN_HOST"
      echo ""
      ask "Enter field numbers to edit (e.g. 1 2) or 'all', empty to cancel"
      read -r EDIT_CHOICE < /dev/tty
      [[ -z "$EDIT_CHOICE" ]] && { info "No changes."; exit 0; }
      if [[ "$EDIT_CHOICE" == *"1"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Domains — comma-separated (e.g. t1.ex.com,t2.ex.com) [$DOMAINS]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && DOMAINS="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"2"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Resolvers — comma-separated IP:PORT (e.g. 1.2.3.4:53,5.6.7.8:53) [$RESOLVERS]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && RESOLVERS="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"3"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Listen port [$LISTEN_PORT]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && LISTEN_PORT="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"4"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Listen host [$LISTEN_HOST]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && LISTEN_HOST="$NEW_VAL"
      fi
      DOMAIN_ARGS=$(build_domain_args "$DOMAINS")
      RESOLVER_ARGS=$(build_resolver_args "$RESOLVERS")
      cat > "$CONF_FILE" <<EOFCONF
DOMAINS=$DOMAINS
RESOLVERS=$RESOLVERS
LISTEN_PORT=$LISTEN_PORT
LISTEN_HOST=$LISTEN_HOST
DOWNLOAD_BASE=${DOWNLOAD_BASE:-}
EOFCONF
      cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOFSVC
[Unit]
Description=slipstream DNS tunnel client
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/slipstream-client --tcp-listen-host $LISTEN_HOST --tcp-listen-port $LISTEN_PORT $RESOLVER_ARGS $DOMAIN_ARGS
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOFSVC
      systemctl daemon-reload
      systemctl restart "$SERVICE_NAME"
      info "Config updated and client restarted."
      ;;
    uninstall)
      echo ""
      ask "Are you sure? This removes slipstream-client completely. (y/n)"
      read -r CONFIRM < /dev/tty
      if [[ "$CONFIRM" == "y" ]]; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
        systemctl daemon-reload
        rm -f "$BIN_DIR/slipstream-client"
        rm -f "$MANAGE_CMD"
        info "Client uninstalled. Config kept at $CONF_DIR"
      else
        info "Cancelled."
      fi
      ;;
    *)
      echo "Usage: slipstream-cli {status|start|stop|restart|logs|edit|uninstall}"
      exit 1
      ;;
  esac
  exit 0
fi

# ═════════════════════════════════════════════════════════════════════
#  No arguments — show help if already installed, else install
# ═════════════════════════════════════════════════════════════════════
if [[ -f "$BIN_DIR/slipstream-client" ]] && [[ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]]; then
  echo ""
  echo -e "${CYAN}slipstream-client management${NC}"
  echo ""
  if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
    DOMAINS="${DOMAINS:-${DOMAIN:-}}"
    RESOLVERS="${RESOLVERS:-${RESOLVER:-}}"
    echo -e "  Domains:   ${GREEN}$DOMAINS${NC}"
    echo -e "  Resolvers: $RESOLVERS"
    echo -e "  Listen:    $LISTEN_HOST:$LISTEN_PORT"
    echo ""
  fi
  echo -e "  ${YELLOW}Commands:${NC}"
  echo -e "  slipstream-cli status     Show service status"
  echo -e "  slipstream-cli start      Start the client"
  echo -e "  slipstream-cli stop       Stop the client"
  echo -e "  slipstream-cli restart    Restart the client"
  echo -e "  slipstream-cli logs       Follow live logs"
  echo -e "  slipstream-cli edit       Edit configuration"
  echo -e "  slipstream-cli uninstall  Remove slipstream"
  echo ""
  exit 0
fi

# ── Install mode ─────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { err "Run as root: sudo bash"; exit 1; }

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}     slipstream-client installer${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""

# Use DOWNLOAD_BASE env var, or fall back to the hardcoded default.
DOWNLOAD_BASE="${DOWNLOAD_BASE:-$DEFAULT_DOWNLOAD_BASE}"
# Strip trailing slash.
DOWNLOAD_BASE="${DOWNLOAD_BASE%/}"

# ── Download binary ──────────────────────────────────────────────────
mkdir -p "$CONF_DIR"
info "Downloading slipstream-client..."
curl -sSL --max-time 120 "${DOWNLOAD_BASE}/slipstream-client" -o "$BIN_DIR/slipstream-client"
chmod +x "$BIN_DIR/slipstream-client"
info "Binary → $BIN_DIR/slipstream-client"

# ── Configuration ────────────────────────────────────────────────────
echo ""

ask "Tunnel domains — comma-separated (e.g. t.example.com or t1.ex.com,t2.ex.com)"
read -r DOMAINS < /dev/tty
[[ -z "$DOMAINS" ]] && { err "At least one domain is required."; exit 1; }

ask "Resolver addresses — comma-separated IP:PORT (e.g. 1.2.3.4:53 or 1.2.3.4:53,5.6.7.8:53)"
read -r RESOLVERS < /dev/tty
[[ -z "$RESOLVERS" ]] && { err "At least one resolver is required."; exit 1; }

ask "Local TCP listen port [default: 1080]"
read -r LISTEN_PORT < /dev/tty
LISTEN_PORT="${LISTEN_PORT:-1080}"

ask "Local TCP listen host [default: 0.0.0.0]"
read -r LISTEN_HOST < /dev/tty
LISTEN_HOST="${LISTEN_HOST:-0.0.0.0}"

DOMAIN_ARGS=$(build_domain_args "$DOMAINS")
RESOLVER_ARGS=$(build_resolver_args "$RESOLVERS")

# Save config.
cat > "$CONF_FILE" <<EOF
DOMAINS=$DOMAINS
RESOLVERS=$RESOLVERS
LISTEN_PORT=$LISTEN_PORT
LISTEN_HOST=$LISTEN_HOST
DOWNLOAD_BASE=$DOWNLOAD_BASE
EOF

# ── systemd service ─────────────────────────────────────────────────
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=slipstream DNS tunnel client
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/slipstream-client --tcp-listen-host $LISTEN_HOST --tcp-listen-port $LISTEN_PORT $RESOLVER_ARGS $DOMAIN_ARGS
Restart=always
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "$SERVICE_NAME"
systemctl restart "$SERVICE_NAME"
info "Client running."

# ── Install management command ───────────────────────────────────────
SCRIPT_PATH="$(realpath "${BASH_SOURCE[0]:-}" 2>/dev/null || echo "")"
if [[ -n "$SCRIPT_PATH" && -f "$SCRIPT_PATH" ]]; then
  cp -f "$SCRIPT_PATH" "$MANAGE_CMD"
else
  curl -sSL --max-time 30 "${DOWNLOAD_BASE}/install-client.sh" -o "$MANAGE_CMD"
fi
chmod +x "$MANAGE_CMD"

# ── Summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Done!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  Domains:    $DOMAINS"
echo -e "  Resolvers:  $RESOLVERS"
echo -e "  Listen:     $LISTEN_HOST:$LISTEN_PORT"
echo ""
echo -e "  ${YELLOW}Management:${NC}"
echo -e "  slipstream-cli status"
echo -e "  slipstream-cli restart"
echo -e "  slipstream-cli logs"
echo -e "  slipstream-cli edit"
echo -e "  slipstream-cli stop"
echo -e "  slipstream-cli uninstall"
echo ""
