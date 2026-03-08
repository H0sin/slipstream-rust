#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
#  slipstream-client  —  install & manage
#
#  This script + the binary sit on an IRANIAN web server.
#  Other Iranian servers install with:
#    curl -sSL http://IRAN_WEBSERVER_IP:PORT/install-client.sh | sudo bash
#
#  After install, manage with:
#    slipstream-cli  status|start|stop|restart|logs|edit|update|uninstall
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

# Build repeated --authoritative flags from comma-separated string.
build_authoritative_args() {
  local IFS=','
  for a in $1; do
    a="$(echo "$a" | xargs)"
    [[ -n "$a" ]] && printf -- '--authoritative %s ' "$a"
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
      AUTHORITATIVES="${AUTHORITATIVES:-}"
      CONGESTION_CONTROL="${CONGESTION_CONTROL:-}"
      KEEP_ALIVE_INTERVAL="${KEEP_ALIVE_INTERVAL:-400}"
      GSO="${GSO:-}"
      SCAN_FILE="${SCAN_FILE:-}"
      SCAN_CACHE="${SCAN_CACHE:-scan-cache.json}"
      SCAN_INTERVAL="${SCAN_INTERVAL:-300}"
      SCAN_MAX="${SCAN_MAX:-5}"
      SCAN_BATCH="${SCAN_BATCH:-50}"
      echo ""
      echo -e "${CYAN}Current configuration:${NC}"
      echo -e "  1) Domains:            $DOMAINS"
      echo -e "  2) Resolvers:          ${RESOLVERS:-(none)}"
      echo -e "  3) Authoritatives:     ${AUTHORITATIVES:-(none)}"
      echo -e "  4) Listen port:        $LISTEN_PORT"
      echo -e "  5) Listen host:        $LISTEN_HOST"
      echo -e "  6) Congestion control: ${CONGESTION_CONTROL:-(default)}"
      echo -e "  7) Keep-alive (ms):    $KEEP_ALIVE_INTERVAL"
      echo -e "  8) GSO:                ${GSO:-off}"
      echo -e "  9) Scan file:          ${SCAN_FILE:-(built-in)}"
      echo -e " 10) Scan cache:         $SCAN_CACHE"
      echo -e " 11) Scan interval (s):  $SCAN_INTERVAL"
      echo -e " 12) Scan max resolvers: $SCAN_MAX"
      echo -e " 13) Scan batch size:    $SCAN_BATCH"
      echo ""
      ask "Enter field numbers to edit (e.g. 1 2) or 'all', empty to cancel"
      read -r EDIT_CHOICE < /dev/tty
      [[ -z "$EDIT_CHOICE" ]] && { info "No changes."; exit 0; }
      if [[ "$EDIT_CHOICE" == *"1"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Domains — comma-separated (e.g. t1.ex.com,t2.ex.com) [$DOMAINS]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && DOMAINS="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"2"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Resolvers (recursive) — comma-separated IP:PORT, enter '-' to clear [${RESOLVERS:-(none)}]"
        read -r NEW_VAL < /dev/tty
        if [[ "$NEW_VAL" == "-" ]]; then RESOLVERS=""
        elif [[ -n "$NEW_VAL" ]]; then RESOLVERS="$NEW_VAL"
        fi
      fi
      if [[ "$EDIT_CHOICE" == *"3"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Authoritatives — comma-separated IP:PORT, enter '-' to clear [${AUTHORITATIVES:-(none)}]"
        read -r NEW_VAL < /dev/tty
        if [[ "$NEW_VAL" == "-" ]]; then AUTHORITATIVES=""
        elif [[ -n "$NEW_VAL" ]]; then AUTHORITATIVES="$NEW_VAL"
        fi
      fi
      if [[ "$EDIT_CHOICE" == *"4"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Listen port [$LISTEN_PORT]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && LISTEN_PORT="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"5"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Listen host [$LISTEN_HOST]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && LISTEN_HOST="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"6"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Congestion control (bbr/dcubic), enter '-' to use default [${CONGESTION_CONTROL:-(default)}]"
        read -r NEW_VAL < /dev/tty
        if [[ "$NEW_VAL" == "-" ]]; then CONGESTION_CONTROL=""
        elif [[ -n "$NEW_VAL" ]]; then CONGESTION_CONTROL="$NEW_VAL"
        fi
      fi
      if [[ "$EDIT_CHOICE" == *"7"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Keep-alive interval in ms [$KEEP_ALIVE_INTERVAL]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && KEEP_ALIVE_INTERVAL="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"8"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Enable GSO? (on/off) [${GSO:-off}]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && GSO="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"9"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Scan file path [$SCAN_FILE]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && SCAN_FILE="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"10"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Scan cache file [$SCAN_CACHE]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && SCAN_CACHE="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"11"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Scan interval in seconds [$SCAN_INTERVAL]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && SCAN_INTERVAL="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"12"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "Max resolvers to discover [$SCAN_MAX]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && SCAN_MAX="$NEW_VAL"
      fi
      if [[ "$EDIT_CHOICE" == *"13"* ]] || [[ "$EDIT_CHOICE" == "all" ]]; then
        ask "IPs per scan batch [$SCAN_BATCH]"
        read -r NEW_VAL < /dev/tty; [[ -n "$NEW_VAL" ]] && SCAN_BATCH="$NEW_VAL"
      fi
      if [[ -z "$RESOLVERS" ]] && [[ -z "$AUTHORITATIVES" ]]; then
        err "At least one resolver or authoritative address is required."
        exit 1
      fi
      DOMAIN_ARGS=$(build_domain_args "$DOMAINS")
      RESOLVER_ARGS=""
      [[ -n "$RESOLVERS" ]] && RESOLVER_ARGS=$(build_resolver_args "$RESOLVERS")
      AUTH_ARGS=""
      [[ -n "$AUTHORITATIVES" ]] && AUTH_ARGS=$(build_authoritative_args "$AUTHORITATIVES")
      EXTRA_ARGS=""
      [[ -n "$CONGESTION_CONTROL" ]] && EXTRA_ARGS="$EXTRA_ARGS --congestion-control $CONGESTION_CONTROL"
      [[ -n "$KEEP_ALIVE_INTERVAL" && "$KEEP_ALIVE_INTERVAL" != "400" ]] && EXTRA_ARGS="$EXTRA_ARGS --keep-alive-interval $KEEP_ALIVE_INTERVAL"
      [[ "$GSO" == "on" ]] && EXTRA_ARGS="$EXTRA_ARGS --gso"
      [[ -n "$SCAN_FILE" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-file $SCAN_FILE"
      [[ -n "$SCAN_CACHE" && "$SCAN_CACHE" != "scan-cache.json" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-cache $SCAN_CACHE"
      [[ -n "$SCAN_INTERVAL" && "$SCAN_INTERVAL" != "300" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-interval $SCAN_INTERVAL"
      [[ -n "$SCAN_MAX" && "$SCAN_MAX" != "5" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-max $SCAN_MAX"
      [[ -n "$SCAN_BATCH" && "$SCAN_BATCH" != "50" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-batch $SCAN_BATCH"
      cat > "$CONF_FILE" <<EOFCONF
DOMAINS=$DOMAINS
RESOLVERS=$RESOLVERS
AUTHORITATIVES=$AUTHORITATIVES
LISTEN_PORT=$LISTEN_PORT
LISTEN_HOST=$LISTEN_HOST
CONGESTION_CONTROL=$CONGESTION_CONTROL
KEEP_ALIVE_INTERVAL=$KEEP_ALIVE_INTERVAL
GSO=$GSO
SCAN_FILE=$SCAN_FILE
SCAN_CACHE=$SCAN_CACHE
SCAN_INTERVAL=$SCAN_INTERVAL
SCAN_MAX=$SCAN_MAX
SCAN_BATCH=$SCAN_BATCH
DOWNLOAD_BASE=${DOWNLOAD_BASE:-}
EOFCONF
      cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOFSVC
[Unit]
Description=slipstream DNS tunnel client
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/slipstream-client --tcp-listen-host $LISTEN_HOST --tcp-listen-port $LISTEN_PORT $RESOLVER_ARGS $AUTH_ARGS $DOMAIN_ARGS$EXTRA_ARGS
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
    update)
      [[ $EUID -ne 0 ]] && { err "Run as root: sudo slipstream-cli update"; exit 1; }
      # Determine download URL from saved config or default
      if [[ -f "$CONF_FILE" ]]; then
        source "$CONF_FILE"
      fi
      DL_BASE="${DOWNLOAD_BASE:-$DEFAULT_DOWNLOAD_BASE}"
      DL_BASE="${DL_BASE%/}"
      echo ""
      info "Updating slipstream-client binary from $DL_BASE ..."
      TMP_BIN=$(mktemp)
      if curl -sSL --max-time 120 "${DL_BASE}/slipstream-client" -o "$TMP_BIN"; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        mv -f "$TMP_BIN" "$BIN_DIR/slipstream-client"
        chmod +x "$BIN_DIR/slipstream-client"
        systemctl start "$SERVICE_NAME"
        info "Binary updated and client restarted."
        # Also update the management script itself
        curl -sSL --max-time 30 "${DL_BASE}/install-client.sh" -o "$MANAGE_CMD" 2>/dev/null && chmod +x "$MANAGE_CMD" || true
      else
        rm -f "$TMP_BIN"
        err "Download failed. Client unchanged."
        exit 1
      fi
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
      echo "Usage: slipstream-cli {status|start|stop|restart|logs|edit|update|uninstall}"
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
    AUTHORITATIVES="${AUTHORITATIVES:-}"
    CONGESTION_CONTROL="${CONGESTION_CONTROL:-}"
    KEEP_ALIVE_INTERVAL="${KEEP_ALIVE_INTERVAL:-400}"
    GSO="${GSO:-}"
    SCAN_FILE="${SCAN_FILE:-}"
    SCAN_CACHE="${SCAN_CACHE:-scan-cache.json}"
    SCAN_INTERVAL="${SCAN_INTERVAL:-300}"
    SCAN_MAX="${SCAN_MAX:-5}"
    SCAN_BATCH="${SCAN_BATCH:-50}"
    echo -e "  Domains:         ${GREEN}$DOMAINS${NC}"
    echo -e "  Resolvers:       ${RESOLVERS:-(none)}"
    echo -e "  Authoritatives:  ${AUTHORITATIVES:-(none)}"
    echo -e "  Listen:          $LISTEN_HOST:$LISTEN_PORT"
    echo -e "  CC:              ${CONGESTION_CONTROL:-(default)}"
    echo -e "  Keep-alive:      ${KEEP_ALIVE_INTERVAL}ms"
    echo -e "  GSO:             ${GSO:-off}"
    echo -e "  Scan file:       ${SCAN_FILE:-(built-in)}"
    echo -e "  Scan cache:      $SCAN_CACHE"
    echo -e "  Scan interval:   ${SCAN_INTERVAL}s"
    echo -e "  Scan max:        $SCAN_MAX"
    echo -e "  Scan batch:      $SCAN_BATCH"
    echo ""
  fi
  echo -e "  ${YELLOW}Commands:${NC}"
  echo -e "  slipstream-cli status     Show service status"
  echo -e "  slipstream-cli start      Start the client"
  echo -e "  slipstream-cli stop       Stop the client"
  echo -e "  slipstream-cli restart    Restart the client"
  echo -e "  slipstream-cli logs       Follow live logs"
  echo -e "  slipstream-cli edit       Edit configuration"
  echo -e "  slipstream-cli update     Download latest binary"
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

ask "Recursive resolver addresses — comma-separated IP:PORT (e.g. 8.8.8.8:53) or leave empty"
read -r RESOLVERS < /dev/tty

ask "Authoritative resolver addresses — comma-separated IP:PORT (e.g. 89.167.94.217:53) or leave empty"
read -r AUTHORITATIVES < /dev/tty

if [[ -z "$RESOLVERS" ]] && [[ -z "$AUTHORITATIVES" ]]; then
  err "At least one resolver or authoritative address is required."
  exit 1
fi

ask "Local TCP listen port [default: 1080]"
read -r LISTEN_PORT < /dev/tty
LISTEN_PORT="${LISTEN_PORT:-1080}"

ask "Local TCP listen host [default: 0.0.0.0]"
read -r LISTEN_HOST < /dev/tty
LISTEN_HOST="${LISTEN_HOST:-0.0.0.0}"

ask "Congestion control algorithm (bbr/dcubic) or leave empty for default"
read -r CONGESTION_CONTROL < /dev/tty

ask "Keep-alive interval in ms [default: 400]"
read -r KEEP_ALIVE_INTERVAL < /dev/tty
KEEP_ALIVE_INTERVAL="${KEEP_ALIVE_INTERVAL:-400}"

ask "Enable GSO? (on/off) [default: off]"
read -r GSO < /dev/tty
GSO="${GSO:-off}"

ask "Scan ranges file path (leave empty to use built-in defaults)"
read -r SCAN_FILE < /dev/tty

ask "Scan cache file [default: scan-cache.json]"
read -r SCAN_CACHE < /dev/tty
SCAN_CACHE="${SCAN_CACHE:-scan-cache.json}"

ask "Scan interval in seconds [default: 300]"
read -r SCAN_INTERVAL < /dev/tty
SCAN_INTERVAL="${SCAN_INTERVAL:-300}"

ask "Max resolvers to discover [default: 5]"
read -r SCAN_MAX < /dev/tty
SCAN_MAX="${SCAN_MAX:-5}"

ask "IPs per scan batch [default: 50]"
read -r SCAN_BATCH < /dev/tty
SCAN_BATCH="${SCAN_BATCH:-50}"

DOMAIN_ARGS=$(build_domain_args "$DOMAINS")
RESOLVER_ARGS=""
[[ -n "$RESOLVERS" ]] && RESOLVER_ARGS=$(build_resolver_args "$RESOLVERS")
AUTH_ARGS=""
[[ -n "$AUTHORITATIVES" ]] && AUTH_ARGS=$(build_authoritative_args "$AUTHORITATIVES")
EXTRA_ARGS=""
[[ -n "$CONGESTION_CONTROL" ]] && EXTRA_ARGS="$EXTRA_ARGS --congestion-control $CONGESTION_CONTROL"
[[ -n "$KEEP_ALIVE_INTERVAL" && "$KEEP_ALIVE_INTERVAL" != "400" ]] && EXTRA_ARGS="$EXTRA_ARGS --keep-alive-interval $KEEP_ALIVE_INTERVAL"
[[ "$GSO" == "on" ]] && EXTRA_ARGS="$EXTRA_ARGS --gso"
[[ -n "$SCAN_FILE" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-file $SCAN_FILE"
[[ -n "$SCAN_CACHE" && "$SCAN_CACHE" != "scan-cache.json" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-cache $SCAN_CACHE"
[[ -n "$SCAN_INTERVAL" && "$SCAN_INTERVAL" != "300" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-interval $SCAN_INTERVAL"
[[ -n "$SCAN_MAX" && "$SCAN_MAX" != "5" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-max $SCAN_MAX"
[[ -n "$SCAN_BATCH" && "$SCAN_BATCH" != "50" ]] && EXTRA_ARGS="$EXTRA_ARGS --scan-batch $SCAN_BATCH"

# Save config.
cat > "$CONF_FILE" <<EOF
DOMAINS=$DOMAINS
RESOLVERS=$RESOLVERS
AUTHORITATIVES=$AUTHORITATIVES
LISTEN_PORT=$LISTEN_PORT
LISTEN_HOST=$LISTEN_HOST
CONGESTION_CONTROL=$CONGESTION_CONTROL
KEEP_ALIVE_INTERVAL=$KEEP_ALIVE_INTERVAL
GSO=$GSO
SCAN_FILE=$SCAN_FILE
SCAN_CACHE=$SCAN_CACHE
SCAN_INTERVAL=$SCAN_INTERVAL
SCAN_MAX=$SCAN_MAX
SCAN_BATCH=$SCAN_BATCH
DOWNLOAD_BASE=$DOWNLOAD_BASE
EOF

# ── systemd service ─────────────────────────────────────────────────
cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=slipstream DNS tunnel client
After=network.target

[Service]
Type=simple
ExecStart=$BIN_DIR/slipstream-client --tcp-listen-host $LISTEN_HOST --tcp-listen-port $LISTEN_PORT $RESOLVER_ARGS $AUTH_ARGS $DOMAIN_ARGS$EXTRA_ARGS
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
echo -e "  Domains:         $DOMAINS"
echo -e "  Resolvers:       ${RESOLVERS:-(none)}"
echo -e "  Authoritatives:  ${AUTHORITATIVES:-(none)}"
echo -e "  Listen:          $LISTEN_HOST:$LISTEN_PORT"
echo -e "  CC:              ${CONGESTION_CONTROL:-(default)}"
echo -e "  Keep-alive:      ${KEEP_ALIVE_INTERVAL}ms"
echo -e "  GSO:             ${GSO:-off}"
echo -e "  Scan file:       ${SCAN_FILE:-(built-in)}"
echo -e "  Scan cache:      $SCAN_CACHE"
echo -e "  Scan interval:   ${SCAN_INTERVAL}s"
echo -e "  Scan max:        $SCAN_MAX"
echo -e "  Scan batch:      $SCAN_BATCH"
echo ""
echo -e "  ${YELLOW}Management:${NC}"
echo -e "  slipstream-cli status"
echo -e "  slipstream-cli restart"
echo -e "  slipstream-cli logs"
echo -e "  slipstream-cli edit"
echo -e "  slipstream-cli update"
echo -e "  slipstream-cli stop"
echo -e "  slipstream-cli uninstall"
echo ""
