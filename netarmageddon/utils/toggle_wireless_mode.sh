#!/usr/bin/env bash

# Usage: sudo ./toggle_wireless_mode.sh <interface> <mode>
# mode: monitor | managed

set -euo pipefail
IFS=$'\n\t'

usage() {
  cat <<EOF
Usage: sudo $0 <interface> <mode>

<interface>  : wireless interface name (e.g. wlan0)
<mode>       : monitor or managed

Examples:
  sudo $0 wlan0 monitor
  sudo $0 wlan0 managed
EOF
  exit 1
}

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root." >&2
    exit 1
  fi
}

check_interface() {
  local ifc="$1"
  if ! iw dev "$ifc" info &>/dev/null; then
    echo "Error: Interface '$ifc' not found or not wireless." >&2
    exit 1
  fi
}

stop_conflicts() {
  if systemctl is-active --quiet NetworkManager; then
    systemctl stop NetworkManager
    _RESTART_NM=true
  fi
  if systemctl is-active --quiet wpa_supplicant; then
    systemctl stop wpa_supplicant
    _RESTART_WPA=true
  fi
}

restore_conflicts() {
  if [[ "${_RESTART_WPA:-}" == true ]]; then
    systemctl start wpa_supplicant || true
  fi
  if [[ "${_RESTART_NM:-}" == true ]]; then
    systemctl start NetworkManager || true
  fi
}

set_monitor() {
  local ifc="$1"
  ip link set "$ifc" down
  iw dev "$ifc" set type monitor
  ip link set "$ifc" up
  echo "Interface $ifc is now in monitor mode."
}

set_managed() {
  local ifc="$1"
  ip link set dev "$ifc" down
  iw dev "$ifc" set type managed
  ip link set dev "$ifc" up
  if systemctl is-enabled NetworkManager &>/dev/null; then
    systemctl restart NetworkManager
    echo "NetworkManager restarted."
  fi
  echo "Interface $ifc is now in managed mode."
}

if [[ $# -ne 2 ]]; then
  usage
fi

ensure_root
INTERFACE="$1"
MODE="$2"

check_interface "$INTERFACE"

case "$MODE" in
  monitor)
    stop_conflicts
    set_monitor "$INTERFACE"
    ;;
  managed)
    set_managed "$INTERFACE"
    ;;
  *)
    echo "Error: Unknown mode '$MODE'. Use 'monitor' or 'managed'." >&2
    usage
    ;;
esac

exit 0
