#!/bin/sh
set -eu

# RPM passes 0 for final removal and 1 for an upgrade.
if [ "${1:-1}" -eq 0 ] && [ -x /usr/bin/lobbylocker ]; then
  /usr/bin/lobbylocker --reset-firewall
fi

exit 0
