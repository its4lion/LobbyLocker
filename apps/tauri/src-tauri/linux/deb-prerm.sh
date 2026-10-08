#!/bin/sh
set -eu

# Upgrades keep the currently applied policy. Only a real removal cleans up.
if [ "${1:-}" = "remove" ] && [ -x /usr/bin/lobbylocker ]; then
  /usr/bin/lobbylocker --reset-firewall
fi

exit 0
