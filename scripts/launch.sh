#!/usr/bin/env bash
set -euo pipefail
if id -Gn | tr ' ' '\n' | grep -Fxq fortigate-manager; then
    exec /usr/local/bin/fortigate-manager
else
    exec sg fortigate-manager -c 'exec /usr/local/bin/fortigate-manager'
fi
