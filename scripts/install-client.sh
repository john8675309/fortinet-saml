#!/usr/bin/env bash
# Client-only update: does not stop or restart the service or strongSwan.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
test "$(id -u)" != 0 || { echo 'Run as your desktop user, without sudo.' >&2; exit 1; }
test -s target/release/fortigate-manager
sudo install -o root -g root -m 755 target/release/fortigate-manager /usr/local/bin/fortigate-manager
sudo install -o root -g root -m 644 packaging/fortigate-manager.desktop /usr/share/applications/
sudo install -d -m 755 /usr/local/share/icons/hicolor/scalable/apps
sudo install -o root -g root -m 644 assets/fortigate-manager.svg /usr/local/share/icons/hicolor/scalable/apps/
echo 'Client updated. Close the old client (or select Quit in its tray menu), then run:'
echo "bash $project_dir/scripts/launch.sh"
echo 'It starts in the system tray. Open its menu to show the window or manage VPNs.'
