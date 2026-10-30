#!/usr/bin/env bash
set -euo pipefail
sudo systemctl disable --now fortigate-manager.socket
sudo systemctl stop fortigate-manager.service
sudo rm -f -- /etc/systemd/system/fortigate-manager.socket /etc/systemd/system/fortigate-manager.service
sudo rm -f -- /etc/strongswan.d/charon/fortigate-manager-subnets.conf
sudo systemctl restart strongswan.service
sudo rm -f -- /usr/lib/ipsec/plugins/libstrongswan-fortigate-manager-subnets.so
sudo rm -f -- /usr/local/bin/fortigate-manager /usr/local/libexec/fortigate-managerd /usr/share/applications/fortigate-manager.desktop
sudo rm -f -- /usr/local/share/icons/hicolor/scalable/apps/fortigate-manager.svg
sudo systemctl daemon-reload
echo 'Removed application/service/plugin. Private saved profiles remain in /var/lib/fortigate-manager.'
echo 'The original CLI and its separate route plugin remain installed.'
