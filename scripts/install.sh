#!/usr/bin/env bash
# Run as your desktop user. Only installation/systemd operations use sudo.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
test "$(id -u)" != 0 || { echo 'Run this script as your desktop user, without sudo.' >&2; exit 1; }
login_user=$(id -un)
version=$(dpkg-query -W -f='${Version}' strongswan-libcharon)
case "$version" in 6.0.1-*) ;; *) echo 'The route plugin currently targets strongSwan 6.0.1.' >&2; exit 1 ;; esac
for artifact in target/release/fortigate-manager target/release/fortigate-managerd target/plugin/libstrongswan-fortigate-manager-subnets.so; do
    test -s "$artifact" || { echo "Missing $artifact; run bash scripts/build.sh first." >&2; exit 1; }
done
sudo -v
plugin_path=/usr/lib/ipsec/plugins/libstrongswan-fortigate-manager-subnets.so
plugin_settings=/etc/strongswan.d/charon/fortigate-manager-subnets.conf
restart_strongswan=false
if ! cmp -s target/plugin/libstrongswan-fortigate-manager-subnets.so "$plugin_path" || ! cmp -s packaging/fortigate-manager-subnets.conf "$plugin_settings"; then restart_strongswan=true; fi
if systemctl is-active --quiet fortigate-manager.socket; then sudo systemctl stop fortigate-manager.socket; fi
if systemctl is-active --quiet fortigate-manager.service; then sudo systemctl stop fortigate-manager.service; fi
if ! getent group fortigate-manager >/dev/null; then sudo groupadd --system fortigate-manager; fi
sudo usermod -a -G fortigate-manager "$login_user"
sudo install -d -m 755 /usr/local/libexec
sudo install -o root -g root -m 755 target/release/fortigate-manager /usr/local/bin/fortigate-manager
sudo install -o root -g root -m 755 target/release/fortigate-managerd /usr/local/libexec/fortigate-managerd
sudo install -o root -g root -m 644 target/plugin/libstrongswan-fortigate-manager-subnets.so /usr/lib/ipsec/plugins/
sudo install -o root -g root -m 644 packaging/fortigate-manager-subnets.conf /etc/strongswan.d/charon/
sudo install -o root -g root -m 644 packaging/fortigate-manager.socket packaging/fortigate-manager.service /etc/systemd/system/
sudo install -o root -g root -m 644 packaging/fortigate-manager.desktop /usr/share/applications/
sudo install -d -m 755 /usr/local/share/icons/hicolor/scalable/apps
sudo install -o root -g root -m 644 assets/fortigate-manager.svg /usr/local/share/icons/hicolor/scalable/apps/
sudo systemctl daemon-reload
if "$restart_strongswan"; then
    echo 'Restarting strongSwan to load the new plugin. Its existing VPN tunnels will disconnect.'
    sudo systemctl restart strongswan.service
else
    sudo systemctl start strongswan.service
fi
sudo /usr/local/libexec/fortigate-managerd --check
sudo systemctl enable --now fortigate-manager.socket
sudo -u "$login_user" -g fortigate-manager /usr/bin/python3 "$project_dir/scripts/import-saved-profiles.py" "$project_dir/.demo/state"
echo "Installed. Launch using: bash $project_dir/scripts/launch.sh"
echo 'For the desktop menu launcher, sign out and back in to refresh group membership.'
