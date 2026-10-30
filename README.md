# fortinet-saml

A native Rust desktop client and a local Rust service for FortiGate IPsec/IKEv2 VPNs using browser-based SAML authentication. The service configures strongSwan through VICI; a dedicated plugin requests the gateway's protected IPv4 subnets and installs split-tunnel policies and routes.

The desktop app is named **FortiGate Manager**. It starts in the system tray and appears under **Internet** in the applications menu.

## Install the Debian package

Current target: **Debian 13, amd64, strongSwan 6.0.1**.

Download the `.deb` from [Releases](https://github.com/john8675309/fortinet-saml/releases), then install it with apt so runtime dependencies are resolved:

```bash
sudo apt install ./fortigate-manager_0.1.0-1_amd64.deb
/usr/bin/fortigate-manager
```

Open the tray menu and choose **Open FortiGate Manager**, or run:

```bash
/usr/bin/fortigate-manager --show
```

When installed using sudo, the installing user is authorized automatically. To authorize another desktop user, or after a graphical/root installation:

```bash
sudo fortigate-manager-access USER
```

The launcher refreshes the authorized group for its own process. Run the GUI as your normal user. Initial installation and route-plugin changes restart strongSwan and disconnect its tunnels; application upgrades stop the manager's own tunnels.

## Create and connect

1. Select **New VPN** and enter a name, gateway, SAML HTTPS port and PSK.
2. Match the gateway's phase 1 and phase 2 settings under **Advanced connection settings**.
3. Save and select **Connect**. Complete SSO/MFA in your normal browser.
4. Inspect assigned addresses, traffic counters and VPN networks in **Connection**.
5. Disconnect through the window or the tray menu.

Closing the window hides it in the tray. **Quit** exits the client while established VPNs remain managed by the service. Leaving the PSK field blank while editing preserves the saved key. Disconnect before editing or deleting a profile.

## Features and scope

- PSK plus browser SAML/SSO/MFA; configurable HTTPS, IKE UDP and loopback callback ports, plus optional SAML CA PEM.
- Multiple phase 1 and phase 2 encryption/integrity proposals, DH groups, PFS, replay detection, second/byte lifetimes, optional identities and DPD.
- Automatic NAT traversal or forced UDP encapsulation.
- Gateway-advertised IPv4 routes via `INTERNAL_IP4_SUBNET`, with no default-route fallback when a usable subnet list is absent.
- Optional exclusion of directly connected active IPv4 LAN ranges.
- Saved profiles, per-profile tray actions, and one active tunnel per gateway address.

This version supports IKEv2, Mode Config and UDP transport. It does not implement SSL VPN, IKEv1, IKE certificate authentication, manual/DHCP address assignment, TCP failover, gateway failover lists or IPv6 VPN routes. Other FortiGate configurations may require protocol adjustments.

## Architecture and credentials

- Unprivileged Rust/GTK 3 desktop client.
- Root service authenticated through a Unix socket and Linux `SO_PEERCRED`.
- Direct VICI operations for individual connections and credentials; bulk credential clearing and bulk connection loading are not used.
- Separate critical strongSwan plugin scoped to generated per-user/profile connection names. It validates subnet attributes, intersects them with negotiated selectors, migrates route state on IKE rekey and cleans up on destruction.

Profiles and PSKs are stored in `/var/lib/fortigate-manager/UID/ID.json` with root-only directory/file permissions (`0700`/`0600`). PSKs are not encrypted at rest. Profile API responses omit PSKs and SAML tokens. Membership in `fortigate-manager` grants the ability to manage host VPN connections.

The SAML callback listens only on IPv4/IPv6 loopback and accepts the configured port on `localhost`, `127.0.0.1` and `[::1]`. Token URLs are not logged. Browser launch occurs in the user's GUI process.

No VPN credentials, saved profiles, private gateway details or authentication logs are included in this repository or package.

## Build from source

Install the build and runtime dependencies:

```bash
sudo apt install build-essential cargo rustc libgtk-3-dev pkg-config dpkg-dev \
  autoconf automake libtool gettext gperf flex bison curl \
  strongswan-swanctl charon-systemd libcharon-extra-plugins \
  libayatana-appindicator3-1 desktop-file-utils

git clone https://github.com/john8675309/fortinet-saml.git
cd fortinet-saml
bash scripts/build.sh
python3 scripts/build-deb.py --skip-build
```

The plugin preparation script downloads checksum-pinned strongSwan 6.0.1 source and configures matching headers under `target/vendor`. It does not rebuild or replace the host daemon. To use an existing configured source tree, set `STRONGSWAN_SOURCE_DIR`.

The resulting package is written to `dist/`. `scripts/build-deb.py` generates versioned ELF dependencies and includes the desktop entry, service/socket units, access helper, plugin, icon, license notices and installation/removal scripts.

For an explicitly managed manual development installation, `scripts/install.sh` is also available. Prefer the Debian package for regular deployment. After migrating from an older manual installation, use the Internet-menu launcher or `/usr/bin/fortigate-manager`; old `/usr/local` binaries are not overwritten by the package.

## Validation and operation

```bash
CARGO_HOME="$PWD/.cargo-home" cargo test --locked --all-targets
bash scripts/build-plugin.sh
python3 scripts/test-deb.py dist/fortigate-manager_0.1.0-1_amd64.deb
systemctl status fortigate-manager.socket fortigate-manager.service
sudo /usr/libexec/fortigate-managerd --check
ip route show table 220
```

Tests cover configuration validation, credential permissions/user isolation, callback/redirect parsing, VICI wire format and events, connection generation and the real local API's handling of unavailable VICI. Plugin checks use ASan/UBSan and the installed library's plugin loader. The Rust client and advertised-route flow have worked against a FortiGate deployment; long-running rekey behavior and heavy-transfer stability need additional live testing.

Tray checks on a real desktop confirmed hidden startup, registration, Open and Quit behavior without restarting the local service. A compatible system tray host is required; if the AppIndicator runtime is absent, the client opens a normal window.

Remove with `sudo apt remove fortigate-manager`. Saved profiles and the access group are retained for recovery, including after purge. Do not publish raw authentication logs or `ip xfrm state` output, which can expose keys.

## License and protocol background

GPL-2.0-or-later; see [COPYING](COPYING). The Debian package includes Rust dependency license notices. The plugin uses strongSwan's attribute-handler and traffic-selector listener APIs. The browser SAML flow was informed by [quincampoix/fortigate-saml-vpn](https://github.com/quincampoix/fortigate-saml-vpn).
