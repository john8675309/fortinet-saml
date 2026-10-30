#!/usr/bin/env python3
"""Build a local Debian binary package from an explicit, credential-free manifest."""
import argparse
import datetime
import gzip
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

PROJECT = Path(__file__).resolve().parents[1]


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def install(source, destination, mode=0o644):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def notices(environment):
    metadata = json.loads(run(["cargo", "metadata", "--offline", "--locked", "--format-version", "1", "--filter-platform", "x86_64-unknown-linux-gnu"], cwd=PROJECT, env=environment, capture_output=True).stdout)
    nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
    selected, queue = set(), [metadata["resolve"]["root"]]
    while queue:
        item = queue.pop()
        if item in selected:
            continue
        selected.add(item)
        queue.extend(dep["pkg"] for dep in nodes[item]["deps"])
    output = []
    for package in sorted(metadata["packages"], key=lambda p: (p["name"], p["version"])):
        if package["id"] not in selected or package["source"] is None:
            continue
        output += [f"\n{'=' * 72}\n{package['name']} {package['version']}\n", f"SPDX: {package.get('license') or 'See included license'}\n"]
        directory = Path(package["manifest_path"]).parent
        files = {file for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "COPYRIGHT*", "NOTICE*", "UNLICENSE*") for file in directory.glob(pattern) if file.is_file()}
        if package.get("license_file"):
            files.add(directory / package["license_file"])
        for file in sorted(files):
            output += [f"\n--- {file.name} ---\n", file.read_text(errors="replace"), "\n"]
    return "".join(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true", help="Package already-built, tested release artifacts")
    parser.add_argument("--version", default="0.1.0-1")
    args = parser.parse_args()
    run(["dpkg", "--validate-version", args.version])
    architecture = run(["dpkg", "--print-architecture"], capture_output=True).stdout.strip()
    if architecture != "amd64":
        raise SystemExit("This plugin build currently targets Debian 13 amd64 only.")
    environment = os.environ.copy()
    environment.setdefault("CARGO_HOME", str(PROJECT / ".cargo-home"))
    if not args.skip_build:
        run(["bash", "scripts/build.sh"], cwd=PROJECT, env=environment)
    (PROJECT / "target").mkdir(exist_ok=True)
    output = PROJECT / "dist"
    output.mkdir(exist_ok=True)
    artifact = output / f"fortigate-manager_{args.version}_{architecture}.deb"
    with tempfile.TemporaryDirectory(prefix="deb-package-", dir=PROJECT / "target") as temporary:
        work = Path(temporary)
        stage = work / "package"
        control = stage / "DEBIAN"
        control.mkdir(parents=True)
        install(PROJECT / "target/release/fortigate-manager", stage / "usr/lib/fortigate-manager/fortigate-manager", 0o755)
        install(PROJECT / "target/release/fortigate-managerd", stage / "usr/libexec/fortigate-managerd", 0o755)
        install(PROJECT / "target/plugin/libstrongswan-fortigate-manager-subnets.so", stage / "usr/lib/ipsec/plugins/libstrongswan-fortigate-manager-subnets.so")
        run(["strip", "--strip-unneeded", str(stage / "usr/lib/ipsec/plugins/libstrongswan-fortigate-manager-subnets.so")])
        install(PROJECT / "packaging/debian/launcher", stage / "usr/bin/fortigate-manager", 0o755)
        install(PROJECT / "packaging/debian/access", stage / "usr/sbin/fortigate-manager-access", 0o755)
        install(PROJECT / "assets/fortigate-manager.svg", stage / "usr/share/icons/hicolor/scalable/apps/fortigate-manager.svg")
        data = stage / "usr/share/fortigate-manager"
        install(PROJECT / "packaging/fortigate-manager-subnets.conf", data / "fortigate-manager-subnets.conf")
        for unit in ("fortigate-manager.service", "fortigate-manager.socket"):
            source = PROJECT / "packaging" / unit
            install(source, data / "legacy" / unit)
            target = stage / "usr/lib/systemd/system" / unit
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source.read_text().replace("/usr/local/libexec/", "/usr/libexec/"))
            target.chmod(0o644)
        desktop = stage / "usr/share/applications/fortigate-manager.desktop"
        desktop.parent.mkdir(parents=True, exist_ok=True)
        desktop.write_text((PROJECT / "packaging/fortigate-manager.desktop").read_text().replace("/usr/local/bin/", "/usr/bin/"))
        desktop.chmod(0o644)
        run(["desktop-file-validate", str(desktop)])
        for script in ("preinst", "postinst", "prerm", "postrm"):
            install(PROJECT / "packaging/debian" / script, control / script, 0o755)
            run(["sh", "-n", str(control / script)])
        docs = stage / "usr/share/doc/fortigate-manager"
        install(PROJECT / "COPYING", docs / "COPYING")
        install(PROJECT / "packaging/debian/README.Debian", docs / "README.Debian")
        (docs / "THIRD-PARTY-LICENSES.txt").write_text(notices(environment))
        (docs / "copyright").write_text("Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nUpstream-Name: FortiGate Manager\nSource: local source build\n\nFiles: *\nCopyright: 2026 FortiGate Manager contributors\nLicense: GPL-2+\n See COPYING for the GNU General Public License version 2.\n .\n Rust dependency notices are included in THIRD-PARTY-LICENSES.txt.\n")
        now = datetime.datetime.fromtimestamp(int(environment.get("SOURCE_DATE_EPOCH", str(int(datetime.datetime.now().timestamp())))), datetime.timezone.utc)
        change = f"fortigate-manager ({args.version}) unstable; urgency=medium\n\n  * Package the Rust tray client, local service and advertised-route plugin.\n\n -- Local Package Builder <root@localhost>  {now.strftime('%a, %d %b %Y %H:%M:%S %z')}\n"
        with gzip.GzipFile(filename=str(docs / "changelog.Debian.gz"), mode="wb", mtime=0) as stream:
            stream.write(change.encode())

        # Generate actual ELF dependency versions; private strongSwan ABI is
        # additionally bounded to the supported upstream release below.
        debian = work / "debian"
        debian.mkdir()
        (debian / "control").write_text("Source: fortigate-manager\nSection: net\nPriority: optional\nMaintainer: Local Package Builder <root@localhost>\n\nPackage: fortigate-manager\nArchitecture: any\nDescription: FortiGate VPN desktop client and local service\n")
        elf = [stage / "usr/lib/fortigate-manager/fortigate-manager", stage / "usr/libexec/fortigate-managerd", stage / "usr/lib/ipsec/plugins/libstrongswan-fortigate-manager-subnets.so"]
        dependencies = run(["dpkg-shlibdeps", "-O", "-l/usr/lib/ipsec", *[f"-e{path}" for path in elf]], cwd=work, capture_output=True).stdout.strip()
        if not dependencies.startswith("shlibs:Depends="):
            raise SystemExit("Could not generate package library dependencies")
        dependencies = dependencies.removeprefix("shlibs:Depends=")
        extra = "charon-systemd (>= 6.0.1), charon-systemd (<< 6.0.2~), strongswan-swanctl (>= 6.0.1), strongswan-libcharon (<< 6.0.2~), libstrongswan (<< 6.0.2~), libcharon-extra-plugins (>= 6.0.1), libayatana-appindicator3-1, systemd, init-system-helpers (>= 1.56~), adduser, passwd, ca-certificates, xdg-utils"
        size = sum(p.stat().st_size for p in stage.rglob("*") if p.is_file()) // 1024 + 1
        (control / "control").write_text(f"Package: fortigate-manager\nVersion: {args.version}\nSection: net\nPriority: optional\nArchitecture: {architecture}\nMaintainer: Local Package Builder <root@localhost>\nInstalled-Size: {size}\nDepends: {dependencies}, {extra}\nRecommends: desktop-file-utils, hicolor-icon-theme\nDescription: FortiGate IKEv2 VPN tray client and local strongSwan service\n Native Rust GTK client with browser SAML authentication, saved VPN profiles,\n a local authenticated management service, and gateway-advertised IPv4 routes.\n Starts in the system tray and is listed in the Internet applications menu.\n Built for Debian 13 amd64 and the strongSwan 6.0.1 plugin ABI.\n")
        files = sorted(p for p in stage.rglob("*") if p.is_file() and control not in p.parents)
        import hashlib
        (control / "md5sums").write_text("".join(f"{hashlib.md5(path.read_bytes()).hexdigest()}  {path.relative_to(stage)}\n" for path in files))
        for path in [stage, *stage.rglob("*")]:
            if path.is_dir():
                path.chmod(0o755)
            elif not path.stat().st_mode & 0o111:
                path.chmod(0o644)
        # No environment files, private profiles, browser/session data, caches,
        # or source-tree directories are copied into the package.
        assert all(str(path.relative_to(stage)).startswith("usr/") for path in files)
        run(["dpkg-deb", "--root-owner-group", "--build", str(stage), str(artifact)])
    print(f"Built {artifact}")


if __name__ == "__main__":
    main()
