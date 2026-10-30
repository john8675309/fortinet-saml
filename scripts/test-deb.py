#!/usr/bin/env python3
"""Inspect a .deb and test its maintainer-file lifecycle in an isolated root.

This does not install the package, manage host accounts, or restart services.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    args = parser.parse_args()
    package = args.package.resolve()
    assert run(["dpkg-deb", "-f", str(package), "Package"], capture_output=True).stdout.strip() == "fortigate-manager"
    assert run(["dpkg-deb", "-f", str(package), "Architecture"], capture_output=True).stdout.strip() == "amd64"
    deps = run(["dpkg-deb", "-f", str(package), "Depends"], capture_output=True).stdout
    assert all(name in deps for name in ("libgtk-3-0t64", "libayatana-appindicator3-1", "charon-systemd", "6.0.2~"))
    with subprocess.Popen(["dpkg-deb", "--fsys-tarfile", str(package)], stdout=subprocess.PIPE) as process:
        with tarfile.open(fileobj=process.stdout, mode="r|") as archive:
            for member in archive:
                name = member.name.removeprefix("./")
                assert member.uid == 0 and member.gid == 0, name
                assert name in ("", ".", "usr") or name.startswith("usr/"), name
                assert not any(part in {".env", ".demo", ".cargo-home", "profiles", "__pycache__"} for part in Path(name).parts)
                assert not member.mode & 0o022, name
        assert process.wait() == 0
    with tempfile.TemporaryDirectory(prefix="fortigate-deb-test-") as temporary:
        root = Path(temporary) / "root"
        controls = Path(temporary) / "control"
        run(["dpkg-deb", "-x", str(package), str(root)])
        run(["dpkg-deb", "-e", str(package), str(controls)])
        for line in (controls / "md5sums").read_text().splitlines():
            checksum, name = line.split("  ", 1)
            assert hashlib.md5((root / name).read_bytes()).hexdigest() == checksum, name
        for name in ("preinst", "postinst", "prerm", "postrm"):
            run(["sh", "-n", str(controls / name)])
            assert os.access(controls / name, os.X_OK)
        desktop = root / "usr/share/applications/fortigate-manager.desktop"
        run(["desktop-file-validate", str(desktop)])
        assert "Categories=Network;GTK;" in desktop.read_text()
        assert "Exec=/usr/bin/fortigate-manager" in desktop.read_text()
        assert "ExecStart=/usr/libexec/fortigate-managerd" in (root / "usr/lib/systemd/system/fortigate-manager.service").read_text()
        legacy = root / "usr/share/fortigate-manager/legacy"
        units = root / "etc/systemd/system"
        units.mkdir(parents=True)
        for unit in ("fortigate-manager.service", "fortigate-manager.socket"):
            (units / unit).write_bytes((legacy / unit).read_bytes() + b"\n")
        wants = units / "sockets.target.wants"
        wants.mkdir()
        (wants / "fortigate-manager.socket").symlink_to("/etc/systemd/system/fortigate-manager.socket")
        state = root / "var/lib/fortigate-manager"
        sentinel = state / "1000/0123456789abcdef0123456789abcdef.json"
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text('{"private-state":"synthetic-test-data"}')
        sentinel.chmod(0o600)
        before = sentinel.read_bytes()
        environment = os.environ.copy()
        environment["DPKG_ROOT"] = str(root)
        run(["sh", str(controls / "preinst"), "install"], env=environment)
        run(["sh", str(controls / "postinst"), "configure"], env=environment)
        assert not (units / "fortigate-manager.service").exists()
        assert not (units / "fortigate-manager.socket").exists()
        assert not (wants / "fortigate-manager.socket").is_symlink()
        assert len(list((state / "manual-unit-backups").iterdir())) == 2
        settings = root / "etc/strongswan.d/charon/fortigate-manager-subnets.conf"
        assert "load = yes" in settings.read_text()
        custom = "# Administrator override: preserve this file\n"
        (units / "fortigate-manager.service").write_text(custom)
        run(["sh", str(controls / "postinst"), "configure"], env=environment)
        assert (units / "fortigate-manager.service").read_text() == custom
        run(["sh", str(controls / "prerm"), "remove"], env=environment)
        assert not settings.exists(), "Critical plugin directive must not survive library removal"
        settings.write_text("# custom settings\nload = yes\n")
        run(["sh", str(controls / "prerm"), "remove"], env=environment)
        assert settings.with_name(settings.name + ".disabled-by-package-removal").exists()
        run(["sh", str(controls / "postrm"), "remove"], env=environment)
        run(["sh", str(controls / "postrm"), "purge"], env=environment)
        assert sentinel.read_bytes() == before, "Saved profile data must be retained"
    print("PASS: package metadata, dependencies, root ownership, file modes, checksums, Internet launcher, unit paths, legacy migration, removal and profile retention")


if __name__ == "__main__":
    main()
