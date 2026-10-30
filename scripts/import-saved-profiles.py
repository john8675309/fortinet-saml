"""Check the real service and migrate the user's previously saved editor profiles.

Only the local authenticated API receives keys. Nothing secret is printed.
"""
import json
import os
from pathlib import Path
import socket
import stat
import sys


def call(request):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(15)
        client.connect("/run/fortigate-manager/control.sock")
        client.sendall(json.dumps(request).encode() + b"\n")
        with client.makefile("rb") as stream:
            data = stream.readline(1_048_577)
    if len(data) > 1_048_576:
        raise ValueError("Oversized response")
    response = json.loads(data)
    if not response.get("ok"):
        raise ValueError("Service rejected request")
    return response


def main():
    response = call({"op": "list"})
    print("Real local service is responding.")
    seen = {(v["profile"]["name"], v["profile"]["gateway"]) for v in response["profiles"]}
    previous = Path(sys.argv[1]) / str(os.getuid())
    imported = 0
    failed = 0
    if previous.is_dir():
        for path in previous.glob("*.json"):
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                    continue
                if info.st_size > 1_048_576:
                    continue
                saved = json.loads(path.read_text())
                profile = saved["profile"]
                if profile.get("gateway", "").endswith((".example.com", ".invalid")):
                    continue
                identity = (profile["name"], profile["gateway"])
                if identity in seen:
                    continue
                profile["id"] = ""
                call({"op": "save", "profile": profile, "psk": saved["psk"]})
                seen.add(identity)
                imported += 1
            except (ValueError, KeyError, OSError):
                failed += 1
    print(f"Imported {imported} previously saved VPN profiles. Credentials were not printed.")
    if failed:
        print(f"{failed} profiles could not be imported; enter them using New VPN.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError):
        print("Could not contact the installed service. Check systemctl status fortigate-manager.service.", file=sys.stderr)
        raise SystemExit(1)
