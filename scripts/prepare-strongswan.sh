#!/usr/bin/env bash
# Download matching public API headers; never build or replace the host daemon.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_dir=${1:-"$project_dir/target/vendor/strongswan-6.0.1"}
test -f "$source_dir/config.h" && exit 0
for tool in curl sha256sum tar autoreconf automake libtoolize gperf flex bison; do
    command -v "$tool" >/dev/null || { echo "Missing $tool. Install the build dependencies listed in README.md." >&2; exit 1; }
done
archive="$project_dir/target/vendor/strongswan-6.0.1.tar.gz"
mkdir -p "$(dirname -- "$archive")"
if ! test -f "$archive"; then
    curl --fail --location --connect-timeout 15 --max-time 120 \
        https://github.com/strongswan/strongswan/archive/refs/tags/6.0.1.tar.gz -o "$archive"
fi
printf '%s  %s\n' 6184ca5be516bd91bc378c3c03c4483c7b70780e2fd4a8288ee47cbb2d0613e5 "$archive" | sha256sum --check --status
if ! test -f "$source_dir/configure.ac"; then
    mkdir -p "$source_dir"
    tar -xzf "$archive" --strip-components=1 -C "$source_dir"
fi
cd "$source_dir"
autoreconf -fi
./configure --disable-defaults --enable-charon --disable-scripts --disable-swanctl
