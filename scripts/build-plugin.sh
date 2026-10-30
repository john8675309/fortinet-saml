#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_dir=${1:-${STRONGSWAN_SOURCE_DIR:-"$project_dir/target/vendor/strongswan-6.0.1"}}
plugin_dir="$project_dir/route-plugin"
output_dir="$project_dir/target/plugin"
if ! test -f "$source_dir/config.h"; then bash "$project_dir/scripts/prepare-strongswan.sh" "$source_dir"; fi
mkdir -p "$output_dir"
flags=(-std=gnu11 -O2 -g -Wall -Wextra -Werror -Wno-unused-parameter -DFGR_MANAGER_PLUGIN
       -include "$source_dir/config.h" -I "$source_dir/src/libstrongswan"
       -I "$source_dir/src/libstrongswan/utils" -I "$source_dir/src/libcharon")
libs=(-L /usr/lib/ipsec -Wl,-rpath,/usr/lib/ipsec -lcharon -lstrongswan)
gcc "${flags[@]}" -fPIC -shared "$plugin_dir/fortigate_subnets.c" "${libs[@]}" -Wl,-z,defs -o "$output_dir/libstrongswan-fortigate-manager-subnets.so"
gcc "${flags[@]}" -fsanitize=address,undefined -fno-omit-frame-pointer "$plugin_dir/test_plugin.c" "${libs[@]}" -o "$output_dir/test_plugin"
cd "$output_dir"
./test_plugin
