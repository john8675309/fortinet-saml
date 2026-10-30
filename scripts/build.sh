#!/usr/bin/env bash
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
export CARGO_HOME="${CARGO_HOME:-$project_dir/.cargo-home}"
cargo build --locked --release
bash scripts/build-plugin.sh
echo "Built GUI, local service and advertised-route plugin under $project_dir/target"
