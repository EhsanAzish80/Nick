#!/bin/zsh
set -euo pipefail

script_dir=${0:A:h}
exec "$script_dir/canary-web.sh"
