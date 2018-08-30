#!/bin/bash

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $LD_PRELOAD ]] && LD_PRELOAD+=" "
export LD_PRELOAD+="$dir/hardened_malloc.so"
exec "$@"
