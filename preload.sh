#!/bin/bash

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $LD_PRELOAD ]] && LD_PRELOAD+=" "
export LD_PRELOAD+="$dir/libhardened_malloc.so"
exec "$@"
