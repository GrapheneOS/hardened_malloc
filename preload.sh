#!/bin/bash

dir=$(cd "$(dirname ${BASH_SOURCE[0]})" && pwd)
export LD_PRELOAD+=" $dir/hardened_malloc.so"
exec $@
