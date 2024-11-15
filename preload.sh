#!/bin/sh

# preload.sh - Test dynamically linked executables

[ ! -f "out/libhardened_malloc.so" ] && make -j"$(nproc)" # If the library isn't found, build it.
[ -n "${LD_PRELOAD}" ] && LD_PRELOAD="${LD_PRELOAD} " # If LD_PRELOAD is already set, add a space.
export LD_PRELOAD="${LD_PRELOAD}${PWD}/out/libhardened_malloc.so" # Add the library to LD_PRELOAD.
exec "$@" # Run the command.
