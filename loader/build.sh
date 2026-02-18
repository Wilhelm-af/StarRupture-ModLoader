#!/bin/bash
set -e
cd "$(dirname "$0")/.."

x86_64-w64-mingw32-g++ -shared -o version.dll \
    loader/version.cpp \
    loader/version.def \
    -static-libgcc -static-libstdc++ \
    -Wl,--enable-stdcall-fixup \
    -O2 -std=c++17
echo "Built version.dll ($(stat -c%s version.dll) bytes)"
