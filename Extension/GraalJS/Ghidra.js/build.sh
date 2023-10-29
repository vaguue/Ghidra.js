#!/bin/bash


root=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}"  )" &> /dev/null && pwd  );
target=$root/../../../dist/graaljs

GHIDRA_INSTALL_DIR=/opt/homebrew/Caskroom/ghidra/10.4-20230928/ghidra_10.4_PUBLIC gradle buildExtension -x test

mkdir -p $target
cp dist/* $target
