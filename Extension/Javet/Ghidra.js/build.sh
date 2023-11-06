#!/bin/bash

set -x

javetId=$0
[ -z "$1" ] && GHIDRA_INSTALL_DIR=/opt/homebrew/Caskroom/ghidra/10.4-20230928/ghidra_10.4_PUBLIC || GHIDRA_INSTALL_DIR=$1
suffix="_Ghidra.js.zip"

echo javetId: $javetId
echo GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR

root=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}"  )" &> /dev/null && pwd  );
target=$root/../../../dist/javet

rm $root/dist/* &> /dev/null
gradle buildExtension -x test -PjavetId=$javetId

mv $root/dist/* $root/dist/$javetId$suffix

mkdir -p $target
rm $target/* &> /dev/null
cp dist/* $target
