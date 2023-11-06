#!/bin/bash

set -x

javetId=$1
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
