#!/bin/bash

set -x

javetId=$1
[ -z "$2" ] && export GHIDRA_INSTALL_DIR=/opt/homebrew/Caskroom/ghidra/10.4-20230928/ghidra_10.4_PUBLIC || export GHIDRA_INSTALL_DIR=$2
outFile="Ghidra.js.zip"

echo javetId: $javetId
echo GHIDRA_INSTALL_DIR: $GHIDRA_INSTALL_DIR

root=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}"  )" &> /dev/null && pwd  );
target=$root/../../../dist/javet

rm $root/dist/* &> /dev/null
gradle buildExtension -x test -PjavetId=$javetId
[ $? -ne 0 ] && exit 1

mv $root/dist/* $root/dist/$outFile

mkdir -p $target
rm $target/* &> /dev/null
cp dist/* $target
