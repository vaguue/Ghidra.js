#!/bin/bash

set -x

PATH=$PATH:/opt/homebrew/Caskroom/ghidra/10.4-20230928/ghidra_10.4_PUBLIC

buildJavet() {
  cur=$(pwd)
  cd Extension/Javet/Ghidra.js
  ./build.sh $@
  cd $cur
}

buildJavet $@
