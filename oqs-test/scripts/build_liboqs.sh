#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - PREFIX: path to install liboqs, default `pwd`/../oqs
###########

set -exo pipefail

PREFIX=${PREFIX:-"`pwd`/tmp/install"}

cd tmp/liboqs
rm -rf build
mkdir build && cd build
cmake .. -GNinja -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=${PREFIX}
ninja
ninja install
