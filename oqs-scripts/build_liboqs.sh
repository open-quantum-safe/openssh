#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - PREFIX: path to install liboqs, default `pwd`/../oqs
#  - LIBOQS_CMAKE_ARGS: arguments to pass to cmake when building liboqs, default empty
###########

set -exo pipefail

PREFIX=${PREFIX:-"`pwd`/oqs"}
LIBOQS_CMAKE_ARGS=${LIBOQS_CMAKE_ARGS:-""}

cd oqs-scripts/tmp/liboqs
rm -rf build
mkdir build && cd build
cmake .. -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DCMAKE_INSTALL_PREFIX=${PREFIX} ${LIBOQS_CMAKE_ARGS}
ninja
ninja install
