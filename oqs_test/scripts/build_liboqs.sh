#!/bin/bash

###########
# Build liboqs
#
# Environment variables:
#  - OPENSSL_SYS_DIR: path to system OpenSSL installation; default /usr
#  - PREFIX: path to install liboqs, default `pwd`/../oqs
###########

set -exo pipefail

case "$OSTYPE" in
    darwin*)  OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr/local/opt/openssl@1.1"} ;;
    linux*)   OPENSSL_SYS_DIR=${OPENSSL_SYS_DIR:-"/usr"} ;;
    *)        echo "Unknown operating system: $OSTYPE" ; exit 1 ;;
esac

PREFIX=${PREFIX:-"`pwd`/tmp/install"}

cd tmp/liboqs
autoreconf -i
./configure --prefix=${PREFIX} --with-pic=yes --with-openssl=${OPENSSL_SYS_DIR}
if [ "x${CIRCLECI}" == "xtrue" ] || [ "x${TRAVIS}" == "xtrue" ]; then
    make -j2
else
    make -j
fi
make install
