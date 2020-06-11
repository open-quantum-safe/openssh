#!/bin/bash

###########
# Do a full run through of a single liboqs/OpenSSH integration test combination
#
# Environment variables:
#  - ARCH: either x64 (default) or x86
#
# The following environment variables affect subsequent scripts:
#  - OPENSSL_SYS_DIR: path to system OpenSSL installation; default /usr
#  - LIBOQS_REPO: which repo to check out from, default https://github.com/open-quantum-safe/liboqs.git
#  - LIBOQS_BRANCH: which branch to check out, default master
#  - WITH_OPENSSL: build OpenSSH with (true, default) or without (false) OpenSSL
#  - WITH_PQAUTH: build OpenSSH with (true, default) or without (false) post-quantum authentication
###########

set -exo pipefail

ARCH=${ARCH:-"x64"}

scripts/clone_liboqs.sh
scripts/build_liboqs.sh
scripts/build_openssh.sh
python3 -m nose --rednose --verbose
