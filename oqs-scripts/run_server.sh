#!/bin/bash

###########
# Start an instance of the OpenSSH server
#
# Environment variables:
#  - KEXALG: key exchange algorithm to use
#  - SIGALG: signature algorithm to use
#  - PREFIX: path to OpenSSH install directory
#  - PORT: port to run server on
###########

PREFIX=${PREFIX:-"`pwd`/oqs-test/tmp"}
KEXALG=${KEXALG:-"classic-mceliece-8192128f-sha384@openquantumsafe.org"}
SIGALG=${SIGALG:-"ssh-rainbowvcclassic"}
PORT=${PORT:-4433}

${PREFIX}/sbin/sshd -q -p ${PORT} -d \
  -f "${PREFIX}/sshd_config" \
  -o "KexAlgorithms=${KEXALG}" \
  -o "AuthorizedKeysFile=${PREFIX}/ssh_server/authorized_keys" \
  -o "StrictModes=no"
