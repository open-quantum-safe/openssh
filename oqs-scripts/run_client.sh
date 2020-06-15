#!/bin/bash

###########
# Start an instance of the OpenSSH client
#
# Environment variables:
#  - KEXALG: key exchange algorithm to use
#  - SIGALG: signature algorithm to use
#  - PREFIX: path to OpenSSH install directory
#  - PORT: port to run server on
###########

PREFIX=${PREFIX:-"`pwd`/oqs-test/tmp"}
KEXALG=${KEXALG:-"bike1-l1-cpa-sha384@openquantumsafe.org"}
SIGALG=${SIGALG:-"ssh-rainbowiiicclassic"}
PORT=${PORT:-4433}

${PREFIX}/bin/ssh \
  -p ${PORT} 127.0.0.1 \
  -F ${PREFIX}/ssh_config \
  -o "UserKnownHostsFile /dev/null" \
  -o "KexAlgorithms=${KEXALG}" \
  -o "HostKeyAlgorithms=${SIGALG}" \
  -o "PubkeyAcceptedKeyTypes=${SIGALG}" \
  -o StrictHostKeyChecking=no \
  -i "${PREFIX}/ssh_client/id_${SIGALG}" \
  "exit"
