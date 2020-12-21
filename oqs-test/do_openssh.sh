#!/bin/bash

###########
# Run one client/server interaction in OpenSSH
#
# Environment variables:
#  - KEXALG: key exchange algorithm to use
#  - SIGALG: signature algorithm to use
#  - PREFIX: path to install directory
#  - PORT: port to run server on
###########

set -x

PREFIX=${PREFIX:-"$(pwd)/oqs-test/tmp"}

rm -f "${PREFIX}"/server_log.txt
rm -f "${PREFIX}"/client_log.txt

rm -f "${PREFIX}"/ssh_server/authorized_keys
touch "${PREFIX}"/ssh_server/authorized_keys
chmod 600 "${PREFIX}"/ssh_server/authorized_keys
cat "${PREFIX}"/ssh_client/*.pub >> "${PREFIX}"/ssh_server/authorized_keys

"${PREFIX}"/sbin/sshd -q -p "${PORT}" -d \
  -f "${PREFIX}/sshd_config" \
  -o "KexAlgorithms=${KEXALG}" \
  -o "AuthorizedKeysFile=${PREFIX}/ssh_server/authorized_keys" \
  -o "HostKeyAlgorithms=${SIGALG}" \
  -o "PubkeyAcceptedKeyTypes=${SIGALG}" \
  -o "StrictModes=no" \
  -h "${PREFIX}/ssh_server/id_${SIGALG}" \
  >> "${PREFIX}"/server_log.txt 2>&1 &

if [[ "${SIGALG}" =~ "rainbowi" ]]; then
    sleep 10
elif [[ "${SIGALG}" =~ "rainbowiii" ]]; then
    sleep 20
elif [[ "${SIGALG}" =~ "rainbowv" ]]; then
    sleep 60
else
    sleep 2
fi

SERVER_PID=$!

"${PREFIX}/bin/ssh" \
  -p "${PORT}" 127.0.0.1 \
  -F "${PREFIX}"/ssh_config \
  -o "UserKnownHostsFile /dev/null" \
  -o "KexAlgorithms=${KEXALG}" \
  -o "HostKeyAlgorithms=${SIGALG}" \
  -o "PubkeyAcceptedKeyTypes=${SIGALG}" \
  -o StrictHostKeyChecking=no \
  -i "${PREFIX}/ssh_client/id_${SIGALG}" \
  "exit" \
  >> "${PREFIX}"/client_log.txt 2>&1

kill -9 ${SERVER_PID}

echo "--- SERVER LOG ---"
cat "${PREFIX}"/server_log.txt

echo "--- CLIENT LOG ---"
cat "${PREFIX}"/client_log.txt

set -e
grep SSH_CONNECTION "${PREFIX}"/client_log.txt
grep "debug1: kex: algorithm: ${KEXALG}" "${PREFIX}"/server_log.txt
grep "debug1: kex: host key algorithm: ${SIGALG}" "${PREFIX}"/server_log.txt
set +e

rm -f "${PREFIX}"/server_log.txt
rm -f "${PREFIX}"/client_log.txt

exit 0
