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

OKAY=1

rm -f ${PREFIX}/server_log.txt
rm -f ${PREFIX}/client_log.txt

rm -f ${PREFIX}/ssh_server/authorized_keys
touch ${PREFIX}/ssh_server/authorized_keys
chmod 600 ${PREFIX}/ssh_server/authorized_keys
cat ${PREFIX}/ssh_client/*.pub >> ${PREFIX}/ssh_server/authorized_keys

${PREFIX}/sbin/sshd -q -p ${PORT} -d \
  -f "${PREFIX}/sshd_config" \
  -o "KexAlgorithms=${KEXALG}" \
  -o "AuthorizedKeysFile=${PREFIX}/ssh_server/authorized_keys" \
  -o "HostKeyAlgorithms=${SIGALG}" \
  -o "PubkeyAcceptedKeyTypes=${SIGALG}" \
  -h "${PREFIX}/ssh_server/id_${SIGALG}" \
  >> ${PREFIX}/server_log.txt 2>&1 &

sleep 1

SERVER_PID=$!

${PREFIX}/bin/ssh \
  -p ${PORT} 127.0.0.1 \
  -F ${PREFIX}/ssh_config \
  -o "KexAlgorithms=${KEXALG}" \
  -o "HostKeyAlgorithms=${SIGALG}" \
  -o "PubkeyAcceptedKeyTypes=${SIGALG}" \
  -o StrictHostKeyChecking=no \
  -i "${PREFIX}/ssh_client/id_${SIGALG}" \
  "exit" \
  >> ${PREFIX}/client_log.txt 2>&1

kill -9 ${SERVER_PID}

A=`cat ${PREFIX}/client_log.txt | grep SSH_CONNECTION`
if [ $? -eq 0 ];then
  OKAY=0
fi

echo "--- SERVER LOG ---"
cat ${PREFIX}/server_log.txt

echo "--- CLIENT LOG ---"
cat ${PREFIX}/client_log.txt

rm -f ${PREFIX}/server_log.txt
rm -f ${PREFIX}/client_log.txt

exit ${OKAY}