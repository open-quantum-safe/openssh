# This script simply picks a random OQS or non-OQS key-exchange
# and signature algorithm, and checks whether the stock BoringSSL
# client and server can establish a handshake with the choices.

import os
import random
import subprocess
import time

# Requires make tests LTESTS="" to be run first

pq_kexs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_PQ_KEXNAMES_START
    "frodokem-640-aes-sha256",
    "frodokem-976-aes-sha384",
    "frodokem-1344-aes-sha512",
    "sike-p434-sha256",
##### OQS_TEMPLATE_FRAGMENT_LIST_PQ_KEXNAMES_END
]

hybrid_kexs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_KEXNAMES_START
    "ecdh-nistp256-frodokem-640-aes-sha256",
    "ecdh-nistp384-frodokem-976-aes-sha384",
    "ecdh-nistp521-frodokem-1344-aes-sha512",
    "ecdh-nistp256-sike-p434-sha256",
##### OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_KEXNAMES_END
]

sigs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_END
]

def try_handshake(ssh, sshd):
    random_sig = 'ssh-ed25519' ## TODO: random.choice(sigs)
    random_kex = random.choice(pq_kexs)

    sshd_process = subprocess.Popen([sshd,
                                    '-f', os.path.abspath('regress/sshd_config'),
                                    "-o", "KexAlgorithms={}".format(random_kex),
                                    "-o", "HostKeyAlgorithms={}".format(random_sig),
                                    '-D'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)

    # sshd should (hopefully?) start in 10 seconds.
    time.sleep(10)

    # Try to connect to it with the client
    ssh_process = subprocess.run([ssh,
                                 '-F', os.path.abspath('regress/ssh_config'),
                                 'somehost', 'true'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
    sshd_process.kill()

    if ssh_process.returncode != 0:
        print(ssh_process.stdout.decode())
        raise Exception('Cannot establish a connection with {} and {}'.format(random_kex, random_sig))

    print("Success! Key Exchange Algorithm: {}.".format(random_kex))

if __name__ == '__main__':
    try_handshake(os.path.abspath('ssh'), os.path.abspath('sshd'))
