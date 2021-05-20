# This script simply picks a random OQS or non-OQS key-exchange
# and signature algorithm, and checks whether the stock BoringSSL
# client and server can establish a handshake with the choices.

import os
import random
import subprocess
import time
import sys

# Requires make tests LTESTS="" to be run first

kexs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_START
    "oqs-default-sha256",
    "ecdh-nistp256-oqs-default-sha256",
    "frodokem-640-aes-sha256",
    "ecdh-nistp256-frodokem-640-aes-sha256",
    "frodokem-976-aes-sha384",
    "ecdh-nistp384-frodokem-976-aes-sha384",
    "frodokem-1344-aes-sha512",
    "ecdh-nistp521-frodokem-1344-aes-sha512",
    "sike-p434-sha256",
    "ecdh-nistp256-sike-p434-sha256",
    "kyber-512-sha256",
    "ecdh-nistp256-kyber-512-sha256",
    "kyber-768-sha384",
    "ecdh-nistp384-kyber-768-sha384",
    "kyber-1024-sha512",
    "ecdh-nistp521-kyber-1024-sha512",
    "kyber-512-90s-sha256",
    "ecdh-nistp256-kyber-512-90s-sha256",
    "kyber-768-90s-sha384",
    "ecdh-nistp384-kyber-768-90s-sha384",
    "kyber-1024-90s-sha512",
    "ecdh-nistp521-kyber-1024-90s-sha512",
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_KEXS_END
]

sigs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_START
    "ssh-oqsdefault",
    "ssh-rsa3072-oqsdefault",
    "ssh-ecdsa-nistp256-oqsdefault",
    "ssh-dilithium2",
    "ssh-rsa3072-dilithium2",
    "ssh-ecdsa-nistp256-dilithium2",
    "ssh-dilithium3",
    "ssh-ecdsa-nistp384-dilithium3",
    "ssh-dilithium5",
    "ssh-ecdsa-nistp521-dilithium5",
    "ssh-dilithium2aes",
    "ssh-rsa3072-dilithium2aes",
    "ssh-ecdsa-nistp256-dilithium2aes",
    "ssh-dilithium3aes",
    "ssh-ecdsa-nistp384-dilithium3aes",
    "ssh-dilithium5aes",
    "ssh-ecdsa-nistp521-dilithium5aes",
##### OQS_TEMPLATE_FRAGMENT_LIST_ALL_SIGS_END
]

def do_handshake(ssh, sshd, test_sig, test_kex):
    sshd_process = subprocess.Popen([sshd,
                                    '-f', os.path.abspath('regress/sshd_config'),
                                    "-o", "KexAlgorithms={}".format(test_kex),
                                    "-o", "HostKeyAlgorithms={}".format(test_sig),
                                    '-D'],
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT)

    # sshd should locally (hopefully?) start in 1 second.
    time.sleep(1)

    # Try to connect to it with the client
    ssh_process = subprocess.run([ssh,
                                 '-F', os.path.abspath('regress/ssh_config'),
                                 "-o", "HostKeyAlgorithms={}".format(test_sig),
                                 'somehost', 'true'],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
    ssh_stdout = ssh_process.stdout.decode()
    sshd_process.kill()

    assert "debug1: kex: algorithm: {}".format(test_kex) in ssh_stdout, ssh_stdout
    assert "debug1: kex: host key algorithm: {}".format(test_sig) in ssh_stdout, ssh_stdout
    assert ssh_process.returncode == 0, ssh_stdout

    print("Success! Key Exchange Algorithm: {}. Signature Algorithm: {}.".format(test_kex, test_sig))

def try_handshake(ssh, sshd, dorandom=True):
    if dorandom:
       test_sig = random.choice(sigs)
       test_kex = random.choice(kexs)
       do_handshake(ssh, sshd, test_sig, test_kex)
    else:
       for test_kex in kexs:
           for test_sig in sigs:
              do_handshake(ssh, sshd, test_sig, test_kex)

if __name__ == '__main__':
    try_handshake(os.path.abspath('ssh'), os.path.abspath('sshd'), dorandom=(len(sys.argv)==1))
