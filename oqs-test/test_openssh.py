import helpers
import os
import sys
import time

sig_algs = ['ssh-ed25519']
if 'WITH_PQAUTH' in os.environ and os.environ['WITH_PQAUTH'] == 'true':
    # post-quantum
    sig_algs += [
##### OQS_TEMPLATE_FRAGMENT_LIST_SIGS_START
    # post-quantum only sigs
    'ssh-oqsdefault','ssh-dilithium2','ssh-falcon512','ssh-mqdss3148','ssh-picnicl1ur','ssh-qteslapi','ssh-rainbowiaclassic','ssh-rainbowiiicclassic','ssh-rainbowvcclassic','ssh-sphincsharaka128frobust','ssh-sphincssha256128frobust','ssh-sphincsshake256128frobust',
    # hybrid sigs
    'ssh-rsa3072-oqsdefault','ssh-p256-oqsdefault','ssh-rsa3072-dilithium2','ssh-p256-dilithium2','ssh-rsa3072-falcon512','ssh-p256-falcon512','ssh-rsa3072-mqdss3148','ssh-p256-mqdss3148','ssh-rsa3072-picnicl1ur','ssh-p256-picnicl1ur','ssh-rsa3072-qteslapi','ssh-p256-qteslapi','ssh-rsa3072-rainbowiaclassic','ssh-p256-rainbowiaclassic','ssh-p384-rainbowiiicclassic','ssh-p521-rainbowvcclassic','ssh-rsa3072-sphincsharaka128frobust','ssh-p256-sphincsharaka128frobust','ssh-rsa3072-sphincssha256128frobust','ssh-p256-sphincssha256128frobust','ssh-rsa3072-sphincsshake256128frobust','ssh-p256-sphincsshake256128frobust',
##### OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END
]

kex_algs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_KEXS_START
    # post-quantum only kex
    'bike1-l1-cpa-sha384@openquantumsafe.org','bike1-l3-cpa-sha384@openquantumsafe.org','bike1-l1-fo-sha384@openquantumsafe.org','bike1-l3-fo-sha384@openquantumsafe.org','classic-mceliece-348864-sha384@openquantumsafe.org','classic-mceliece-348864f-sha384@openquantumsafe.org','classic-mceliece-460896-sha384@openquantumsafe.org','classic-mceliece-460896f-sha384@openquantumsafe.org','classic-mceliece-6688128-sha384@openquantumsafe.org','classic-mceliece-6688128f-sha384@openquantumsafe.org','classic-mceliece-6960119-sha384@openquantumsafe.org','classic-mceliece-6960119f-sha384@openquantumsafe.org','classic-mceliece-8192128-sha384@openquantumsafe.org','classic-mceliece-8192128f-sha384@openquantumsafe.org','frodo-640-aes-sha384@openquantumsafe.org','frodo-640-shake-sha384@openquantumsafe.org','frodo-976-aes-sha384@openquantumsafe.org','frodo-976-shake-sha384@openquantumsafe.org','frodo-1344-aes-sha384@openquantumsafe.org','frodo-1344-shake-sha384@openquantumsafe.org','kyber-512-sha384@openquantumsafe.org','kyber-768-sha384@openquantumsafe.org','kyber-1024-sha384@openquantumsafe.org','kyber-512-90s-sha384@openquantumsafe.org','kyber-768-90s-sha384@openquantumsafe.org','kyber-1024-90s-sha384@openquantumsafe.org','newhope-512-sha384@openquantumsafe.org','newhope-1024-sha384@openquantumsafe.org','ntru-hps-2048-509-sha384@openquantumsafe.org','ntru-hps-2048-677-sha384@openquantumsafe.org','ntru-hrss-701-sha384@openquantumsafe.org','ntru-hps-4096-821-sha384@openquantumsafe.org','saber-lightsaber-sha384@openquantumsafe.org','saber-saber-sha384@openquantumsafe.org','saber-firesaber-sha384@openquantumsafe.org','sidh-p434-sha384@openquantumsafe.org','sidh-p503-sha384@openquantumsafe.org','sidh-p610-sha384@openquantumsafe.org','sidh-p751-sha384@openquantumsafe.org','sidh-p434-compressed-sha384@openquantumsafe.org','sidh-p503-compressed-sha384@openquantumsafe.org','sidh-p610-compressed-sha384@openquantumsafe.org','sidh-p751-compressed-sha384@openquantumsafe.org','sike-p434-sha384@openquantumsafe.org','sike-p503-sha384@openquantumsafe.org','sike-p610-sha384@openquantumsafe.org','sike-p751-sha384@openquantumsafe.org','-sha384@openquantumsafe.org','sike-p503-compressed-sha384@openquantumsafe.org','sike-p610-compressed-sha384@openquantumsafe.org','sike-p751-compressed-sha384@openquantumsafe.org','babybear-sha384@openquantumsafe.org','babybear-ephem-sha384@openquantumsafe.org','mamabear-sha384@openquantumsafe.org','mamabear-ephem-sha384@openquantumsafe.org','papabear-sha384@openquantumsafe.org','papabear-ephem-sha384@openquantumsafe.org','hqc-128-1-cca2-sha384@openquantumsafe.org','hqc-192-1-cca2-sha384@openquantumsafe.org','hqc-192-2-cca2-sha384@openquantumsafe.org','hqc-256-1-cca2-sha384@openquantumsafe.org','hqc-256-2-cca2-sha384@openquantumsafe.org','hqc-256-3-cca2-sha384@openquantumsafe.org',
    # hybrid kex
    'ecdh-nistp384-bike1-l1-cpa-sha384@openquantumsafe.org','ecdh-nistp384-bike1-l3-cpa-sha384@openquantumsafe.org','ecdh-nistp384-bike1-l1-fo-sha384@openquantumsafe.org','ecdh-nistp384-bike1-l3-fo-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-348864-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-348864f-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-460896-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-460896f-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-6688128-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-6688128f-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-6960119-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-6960119f-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-8192128-sha384@openquantumsafe.org','ecdh-nistp384-classic-mceliece-8192128f-sha384@openquantumsafe.org','ecdh-nistp384-frodo-640-aes-sha384@openquantumsafe.org','ecdh-nistp384-frodo-640-shake-sha384@openquantumsafe.org','ecdh-nistp384-frodo-976-aes-sha384@openquantumsafe.org','ecdh-nistp384-frodo-976-shake-sha384@openquantumsafe.org','ecdh-nistp384-frodo-1344-aes-sha384@openquantumsafe.org','ecdh-nistp384-frodo-1344-shake-sha384@openquantumsafe.org','ecdh-nistp384-kyber-512-sha384@openquantumsafe.org','ecdh-nistp384-kyber-768-sha384@openquantumsafe.org','ecdh-nistp384-kyber-1024-sha384@openquantumsafe.org','ecdh-nistp384-kyber-512-90s-sha384@openquantumsafe.org','ecdh-nistp384-kyber-768-90s-sha384@openquantumsafe.org','ecdh-nistp384-kyber-1024-90s-sha384@openquantumsafe.org','ecdh-nistp384-newhope-512-sha384@openquantumsafe.org','ecdh-nistp384-newhope-1024-sha384@openquantumsafe.org','ecdh-nistp384-ntru-hps-2048-509-sha384@openquantumsafe.org','ecdh-nistp384-ntru-hps-2048-677-sha384@openquantumsafe.org','ecdh-nistp384-ntru-hrss-701-sha384@openquantumsafe.org','ecdh-nistp384-ntru-hps-4096-821-sha384@openquantumsafe.org','ecdh-nistp384-saber-lightsaber-sha384@openquantumsafe.org','ecdh-nistp384-saber-saber-sha384@openquantumsafe.org','ecdh-nistp384-saber-firesaber-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p434-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p503-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p610-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p751-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p434-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p503-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p610-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p751-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sike-p434-sha384@openquantumsafe.org','ecdh-nistp384-sike-p503-sha384@openquantumsafe.org','ecdh-nistp384-sike-p610-sha384@openquantumsafe.org','ecdh-nistp384-sike-p751-sha384@openquantumsafe.org','ecdh-nistp384--sha384@openquantumsafe.org','ecdh-nistp384-sike-p503-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sike-p610-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sike-p751-compressed-sha384@openquantumsafe.org','ecdh-nistp384-babybear-sha384@openquantumsafe.org','ecdh-nistp384-babybear-ephem-sha384@openquantumsafe.org','ecdh-nistp384-mamabear-sha384@openquantumsafe.org','ecdh-nistp384-mamabear-ephem-sha384@openquantumsafe.org','ecdh-nistp384-papabear-sha384@openquantumsafe.org','ecdh-nistp384-papabear-ephem-sha384@openquantumsafe.org','ecdh-nistp384-hqc-128-1-cca2-sha384@openquantumsafe.org','ecdh-nistp384-hqc-192-1-cca2-sha384@openquantumsafe.org','ecdh-nistp384-hqc-192-2-cca2-sha384@openquantumsafe.org','ecdh-nistp384-hqc-256-1-cca2-sha384@openquantumsafe.org','ecdh-nistp384-hqc-256-2-cca2-sha384@openquantumsafe.org','ecdh-nistp384-hqc-256-3-cca2-sha384@openquantumsafe.org',
##### OQS_TEMPLATE_FRAGMENT_LIST_KEXS_END
        ]


def test_gen_keys():
    global sig_algs
    helpers.run_subprocess(
        ['rm', '-rf', 'ssh_client'],
        working_dir=os.path.join('oqs-test', 'tmp')
    )
    helpers.run_subprocess(
        ['rm', '-rf', 'ssh_server'],
        working_dir=os.path.join('oqs-test', 'tmp')
    )
    os.mkdir(os.path.join('oqs-test', 'tmp', 'ssh_client'), mode=0o700)
    os.mkdir(os.path.join('oqs-test', 'tmp', 'ssh_server'), mode=0o700)
    for party in ['client', 'server']:
        for sig_alg in sig_algs:
            yield (gen_keys, sig_alg, party)

def gen_keys(sig_alg, party):
    helpers.run_subprocess(
        [
            'bin/ssh-keygen',
            '-t', sig_alg,
            '-N', '',
            '-f', os.path.join('ssh_{}'.format(party), 'id_{}'.format(sig_alg))
        ],
        os.path.join('oqs-test', 'tmp')
    )

def test_connection():
    global sig_algs, kex_algs
    port = 22345
    for sig_alg in sig_algs:
        if 'rainbow' in sig_alg:
            # TODO: Revisit this after round 3 candidates come out
            if 'classic-mceliece-8192128f-sha384@openquantumsafe.org' in kex_algs:
                yield(run_connection, sig_alg, 'classic-mceliece-8192128f-sha384@openquantumsafe.org', port)
            else:
                yield(run_connection, sig_alg, kex_algs[0], port)
            port = port + 1
        else:
            for kex_alg in kex_algs:
                if ('WITH_OPENSSL' in os.environ and os.environ['WITH_OPENSSL'] != 'true') and ('ecdh' in kex_alg):
                    continue
                yield(run_connection, sig_alg, kex_alg, port)
                port = port + 1

def run_connection(sig_alg, kex_alg, port):
    helpers.run_subprocess(
        [os.path.join('oqs-test', 'do_openssh.sh')],
        env={
            'SIGALG': sig_alg,
            'KEXALG': kex_alg,
            'PORT': str(port),
        }
    )

if __name__ == '__main__':
    try:
        import nose2
        nose2.main()
    except ImportError:
        import nose
        nose.runmodule()
