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
    'ssh-oqsdefault','ssh-dilithium2','ssh-dilithium4','ssh-mqdss3148','ssh-picnicl1fs','ssh-picnicl1ur','ssh-picnicl1full','ssh-picnicl3fs','ssh-picnicl3ur','ssh-picnicl3full','ssh-picnicl5fs','ssh-picnicl5ur','ssh-picnicl5full','ssh-picnic3l1','ssh-picnic3l3','ssh-picnic3l5','ssh-qteslapi','ssh-qteslapiii','ssh-sphincsharaka128frobust',
    # hybrid sigs
    'ssh-rsa3072-oqsdefault','ssh-p256-oqsdefault','ssh-rsa3072-dilithium2','ssh-p256-dilithium2','ssh-p384-dilithium4','ssh-rsa3072-mqdss3148','ssh-p256-mqdss3148','ssh-rsa3072-picnicl1fs','ssh-p256-picnicl1fs','ssh-rsa3072-picnicl1ur','ssh-p256-picnicl1ur','ssh-rsa3072-picnicl1full','ssh-p256-picnicl1full','ssh-p384-picnicl3fs','ssh-p384-picnicl3ur','ssh-p384-picnicl3full','ssh-p521-picnicl5fs','ssh-p521-picnicl5ur','ssh-p521-picnicl5full','ssh-rsa3072-picnic3l1','ssh-p256-picnic3l1','ssh-p384-picnic3l3','ssh-p384-picnic3l5','ssh-rsa3072-qteslapi','ssh-p256-qteslapi','ssh-p384-qteslapiii','ssh-rsa3072-sphincsharaka128frobust','ssh-p256-sphincsharaka128frobust',
##### OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END
]

kex_algs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_KEXS_START
    # post-quantum only kex
    'bike1-l1-cpa-sha384@openquantumsafe.org','bike1-l3-cpa-sha384@openquantumsafe.org','bike1-l1-fo-sha384@openquantumsafe.org','bike1-l3-fo-sha384@openquantumsafe.org','frodo-640-aes-sha384@openquantumsafe.org','frodo-976-aes-sha384@openquantumsafe.org','kyber-512-sha384@openquantumsafe.org','kyber-768-sha384@openquantumsafe.org','kyber-1024-sha384@openquantumsafe.org','newhope-512-sha384@openquantumsafe.org','newhope-1024-sha384@openquantumsafe.org','ntru-hps-2048-509-sha384@openquantumsafe.org','ntru-hps-2048-677-sha384@openquantumsafe.org','saber-lightsaber-sha384@openquantumsafe.org','saber-saber-sha384@openquantumsafe.org','saber-firesaber-sha384@openquantumsafe.org','sidh-p434-sha384@openquantumsafe.org','sidh-p503-sha384@openquantumsafe.org','sidh-p610-sha384@openquantumsafe.org','sidh-p751-sha384@openquantumsafe.org','sidh-p434-compressed-sha384@openquantumsafe.org','sidh-p503-compressed-sha384@openquantumsafe.org','sidh-p610-compressed-sha384@openquantumsafe.org','sidh-p751-compressed-sha384@openquantumsafe.org','sike-p434-sha384@openquantumsafe.org','sike-p503-sha384@openquantumsafe.org','sike-p610-sha384@openquantumsafe.org','sike-p751-sha384@openquantumsafe.org','sike-p434-compressed-sha384@openquantumsafe.org','sike-p503-compressed-sha384@openquantumsafe.org','sike-p610-compressed-sha384@openquantumsafe.org','sike-p751-compressed-sha384@openquantumsafe.org',
    # hybrid kex
    'ecdh-nistp384-bike1-l1-cpa-sha384@openquantumsafe.org','ecdh-nistp384-bike1-l3-cpa-sha384@openquantumsafe.org','ecdh-nistp384-bike1-l1-fo-sha384@openquantumsafe.org','ecdh-nistp384-bike1-l3-fo-sha384@openquantumsafe.org','ecdh-nistp384-frodo-640-aes-sha384@openquantumsafe.org','ecdh-nistp384-frodo-976-aes-sha384@openquantumsafe.org','ecdh-nistp384-kyber-512-sha384@openquantumsafe.org','ecdh-nistp384-kyber-768-sha384@openquantumsafe.org','ecdh-nistp384-kyber-1024-sha384@openquantumsafe.org','ecdh-nistp384-newhope-512-sha384@openquantumsafe.org','ecdh-nistp384-newhope-1024-sha384@openquantumsafe.org','ecdh-nistp384-ntru-hps-2048-509-sha384@openquantumsafe.org','ecdh-nistp384-ntru-hps-2048-677-sha384@openquantumsafe.org','ecdh-nistp384-saber-lightsaber-sha384@openquantumsafe.org','ecdh-nistp384-saber-saber-sha384@openquantumsafe.org','ecdh-nistp384-saber-firesaber-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p434-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p503-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p610-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p751-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p434-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p503-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p610-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sidh-p751-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sike-p434-sha384@openquantumsafe.org','ecdh-nistp384-sike-p503-sha384@openquantumsafe.org','ecdh-nistp384-sike-p610-sha384@openquantumsafe.org','ecdh-nistp384-sike-p751-sha384@openquantumsafe.org','ecdh-nistp384-sike-p434-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sike-p503-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sike-p610-compressed-sha384@openquantumsafe.org','ecdh-nistp384-sike-p751-compressed-sha384@openquantumsafe.org',
##### OQS_TEMPLATE_FRAGMENT_LIST_KEXS_END
        ]


def test_gen_keys():
    global sig_algs
    helpers.run_subprocess(
        ['rm', '-rf', 'ssh_client'],
        os.path.join('tmp', 'install')
    )
    helpers.run_subprocess(
        ['rm', '-rf', 'ssh_server'],
        os.path.join('tmp', 'install')
    )
    os.mkdir(os.path.join('tmp', 'install', 'ssh_client'), mode=0o700)
    os.mkdir(os.path.join('tmp', 'install', 'ssh_server'), mode=0o700)
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
        os.path.join('tmp', 'install')
    )

def test_connection():
    global sig_algs, kex_algs
    port = 22345
    for sig_alg in sig_algs:
        for kex_alg in kex_algs:
            if 'WITH_OPENSSL' in os.environ and os.environ['WITH_OPENSSL'] != 'true':
                if 'ecdh' in kex_alg:
                    continue
            yield(run_connection, sig_alg, kex_alg, port)
            port = port + 1

def run_connection(sig_alg, kex_alg, port):
    helpers.run_subprocess(
        [os.path.join('scripts', 'do_openssh.sh')],
        env={
            'SIGALG': sig_alg,
            'KEXALG': kex_alg,
            'PORT': str(port),
            'PREFIX': os.path.join(os.getcwd(), 'tmp', 'install')
        }
    )

if __name__ == '__main__':
    try:
        import nose2
        nose2.main()
    except ImportError:
        import nose
        nose.runmodule()
