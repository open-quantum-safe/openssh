import helpers
import os
import sys
import time

sig_algs = ['ssh-ed25519']
if 'WITH_PQAUTH' in os.environ and os.environ['WITH_PQAUTH'] == 'true':
    # post-quantum
    sig_algs += ['ssh-qteslai', 'ssh-qteslaiiispeed', 'ssh-qteslaiiisize', 'ssh-picnicl1fs', 'ssh-picnic2l1fs', 'ssh-picnic2l3fs', 'ssh-picnic2l5fs', 'ssh-oqsdefault']
    # hybrid
    sig_algs += ['ssh-p256-qteslai', 'ssh-rsa3072-qteslai', 'ssh-p384-qteslaiiispeed', 'ssh-p384-qteslaiiisize', 'ssh-p256-picnicl1fs', 'ssh-rsa3072-picnicl1fs', 'ssh-p256-picnic2l1fs', 'ssh-rsa3072-picnic2l1fs', 'ssh-p384-picnic2l3fs', 'ssh-p521-picnic2l5fs', 'ssh-p256-oqsdefault', 'ssh-rsa3072-oqsdefault']

# post-quantum only KEX
kex_algs = ['bike1-L1-sha384@openquantumsafe.org', 'bike1-L3-sha384@openquantumsafe.org', 'bike1-L5-sha384@openquantumsafe.org', 'frodo-640-aes-sha384@openquantumsafe.org', 'frodo-976-aes-sha384@openquantumsafe.org', 'sike-503-sha384@openquantumsafe.org', 'sike-751-sha384@openquantumsafe.org', 'oqsdefault-sha384@openquantumsafe.org']
# hybrid KEX
kex_algs += ['ecdh-nistp384-bike1-L1-sha384@openquantumsafe.org', 'ecdh-nistp384-bike1-L3-sha384@openquantumsafe.org', 'ecdh-nistp384-bike1-L5-sha384@openquantumsafe.org', 'ecdh-nistp384-frodo-640-aes-sha384@openquantumsafe.org', 'ecdh-nistp384-frodo-976-aes-sha384@openquantumsafe.org', 'ecdh-nistp384-sike-503-sha384@openquantumsafe.org', 'ecdh-nistp384-sike-751-sha384@openquantumsafe.org', 'ecdh-nistp384-oqsdefault-sha384@openquantumsafe.org']


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
            if 'CIRCLECI' in os.environ:
                if 'bike' in kex_alg:
                    continue # FIXME: BIKE doesn't work on CircleCI due to symbol _CMP_LT_OS not being defined
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
