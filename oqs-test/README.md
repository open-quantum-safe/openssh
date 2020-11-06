OQS-OpenSSH Integration Testing
===============================

[![CircleCI](https://circleci.com/gh/open-quantum-safe/openssh-portable/tree/OQS-master.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/openssh-portable/tree/OQS-master)

---

This directory contains scripts for testing the OQS fork of OpenSSH with liboqs, using all supported algorithms. The [README.md file for the OQS-OpenSSH fork](https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/README.md) describes the various key exchange and authentication mechanisms supported.

First make sure you have **installed the dependencies** for the target OS as indicated in the [top-level README](https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/README.md).

Testing on Linux
-----------------

The tests should run on Ubuntu 18.04 (Bionic).

### Running directly

Before running the script on Linux, you may need to create directories and users for OpenSSH privilege separation.  (On some Linux installations this will already exist, on others you may need to create it.)  Please try the following:

1. Create the privilege separation directory:

		sudo mkdir -p -m 0755 /var/empty

2. Create the privilege separation user:

		sudo groupadd sshd
		sudo useradd -g sshd -c 'sshd privsep' -d /var/empty -s /bin/false sshd

Then, in the project root directory, run:

	env WITH_PQAUTH={true|false} WITH_OPENSSL={true|false} python3 -m nose --rednose --verbose

### Running using CircleCI

You can locally run any of the integration tests that CircleCI runs.  First, you need to install CircleCI's local command line interface as indicated in the [installation instructions](https://circleci.com/docs/2.0/local-cli/).  Then:

	circleci local execute --job <jobname>

where `<jobname>` is one of the following:

- `with-openssl`
- `without-openssl`

By default, these jobs will use the latest Github versions of liboqs.  You can override this by modifying the `oqs-scripts/clone_liboqs.sh`.
