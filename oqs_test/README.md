OQS-OpenSSH Integration Testing
===============================

[![CircleCI](https://circleci.com/gh/open-quantum-safe/openssh-portable/tree/OQS-master.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/openssh-portable/tree/OQS-master)

---

This directory contains scripts for testing the OQS fork of OpenSSH with liboqs, using all supported algorithms. The [README.md file for the OQS-OpenSSH fork](https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/README.md) describes the various key exchange and authentication mechanisms supported.

First make sure you have **installed the dependencies** for the target OS as indicated in the [top-level testing README](https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/README.md).

Testing on Linux and macOS
--------------------------

The scripts have been tested on macOS 10.14, Debian 10 (Buster), and Ubuntu 18.04 (Bionic).

### Running directly

Before running the script on Linux, you may need to create directories and users for OpenSSH privilege separation.  (On some Linux installations this will already exist, on others you may need to create it.)  Please try the following:

1. Create the privilege separation directory:

		sudo mkdir -p -m 0755 /var/empty

2. Create the privilege separation user:

		sudo groupadd sshd
		sudo useradd -g sshd -c 'sshd privsep' -d /var/empty -s /bin/false sshd

Then run:

	cd oqs_test
	./run.sh

Alternatively, to log the run.sh output while following live, try:

    ./run.sh | tee `date "+%Y%m%d-%Hh%Mm%Ss-openssh.log.txt"`
	
### Running using CircleCI

You can locally run any of the integration tests that CircleCI runs.  First, you need to install CircleCI's local command line interface as indicated in the [installation instructions](https://circleci.com/docs/2.0/local-cli/).  Then:

	circleci local execute --job <jobname>

where `<jobname>` is one of the following:

- `ssh-amd64-buster-liboqs-master-with-openssl-with-pqauth`
- `ssh-amd64-buster-liboqs-master-with-openssl-no-pqauth`
- `ssh-amd64-buster-liboqs-master-no-openssl-no-pqauth`
- `ssh-x86_64-bionic-liboqs-master-with-openssl-with-pqauth`
- `ssh-x86_64-bionic-liboqs-master-with-openssl-no-pqauth`
- `ssh-x86_64-bionic-liboqs-master-no-openssl-no-pqauth`

By default, these jobs will use the current Github versions of liboqs and OQS-OpenSSH.  You can override these by passing environment variables to CircleCI:

	circleci local execute --job <jobname> --env <NAME>=<VALUE> --env <NAME>=<VALUE> ...

where `<NAME>` is one of the following:

- `LIBOQS_REPO`: which repo to check out from, default `https://github.com/open-quantum-safe/liboqs.git`
- `LIBOQS_BRANCH`: which branch to check out, default `master`
