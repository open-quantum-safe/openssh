open-quantum-safe/openssh-portable
==================================

**OpenSSH** is an open-source implementation of the Secure Shell protocol https://openssh.org/.  ([View the original README file for OpenSSH](https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/README).)

This repository contains a fork of OpenSSH that adds quantum-resistant key exchange and signature algorithms using liboqs for prototyping purposes.

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms. OpenSSH can use either the [master](https://github.com/open-quantum-safe/liboqs/tree/master) or the [nist](https://github.com/open-quantum-safe/liboqs/tree/nist-branch) branch of liboqs for key exchange mechanisms, but the master branch is required for signature mechanisms. The master branch is recommended for normal uses of OpenSSH as included mechanisms follow a stricter set of requirements; the nist branch contains more algorithms and is better suited for experimentation.

**open-quantum-safe/openssh-portable** contains a fork of OpenSSH that adds quantum-safe key exchange algorithms using liboqs for prototyping purposes, specifically adding key exchange methods that use hybrid (post-quantum + traditional elliptic curve) or post-quantum-only algorithms.  The integration should not be considered "production quality".  The OQS-master branch of open-quantum-safe/openssh-portable is currently based on **OpenSSH version 7.9** (Git tag V_7_9_P1).

More information on OQS can be found on our website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

Contents
--------

This branch ([OQS-master](https://github.com/open-quantum-safe/openssh-portable/tree/OQS-master)) integrates post-quantum key exchange and authentication from liboqs in SSH 2 in OpenSSH v7.9 portable 1.

### Key exchange mechanisms

The following key exchange / key encapsulation methods from liboqs are supported (assuming they have been enabled in liboqs):

- `bike1-L1`, `bike1-L3`, `bike1-L5`
- `frodo-640-aes`, `frodo-976-aes`
- `newhope-512`, `newhope-1024`
- `sike-503`, `sike-751`
- `oqsdefault`

### Authentication mechanisms

The following signature methods from liboqs's master branch are supported (assuming they have been enabled in liboqs and that the `pq-auth` configuration option has been enabled; see below):

- `qteslai`, `qteslaiiispeed`, `qteslaiiisize`
- `picnicl1fs`, `picnic2l1fs`, `picnic2l3fs`, `picnic2l5fs`
- `oqsdefault`

In addition to the PQ-only signature methods, the following hybrid methods are supported combining a PQ scheme with either RSA3072 or ECDSA using NIST's P256 curve for L1 schemes, and with ECDSA using NIST's P384 curve for L3 schemes (assuming the PQ schemes have been enabled in liboqs and that the `hybrid-auth` configuration option has been enabled; see below):

- `rsa3072-qteslai`, `p256-qteslai`, `p384-qteslaiiispeed`, `p384-qteslaiiisize`
- `rsa3072-picnicl1fs`, `p256-picnicl1fs`, `rsa3072-picnic2l1fs`, `p256-picnic2l1fs`, `p384-picnic2l3fs`, `p521-picnic2l5fs`
- `rsa3072-oqsdefault`, `p256-oqsdefault`

The liboqs's nist branch uses a different signature API that hasn't yet been integrated.

Limitations and security
------------------------

liboqs is designed for prototyping and evaluating quantum-resistant cryptography.  Security of proposed quantum-resistant algorithms may rapidly change as research advances, and may ultimately be completely insecure against either classical or quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms.  liboqs does not intend to "pick winners", and we strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying post-quantum cryptography.

We acknowledge that some parties may want to begin deploying post-quantum cryptography prior to the conclusion of the NIST standardization project.  We strongly recommend that any attempts to do make use of so-called **hybrid cryptography**, in which post-quantum public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

liboqs is provided "as is", without warranty of any kind.  See [LICENSE.txt](https://github.com/open-quantum-safe/liboqs/blob/nist-branch/LICENSE.txt) for the full disclaimer.

The integration of liboqs into our fork of OpenSSH is currently at an experimental stage.  This fork of OpenSSH has not received the same level of auditing and analysis that OpenSSH has received.  At this stage, we do not recommend relying on it in any production environment or to protect any sensitive data.

The OQS fork of OpenSSH is not endorsed by with the OpenSSH project.

This fork is developed for the purposes of prototyping and evaluating the use of post-quantum cryptography in SSH, and is not intended for use in production environments to protect the transmission of sensitive information.

At the time of writing, there are no vulnerabilities or weaknesses known in any of the post-quantum key exchange algorithms used in this fork.  However, it is advisable to wait on deploying post-quantum algorithms until further guidance is provided by the standards community, especially from the NIST Post-Quantum Cryptography project.

Lifecycle for open-quantum-safe/openssh-portable OQS-master branch
------------------------------------------------------------------

**Release cycle:** We aim to make releases of our fork of OpenSSH stable on a bi-monthly basis, either when there has been a new release of OpenSSH or when we have made changes to our fork.

See the README.md files of [liboqs master branch](https://github.com/open-quantum-safe/liboqs/blob/master/README.md) and [liboqs nist-branch](https://github.com/open-quantum-safe/liboqs/blob/nist-branch/README.md) for information about the algorithm lifecycle within the corresponding libraries.

**SSH compatibility:** The message format used in this fork is not standardized, and is subject to unilateral change at any time without regards to backwards compatibility with previous versions of this fork.

Building on Linux and macOS
---------------------------

Builds have been tested manually on macOS 10.14 (clang 10.0.0), Ubuntu 14.04 (gcc-5), Ubuntu 16.04 (gcc-5), and Ubuntu 18.04.1 (gcc-7).

### Step 0: Install dependencies

For **Ubuntu**, you need to install the following packages:

	sudo apt install autoconf automake gcc libtool libssl-dev make unzip xsltproc

For **Ubuntu 18.04**, you need to downgrade the version of OpenSSL.  (Ubuntu 18.04 bundles OpenSSL 1.1.0 by default,  but OpenSSH only supports building against OpenSSL 1.0.2 at present.)

	sudo apt install openssl1.0 libssl1.0-dev
	
Warning: this removes the existing libssl 1.1 development package.

On **Linux**, you also may need to do the following:

- You may need to create the privilege separation directory:

		sudo mkdir -p -m 0755 /var/empty

- You may need to create the privilege separation user:

		sudo groupadd sshd
		sudo useradd -g sshd -c 'sshd privsep' -d /var/empty -s /bin/false sshd

For **macOS**, you need to install the following packages using brew (or a package manager of your choice):

	brew install autoconf automake libtool openssl wget
	
### Step 1: Build and install liboqs

You can use the either the [master](https://github.com/open-quantum-safe/liboqs/tree/master) or the [nist](https://github.com/open-quantum-safe/liboqs/tree/nist-branch) branch of liboqs with the OQS-master branch of OpenSSH for key exchange mechanisms (each branch support a different set, see above), but the master branch is required for signature mechanisms.

You will need to specify a path to install liboqs in during configure time; we recommend that you install in a special-purpose directory, rather than the global `/usr` or `/usr/local` directories.

For the **master branch** of liboqs:

	git clone -b master --single-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
	./configure --prefix=<path-to-openssl-dir>/oqs --with-pic=yes --enable-shared=no
	make -j
	make install
	rm -f <path-to-install-liboqs>/lib/liboqs.so*

Building liboqs requires your system to have OpenSSL already installed.  configure will detect it if it is located in a standard location, such as `/usr` or `/usr/local/opt/openssl` (for brew on macOS).  Otherwise, you may need to specify it with `--with-openssl=<path-to-system-openssl-dir>`.

For the **nist branch** of liboqs:

	git clone -b nist-branch --single-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	make -j
	make install-noshared PREFIX=<path-to-install-liboqs>

### Step 2: Build fork of OpenSSH

Next, you can build and install our fork of OpenSSH:

	export LIBOQS_INSTALL=<path-to-liboqs>
	export OPENSSH_INSTALL=<path-to-install-openssh>
	git clone https://github.com/open-quantum-safe/openssh-portable.git
	cd openssh-portable
	autoreconf

For Ubuntu 16.04 and macOS, try the following:

	./configure --enable-pq-kex --enable-hybrid-kex      \
	            --enable-pq-auth --enable-hybrid-auth    \
	            --with-ssl-dir=<path-to-openssl>/include \
	            --with-ldflags=-L<path-to-openssl>/lib   \
	            --prefix=$OPENSSH_INSTALL                \
	            --sysconfdir=$OPENSSH_INSTALL            \
	            --with-liboqs-dir=$LIBOQS_INSTALL
	make -j
	make install

On Ubuntu 18.04, some modifications are required due to the default openssl version:

	./configure --enable-pq-kex --enable-hybrid-kex   \
	            --enable-pq-auth --enable-hybrid-auth \
	            --with-ldflags=-L/usr/lib/ssl1.0      \
	            --prefix=$OPENSSH_INSTALL             \
	            --sysconfdir=$OPENSSH_INSTALL         \
	            --with-liboqs-dir=$LIBOQS_INSTALL
	make -j
	make install

Notes about building OpenSSH:

- `--enable-pq-kex` enables PQ-only key exchange methods.
- `--enable-hybrid-kex` enables hybrid key exchange methods.
- `--enable-pq-auth` enables PQ-only authentication methods, requires the liboqs master branch.
- `--enable-hybrid-auth` enables hybrid authentication methods, requires the liboqs master branch.

Running
-------

The following instructions explain how to run a quantum-safe SSH connection (with both key exchange and authentication).

### Generating post-quantum authentication keys

To setup post-quantum authentication, the server and optionally the client need to generate post-quantum keys. The process
is illustrated using test key files. In what follows, `<SIG>` is one of the signature algorithms listed in the Contents
section above.

The server generates its key files with the right permissions, and then generates its key pair:

	mkdir ~/ssh_server/
	chmod 700 ~/ssh_server/
	touch ~/ssh_server/authorized_keys
	chmod 600 ~/ssh_server/authorized_keys
	<path-to-openssh>/bin/ssh-keygen -t ssh-<SIG> -f ~/ssh_server/id_<SIG>

To enable client-side public-key authentication, the client generates its key pair:

	mkdir ~/ssh_client/
	<path-to-openssh>/bin/ssh-keygen -t ssh-<SIG> -f ~/ssh_client/id_<SIG>

The server then adds the client's public key to its authorized keys

	cat ~/ssh_client/id_<SIG>.pub >> ~/ssh_server/authorized_keys

### Running key exchange

In what follows, `<KEX>` and `<SIG>` are one of the key exchange and signature (PQ-only or hybrid) algorithms listed in the Contents section above, respectively. The `-o` options can instead be added to the server/client configuration file.

In one terminal, run a server:

	sudo <path-to-openssh>/sbin/sshd -p 2222 -d             \
	    -o KexAlgorithms=<LIBOQS_ALGORITHM_KEX>             \
	    [-o AuthorizedKeysFile=<absolute-path-to>/ssh_server/authorized_keys \
	     -o HostKeyAlgorithms=<LIBOQS_SIG_ALGORITHM>        \
	     -o PubkeyAcceptedKeyTypes=<LIBOQS_SIG_ALGORITHM>   \
	     -h <absolute-path-to>/ssh_server/id_<SIG>]

where `<LIBOQS_SIG_ALGORITHM>` is `ssh-<SIG>` all in lowercase.

The server automatically supports all available hybrid and PQ-only key exchange methods.  `sudo` is required on Linux so that sshd can read the shadow password file. The arguments between `[...]` are for post-quantum authentication and can be omitted to use classical authentication.

In another terminal, run a client:

	<path-to-openssh>/bin/ssh -l <username>              \
	    -p 2222 localhost                                \
	    -o KexAlgorithms=<LIBOQS_ALGORITHM_KEX>          \
	   [-o HostKeyAlgorithms=<LIBOQS_SIG_ALGORITHM>      \
	    -o PubkeyAcceptedKeyTypes=<LIBOQS_SIG_ALGORITHM> \
	    -o StrictHostKeyChecking=no                      \
	    -i ~/ssh_client/id_<SIG>]

where `<LIBOQS_KEX_ALGORITHM>` is either:

- `<KEX>-sha384@openquantumsafe.org` (for post-quantum-only key exchange)
- `ecdh-nistp384-<KEX>-sha384@openquantumsafe.org` (for hybrid post-quantum and elliptic curve key exchange)

and where `<LIBOQS_SIG_ALGORITHM>` is `ssh-<SIG>` all in lowercase.

The `StrictHostKeyChecking` option is used to allow trusting the newly generated server key; alternatively, the key could be added manually to the client's trusted keys. The arguments between `[...]` are for post-quantum authentication and can be omitted to use classical authentication.

### Automated tests

To test the build, run:

	make tests

oqsdefault alg
--------------

liboqs can be configured at compile-time to use any of its algorithms as its "default" algorithm.  If OpenSSH is told to use `oqsdefault`, then it will use whichever KEM or signature algorithm was set as the default in liboqs at compile time.

The purpose of this option is as follows.  The liboqs master and nist branches contain different subsets of algorithms; and the master branch is needed to enable PQC authentication.  We will make most algorithms from liboqs master branch available as a named key exchange or signature method in OpenSSH.  However, there are significantly more algorithms supported in the nist branch than in the master one, and we will not be explicitly making each nist branch algorithm available as a named method in OpenSSH.  It is still possible to test with algorithms not made available as named methods in OpenSSH using the `oqsdefault` method in OpenSSH by changing the default mapping in liboqs and then recompiling the library.

1. Recompile liboqs with your preferred default algorithm:
	- For liboqs master branch:
		- `cd liboqs`
		- For KEX: edit `src/kem/kem.h` and change `#define OQS_KEM_DEFAULT` to map to your preferred algorithm
		- For signature: edit `src/sig/sig.h` and change `#define OQS_SIG_DEFAULT` to map to your preferred algorithm
		- `make clean`
		- `make -j`
		- `make install`
	- For liboqs nist-branch:
		- `cd liboqs`
		- `make clean`
		- `make -j KEM_DEFAULT=newhope_1024_cca_kem` (or whichever algorithm you prefer)
		- `make install-noshared PREFIX=<path-to-install-liboqs>`
2. Recompile OpenSSH against the newly build liboqs:
	- `cd openssh-portable`
	- `make clean`
	- `make -j`
	- `make install`
3. Run `ssh` with `oqsdefault` replacing the `<KEX>` and/or `<SIG>` value in the Running section above.

License
-------

This fork is released under the same license(s) as Portable OpenSSH. More information about licensing can be found in the LICENSE file.

(Pre-draft) IETF Draft
----------------------

This repository contains an experimental (pre-draft) IETF draft for hybrid key exchange methods ECDH-SIKE and ECDH-BIKE. This documents has **not** been submitted to IETF.  See https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/ietf_pre_draft_sike_bike_hybrid_kex.txt.

Team
----

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

### Contributors

Contributors to this fork of OpenSSH include:

- Eric Crockett (Amazon Web Services)
- Ben Davies (University of Waterloo)
- Torben Hansen (Amazon Web Services and Royal Holloway, University of London)
- Christian Paquin (Microsoft Research)
- Douglas Stebila (University of Waterloo)

Contributors to an earlier OQS fork of OpenSSH included:

- Mira Belenkiy (Microsoft Research)
- Karl Knopf (McMaster University)

### Support

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.  

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, and Microsoft Research.  

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see the source papers for funding acknowledgments.

### OQS TODO

- Add certified PQ keys (?)
- Add PQ info to doc (man pages)
