OQS-OpenSSH snapshot 2025-05
============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**OQS-OpenSSH** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This is the 2025-05 snapshot release of OQS-OpenSSH, released on May 23, 2025. This release is intended to be used with liboqs version 0.13.0.

What's New
----------

This is the ninth snapshot release of the OQS fork of OpenSSH.  It is based on OpenSSH 9.7 portable 1.

- Disable HQC based on [liboqs PR#2122](https://github.com/open-quantum-safe/liboqs/pull/2122)
- Update the SSH algorithm names for ML-KEM

---

Detailed changelog
------------------

* Disable HQC by @SWilson4 in https://github.com/open-quantum-safe/openssh/pull/175
* Updating the ML-KEM for finalized codepoints by @alharrison in https://github.com/open-quantum-safe/openssh/pull/176

## New Contributors

* @SWilson4 made their first contribution in https://github.com/open-quantum-safe/openssh/pull/175
* @alharrison made their first contribution in https://github.com/open-quantum-safe/openssh/pull/176

**Full Changelog**: https://github.com/open-quantum-safe/openssh/compare/OQS-OpenSSH-snapshot-2024-08...OQS-OpenSSH-snapshot-2025-05