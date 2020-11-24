/* $OpenBSD: myproposal.h,v 1.57 2018/09/12 01:34:02 djm Exp $ */

/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <openssl/opensslv.h>

/* conditional algorithm support */

#if defined(WITH_OQS) && defined(WITH_PQ_KEX)
#define PQ_OQS_KEX_METHOD(X) PQ_OQS_KEX_SUFFIX(X) ","
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_START
#ifdef HAVE_BIKE
#define KEX_PQ_METHOD_BIKE \
    PQ_OQS_KEX_METHOD("bike1-l1-cpa-sha384") \
    PQ_OQS_KEX_METHOD("bike1-l3-cpa-sha384") \
    PQ_OQS_KEX_METHOD("bike1-l1-fo-sha384") \
    PQ_OQS_KEX_METHOD("bike1-l3-fo-sha384")
#else
#define KEX_PQ_METHOD_BIKE ""
#endif /* HAVE_BIKE */
#ifdef HAVE_CLASSIC_MCELIECE
#define KEX_PQ_METHOD_CLASSIC_MCELIECE \
    PQ_OQS_KEX_METHOD("classic-mceliece-348864-sha384") \
    PQ_OQS_KEX_METHOD("classic-mceliece-348864f-sha384") \
    PQ_OQS_KEX_METHOD("classic-mceliece-460896-sha384") \
    PQ_OQS_KEX_METHOD("classic-mceliece-460896f-sha384") \
    PQ_OQS_KEX_METHOD("classic-mceliece-6688128-sha384") \
    PQ_OQS_KEX_METHOD("classic-mceliece-6688128f-sha384") \
    PQ_OQS_KEX_METHOD("classic-mceliece-6960119-sha384") \
    PQ_OQS_KEX_METHOD("classic-mceliece-6960119f-sha384") \
    PQ_OQS_KEX_METHOD("classic-mceliece-8192128-sha384") \
    PQ_OQS_KEX_METHOD("classic-mceliece-8192128f-sha384")
#else
#define KEX_PQ_METHOD_CLASSIC_MCELIECE ""
#endif /* HAVE_CLASSIC_MCELIECE */
#ifdef HAVE_FRODO
#define KEX_PQ_METHOD_FRODO \
    PQ_OQS_KEX_METHOD("frodo-640-aes-sha384") \
    PQ_OQS_KEX_METHOD("frodo-640-shake-sha384") \
    PQ_OQS_KEX_METHOD("frodo-976-aes-sha384") \
    PQ_OQS_KEX_METHOD("frodo-976-shake-sha384") \
    PQ_OQS_KEX_METHOD("frodo-1344-aes-sha384") \
    PQ_OQS_KEX_METHOD("frodo-1344-shake-sha384")
#else
#define KEX_PQ_METHOD_FRODO ""
#endif /* HAVE_FRODO */
#ifdef HAVE_KYBER
#define KEX_PQ_METHOD_KYBER \
    PQ_OQS_KEX_METHOD("kyber-512-sha384") \
    PQ_OQS_KEX_METHOD("kyber-768-sha384") \
    PQ_OQS_KEX_METHOD("kyber-1024-sha384") \
    PQ_OQS_KEX_METHOD("kyber-512-90s-sha384") \
    PQ_OQS_KEX_METHOD("kyber-768-90s-sha384") \
    PQ_OQS_KEX_METHOD("kyber-1024-90s-sha384")
#else
#define KEX_PQ_METHOD_KYBER ""
#endif /* HAVE_KYBER */
#ifdef HAVE_NTRU
#define KEX_PQ_METHOD_NTRU \
    PQ_OQS_KEX_METHOD("ntru-hps-2048-509-sha384") \
    PQ_OQS_KEX_METHOD("ntru-hps-2048-677-sha384") \
    PQ_OQS_KEX_METHOD("ntru-hrss-701-sha384") \
    PQ_OQS_KEX_METHOD("ntru-hps-4096-821-sha384")
#else
#define KEX_PQ_METHOD_NTRU ""
#endif /* HAVE_NTRU */
#ifdef HAVE_SABER
#define KEX_PQ_METHOD_SABER \
    PQ_OQS_KEX_METHOD("saber-lightsaber-sha384") \
    PQ_OQS_KEX_METHOD("saber-saber-sha384") \
    PQ_OQS_KEX_METHOD("saber-firesaber-sha384")
#else
#define KEX_PQ_METHOD_SABER ""
#endif /* HAVE_SABER */
#ifdef HAVE_SIDH
#define KEX_PQ_METHOD_SIDH \
    PQ_OQS_KEX_METHOD("sidh-p434-sha384") \
    PQ_OQS_KEX_METHOD("sidh-p503-sha384") \
    PQ_OQS_KEX_METHOD("sidh-p610-sha384") \
    PQ_OQS_KEX_METHOD("sidh-p751-sha384") \
    PQ_OQS_KEX_METHOD("sidh-p434-compressed-sha384") \
    PQ_OQS_KEX_METHOD("sidh-p503-compressed-sha384") \
    PQ_OQS_KEX_METHOD("sidh-p610-compressed-sha384") \
    PQ_OQS_KEX_METHOD("sidh-p751-compressed-sha384")
#else
#define KEX_PQ_METHOD_SIDH ""
#endif /* HAVE_SIDH */
#ifdef HAVE_SIKE
#define KEX_PQ_METHOD_SIKE \
    PQ_OQS_KEX_METHOD("sike-p434-sha384") \
    PQ_OQS_KEX_METHOD("sike-p503-sha384") \
    PQ_OQS_KEX_METHOD("sike-p610-sha384") \
    PQ_OQS_KEX_METHOD("sike-p751-sha384") \
    PQ_OQS_KEX_METHOD("-sha384") \
    PQ_OQS_KEX_METHOD("sike-p503-compressed-sha384") \
    PQ_OQS_KEX_METHOD("sike-p610-compressed-sha384") \
    PQ_OQS_KEX_METHOD("sike-p751-compressed-sha384")
#else
#define KEX_PQ_METHOD_SIKE ""
#endif /* HAVE_SIKE */
#ifdef HAVE_HQC
#define KEX_PQ_METHOD_HQC \
    PQ_OQS_KEX_METHOD("hqc-128-sha384") \
    PQ_OQS_KEX_METHOD("hqc-192-sha384") \
    PQ_OQS_KEX_METHOD("hqc-256-sha384")
#else
#define KEX_PQ_METHOD_HQC ""
#endif /* HAVE_HQC */
#ifdef HAVE_NTRU_PRIME
#define KEX_PQ_METHOD_NTRU_PRIME \
    PQ_OQS_KEX_METHOD("ntrulpr-653-sha384") \
    PQ_OQS_KEX_METHOD("ntrulpr-761-sha384") \
    PQ_OQS_KEX_METHOD("ntrulpr-857-sha384") \
    PQ_OQS_KEX_METHOD("sntrup-653-sha384") \
    PQ_OQS_KEX_METHOD("sntrup-761-sha384") \
    PQ_OQS_KEX_METHOD("sntrup-857-sha384")
#else
#define KEX_PQ_METHOD_NTRU_PRIME ""
#endif /* HAVE_NTRU_PRIME */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_END
#else /* defined(WITH_OQS) && defined(WITH_PQ_KEX) */
///// OQS_TEMPLATE_FRAGMENT_UNDEFINE_PQ_KEXS_START
#define KEX_PQ_METHOD_BIKE ""
#define KEX_PQ_METHOD_CLASSIC_MCELIECE ""
#define KEX_PQ_METHOD_FRODO ""
#define KEX_PQ_METHOD_KYBER ""
#define KEX_PQ_METHOD_NTRU ""
#define KEX_PQ_METHOD_SABER ""
#define KEX_PQ_METHOD_SIDH ""
#define KEX_PQ_METHOD_SIKE ""
#define KEX_PQ_METHOD_HQC ""
#define KEX_PQ_METHOD_NTRU_PRIME ""
///// OQS_TEMPLATE_FRAGMENT_UNDEFINE_PQ_KEXS_END
#endif /* defined(WITH_OQS) && defined(WITH_PQ_KEX) */

///// OQS_TEMPLATE_FRAGMENT_LIST_PQ_KEXS_START
#define KEX_PQ_METHODS \
    PQ_OQS_KEX_METHOD("oqsdefault-sha384") \
    KEX_PQ_METHOD_BIKE \
    KEX_PQ_METHOD_CLASSIC_MCELIECE \
    KEX_PQ_METHOD_FRODO \
    KEX_PQ_METHOD_KYBER \
    KEX_PQ_METHOD_NTRU \
    KEX_PQ_METHOD_SABER \
    KEX_PQ_METHOD_SIDH \
    KEX_PQ_METHOD_SIKE \
    KEX_PQ_METHOD_HQC \
    KEX_PQ_METHOD_NTRU_PRIME
///// OQS_TEMPLATE_FRAGMENT_LIST_PQ_KEXS_END

#ifdef OPENSSL_HAS_ECC
#if defined(WITH_OQS) && defined(WITH_HYBRID_KEX)
#define HYBRID_ECDH_OQS_METHOD(X) HYBRID_ECDH_OQS_KEX_SUFFIX(X) ","
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_START
#ifdef HAVE_BIKE
#define KEX_HYBRID_METHOD_BIKE \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-bike1-l1-cpa-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-bike1-l3-cpa-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-bike1-l1-fo-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-bike1-l3-fo-sha384")
#else
#define KEX_HYBRID_METHOD_BIKE ""
#endif /* HAVE_BIKE */
#ifdef HAVE_CLASSIC_MCELIECE
#define KEX_HYBRID_METHOD_CLASSIC_MCELIECE \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-348864-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-348864f-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-460896-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-460896f-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-6688128-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-6688128f-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-6960119-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-6960119f-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-8192128-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-classic-mceliece-8192128f-sha384")
#else
#define KEX_HYBRID_METHOD_CLASSIC_MCELIECE ""
#endif /* HAVE_CLASSIC_MCELIECE */
#ifdef HAVE_FRODO
#define KEX_HYBRID_METHOD_FRODO \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-frodo-640-aes-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-frodo-640-shake-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-frodo-976-aes-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-frodo-976-shake-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-frodo-1344-aes-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-frodo-1344-shake-sha384")
#else
#define KEX_HYBRID_METHOD_FRODO ""
#endif /* HAVE_FRODO */
#ifdef HAVE_KYBER
#define KEX_HYBRID_METHOD_KYBER \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-kyber-512-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-kyber-768-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-kyber-1024-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-kyber-512-90s-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-kyber-768-90s-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-kyber-1024-90s-sha384")
#else
#define KEX_HYBRID_METHOD_KYBER ""
#endif /* HAVE_KYBER */
#ifdef HAVE_NTRU
#define KEX_HYBRID_METHOD_NTRU \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-ntru-hps-2048-509-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-ntru-hps-2048-677-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-ntru-hrss-701-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-ntru-hps-4096-821-sha384")
#else
#define KEX_HYBRID_METHOD_NTRU ""
#endif /* HAVE_NTRU */
#ifdef HAVE_SABER
#define KEX_HYBRID_METHOD_SABER \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-saber-lightsaber-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-saber-saber-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-saber-firesaber-sha384")
#else
#define KEX_HYBRID_METHOD_SABER ""
#endif /* HAVE_SABER */
#ifdef HAVE_SIDH
#define KEX_HYBRID_METHOD_SIDH \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sidh-p434-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sidh-p503-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sidh-p610-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sidh-p751-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sidh-p434-compressed-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sidh-p503-compressed-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sidh-p610-compressed-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sidh-p751-compressed-sha384")
#else
#define KEX_HYBRID_METHOD_SIDH ""
#endif /* HAVE_SIDH */
#ifdef HAVE_SIKE
#define KEX_HYBRID_METHOD_SIKE \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sike-p434-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sike-p503-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sike-p610-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sike-p751-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384--sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sike-p503-compressed-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sike-p610-compressed-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sike-p751-compressed-sha384")
#else
#define KEX_HYBRID_METHOD_SIKE ""
#endif /* HAVE_SIKE */
#ifdef HAVE_HQC
#define KEX_HYBRID_METHOD_HQC \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-hqc-128-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-hqc-192-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-hqc-256-sha384")
#else
#define KEX_HYBRID_METHOD_HQC ""
#endif /* HAVE_HQC */
#ifdef HAVE_NTRU_PRIME
#define KEX_HYBRID_METHOD_NTRU_PRIME \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-ntrulpr-653-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-ntrulpr-761-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-ntrulpr-857-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sntrup-653-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sntrup-761-sha384") \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-sntrup-857-sha384")
#else
#define KEX_HYBRID_METHOD_NTRU_PRIME ""
#endif /* HAVE_NTRU_PRIME */
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_END
#else /* defined(WITH_OQS) && defined(WITH_HYBRID_KEX) */
///// OQS_TEMPLATE_FRAGMENT_UNDEFINE_HYBRID_KEXS_START
#define KEX_HYBRID_METHOD_BIKE ""
#define KEX_HYBRID_METHOD_CLASSIC_MCELIECE ""
#define KEX_HYBRID_METHOD_FRODO ""
#define KEX_HYBRID_METHOD_KYBER ""
#define KEX_HYBRID_METHOD_NTRU ""
#define KEX_HYBRID_METHOD_SABER ""
#define KEX_HYBRID_METHOD_SIDH ""
#define KEX_HYBRID_METHOD_SIKE ""
#define KEX_HYBRID_METHOD_HQC ""
#define KEX_HYBRID_METHOD_NTRU_PRIME ""
///// OQS_TEMPLATE_FRAGMENT_UNDEFINE_HYBRID_KEXS_END
#endif /* defined(WITH_OQS) && defined(WITH_HYBRID_KEX) */

///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_KEXS_START
#define KEX_HYBRID_METHODS \
    HYBRID_ECDH_OQS_METHOD("ecdh-nistp384-oqsdefault-sha384") \
    KEX_HYBRID_METHOD_BIKE \
    KEX_HYBRID_METHOD_CLASSIC_MCELIECE \
    KEX_HYBRID_METHOD_FRODO \
    KEX_HYBRID_METHOD_KYBER \
    KEX_HYBRID_METHOD_NTRU \
    KEX_HYBRID_METHOD_SABER \
    KEX_HYBRID_METHOD_SIDH \
    KEX_HYBRID_METHOD_SIKE \
    KEX_HYBRID_METHOD_HQC \
    KEX_HYBRID_METHOD_NTRU_PRIME
///// OQS_TEMPLATE_FRAGMENT_LIST_HYBRID_KEXS_END

#ifdef OPENSSL_HAS_NISTP521
# define KEX_ECDH_METHODS \
	"ecdh-sha2-nistp256," \
	"ecdh-sha2-nistp384," \
	"ecdh-sha2-nistp521,"
# define HOSTKEY_ECDSA_CERT_METHODS \
	"ecdsa-sha2-nistp256-cert-v01@openssh.com," \
	"ecdsa-sha2-nistp384-cert-v01@openssh.com," \
	"ecdsa-sha2-nistp521-cert-v01@openssh.com,"
# define HOSTKEY_ECDSA_METHODS \
	"ecdsa-sha2-nistp256," \
	"ecdsa-sha2-nistp384," \
	"ecdsa-sha2-nistp521,"
#else
# define KEX_ECDH_METHODS \
	"ecdh-sha2-nistp256," \
	"ecdh-sha2-nistp384,"
# define HOSTKEY_ECDSA_CERT_METHODS \
	"ecdsa-sha2-nistp256-cert-v01@openssh.com," \
	"ecdsa-sha2-nistp384-cert-v01@openssh.com,"
# define HOSTKEY_ECDSA_METHODS \
	"ecdsa-sha2-nistp256," \
	"ecdsa-sha2-nistp384,"
#endif
#else
# define KEX_ECDH_METHODS
# define HOSTKEY_ECDSA_CERT_METHODS
# define HOSTKEY_ECDSA_METHODS
#endif

#ifdef OPENSSL_HAVE_EVPGCM
# define AESGCM_CIPHER_MODES \
	",aes128-gcm@openssh.com,aes256-gcm@openssh.com"
#else
# define AESGCM_CIPHER_MODES
#endif

#ifdef HAVE_EVP_SHA256
# define KEX_SHA2_METHODS \
	"diffie-hellman-group-exchange-sha256," \
	"diffie-hellman-group16-sha512," \
	"diffie-hellman-group18-sha512,"
# define KEX_SHA2_GROUP14 \
	"diffie-hellman-group14-sha256,"
#define	SHA2_HMAC_MODES \
	"hmac-sha2-256," \
	"hmac-sha2-512,"
#else
# define KEX_SHA2_METHODS
# define KEX_SHA2_GROUP14
# define SHA2_HMAC_MODES
#endif

#ifdef WITH_OPENSSL
# ifdef HAVE_EVP_SHA256
#  define KEX_CURVE25519_METHODS \
	"curve25519-sha256," \
	"curve25519-sha256@libssh.org,"
# else
#  define KEX_CURVE25519_METHODS ""
# endif
#define KEX_COMMON_KEX \
	KEX_CURVE25519_METHODS \
	KEX_ECDH_METHODS \
	KEX_SHA2_METHODS \
	KEX_HYBRID_METHODS \
	KEX_PQ_METHODS

#define KEX_SERVER_KEX KEX_COMMON_KEX \
	KEX_SHA2_GROUP14 \
	"diffie-hellman-group14-sha1" \

#define KEX_CLIENT_KEX KEX_COMMON_KEX \
	"diffie-hellman-group-exchange-sha1," \
	KEX_SHA2_GROUP14 \
	"diffie-hellman-group14-sha1"

#define	KEX_DEFAULT_PK_ALG	\
	HOSTKEY_ECDSA_CERT_METHODS \
	"ssh-ed25519-cert-v01@openssh.com," \
	"rsa-sha2-512-cert-v01@openssh.com," \
	"rsa-sha2-256-cert-v01@openssh.com," \
	"ssh-rsa-cert-v01@openssh.com," \
	HOSTKEY_ECDSA_METHODS \
	"ssh-ed25519," \
	"rsa-sha2-512," \
	"rsa-sha2-256," \
	"ssh-rsa"

/* the actual algorithms */

#define KEX_SERVER_ENCRYPT \
	"chacha20-poly1305@openssh.com," \
	"aes128-ctr,aes192-ctr,aes256-ctr" \
	AESGCM_CIPHER_MODES

#define KEX_CLIENT_ENCRYPT KEX_SERVER_ENCRYPT

#define KEX_SERVER_MAC \
	"umac-64-etm@openssh.com," \
	"umac-128-etm@openssh.com," \
	"hmac-sha2-256-etm@openssh.com," \
	"hmac-sha2-512-etm@openssh.com," \
	"hmac-sha1-etm@openssh.com," \
	"umac-64@openssh.com," \
	"umac-128@openssh.com," \
	"hmac-sha2-256," \
	"hmac-sha2-512," \
	"hmac-sha1"

#define KEX_CLIENT_MAC KEX_SERVER_MAC

/* Not a KEX value, but here so all the algorithm defaults are together */
#define	SSH_ALLOWED_CA_SIGALGS	\
	"ecdsa-sha2-nistp256," \
	"ecdsa-sha2-nistp384," \
	"ecdsa-sha2-nistp521," \
	"ssh-ed25519," \
	"rsa-sha2-512," \
	"rsa-sha2-256," \
	"ssh-rsa"

#else /* WITH_OPENSSL */

#define KEX_SERVER_KEX		\
	"curve25519-sha256," \
	"curve25519-sha256@libssh.org"
#define	KEX_DEFAULT_PK_ALG	\
	"ssh-ed25519-cert-v01@openssh.com," \
	"ssh-ed25519"
#define	KEX_SERVER_ENCRYPT \
	"chacha20-poly1305@openssh.com," \
	"aes128-ctr,aes192-ctr,aes256-ctr"
#define	KEX_SERVER_MAC \
	"umac-64-etm@openssh.com," \
	"umac-128-etm@openssh.com," \
	"hmac-sha2-256-etm@openssh.com," \
	"hmac-sha2-512-etm@openssh.com," \
	"hmac-sha1-etm@openssh.com," \
	"umac-64@openssh.com," \
	"umac-128@openssh.com," \
	"hmac-sha2-256," \
	"hmac-sha2-512," \
	"hmac-sha1"

#define KEX_CLIENT_KEX KEX_SERVER_KEX
#define	KEX_CLIENT_ENCRYPT KEX_SERVER_ENCRYPT
#define KEX_CLIENT_MAC KEX_SERVER_MAC

#define	SSH_ALLOWED_CA_SIGALGS	"ssh-ed25519"

#endif /* WITH_OPENSSL */

#define	KEX_DEFAULT_COMP	"none,zlib@openssh.com"
#define	KEX_DEFAULT_LANG	""

#define KEX_CLIENT \
	KEX_CLIENT_KEX, \
	KEX_DEFAULT_PK_ALG, \
	KEX_CLIENT_ENCRYPT, \
	KEX_CLIENT_ENCRYPT, \
	KEX_CLIENT_MAC, \
	KEX_CLIENT_MAC, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_LANG, \
	KEX_DEFAULT_LANG

#define KEX_SERVER \
	KEX_SERVER_KEX, \
	KEX_DEFAULT_PK_ALG, \
	KEX_SERVER_ENCRYPT, \
	KEX_SERVER_ENCRYPT, \
	KEX_SERVER_MAC, \
	KEX_SERVER_MAC, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_COMP, \
	KEX_DEFAULT_LANG, \
	KEX_DEFAULT_LANG
