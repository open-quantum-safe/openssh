/* $OpenBSD: kex.h,v 1.91 2018/07/11 18:53:29 markus Exp $ */

/*
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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
#ifndef KEX_H
#define KEX_H

#include "mac.h"

#include "kexoqs.h"
#include "kexhy.h"
#include "kexpq.h"

#ifdef WITH_LEAKMALLOC
#include "leakmalloc.h"
#endif

#ifdef WITH_OPENSSL
# ifdef OPENSSL_HAS_ECC
#  include <openssl/ec.h>
# else /* OPENSSL_HAS_ECC */
#  define EC_KEY	void
#  define EC_GROUP	void
#  define EC_POINT	void
# endif /* OPENSSL_HAS_ECC */
#else /* WITH_OPENSSL */
# define DH		void
# define BIGNUM		void
# define EC_KEY		void
# define EC_GROUP	void
# define EC_POINT	void
#endif /* WITH_OPENSSL */

#define KEX_COOKIE_LEN	16

#define	KEX_DH1				"diffie-hellman-group1-sha1"
#define	KEX_DH14_SHA1			"diffie-hellman-group14-sha1"
#define	KEX_DH14_SHA256			"diffie-hellman-group14-sha256"
#define	KEX_DH16_SHA512			"diffie-hellman-group16-sha512"
#define	KEX_DH18_SHA512			"diffie-hellman-group18-sha512"
#define	KEX_DHGEX_SHA1			"diffie-hellman-group-exchange-sha1"
#define	KEX_DHGEX_SHA256		"diffie-hellman-group-exchange-sha256"
#define	KEX_ECDH_SHA2_NISTP256		"ecdh-sha2-nistp256"
#define	KEX_ECDH_SHA2_NISTP384		"ecdh-sha2-nistp384"
#define	KEX_ECDH_SHA2_NISTP521		"ecdh-sha2-nistp521"
#define	KEX_CURVE25519_SHA256		"curve25519-sha256"
#define	KEX_CURVE25519_SHA256_OLD	"curve25519-sha256@libssh.org"

#if defined(WITH_OQS) && defined(WITH_PQ_KEX)

#define KEX_OQSDEFAULT_SHA384 PQ_OQS_KEX_SUFFIX("oqsdefault-sha384")
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_START
#define KEX_BIKE1_L1_CPA_SHA384 PQ_OQS_KEX_SUFFIX("bike1-l1-cpa-sha384")
#define KEX_BIKE1_L3_CPA_SHA384 PQ_OQS_KEX_SUFFIX("bike1-l3-cpa-sha384")
#define KEX_BIKE1_L1_FO_SHA384 PQ_OQS_KEX_SUFFIX("bike1-l1-fo-sha384")
#define KEX_BIKE1_L3_FO_SHA384 PQ_OQS_KEX_SUFFIX("bike1-l3-fo-sha384")
#define KEX_FRODO_640_AES_SHA384 PQ_OQS_KEX_SUFFIX("frodo-640-aes-sha384")
#define KEX_FRODO_640_SHAKE_SHA384 PQ_OQS_KEX_SUFFIX("frodo-640-shake-sha384")
#define KEX_FRODO_976_AES_SHA384 PQ_OQS_KEX_SUFFIX("frodo-976-aes-sha384")
#define KEX_FRODO_976_SHAKE_SHA384 PQ_OQS_KEX_SUFFIX("frodo-976-shake-sha384")
#define KEX_FRODO_1344_AES_SHA384 PQ_OQS_KEX_SUFFIX("frodo-1344-aes-sha384")
#define KEX_FRODO_1344_SHAKE_SHA384 PQ_OQS_KEX_SUFFIX("frodo-1344-shake-sha384")
#define KEX_KYBER_512_SHA384 PQ_OQS_KEX_SUFFIX("kyber-512-sha384")
#define KEX_KYBER_768_SHA384 PQ_OQS_KEX_SUFFIX("kyber-768-sha384")
#define KEX_KYBER_1024_SHA384 PQ_OQS_KEX_SUFFIX("kyber-1024-sha384")
#define KEX_KYBER_512_90S_SHA384 PQ_OQS_KEX_SUFFIX("kyber-512-90s-sha384")
#define KEX_KYBER_768_90S_SHA384 PQ_OQS_KEX_SUFFIX("kyber-768-90s-sha384")
#define KEX_KYBER_1024_90S_SHA384 PQ_OQS_KEX_SUFFIX("kyber-1024-90s-sha384")
#define KEX_NEWHOPE_512_SHA384 PQ_OQS_KEX_SUFFIX("newhope-512-sha384")
#define KEX_NEWHOPE_1024_SHA384 PQ_OQS_KEX_SUFFIX("newhope-1024-sha384")
#define KEX_NTRU_HPS_2048_509_SHA384 PQ_OQS_KEX_SUFFIX("ntru-hps-2048-509-sha384")
#define KEX_NTRU_HPS_2048_677_SHA384 PQ_OQS_KEX_SUFFIX("ntru-hps-2048-677-sha384")
#define KEX_NTRU_HRSS_701_SHA384 PQ_OQS_KEX_SUFFIX("ntru-hrss-701-sha384")
#define KEX_NTRU_HPS_4096_821_SHA384 PQ_OQS_KEX_SUFFIX("ntru-hps-4096-821-sha384")
#define KEX_SABER_LIGHTSABER_SHA384 PQ_OQS_KEX_SUFFIX("saber-lightsaber-sha384")
#define KEX_SABER_SABER_SHA384 PQ_OQS_KEX_SUFFIX("saber-saber-sha384")
#define KEX_SABER_FIRESABER_SHA384 PQ_OQS_KEX_SUFFIX("saber-firesaber-sha384")
#define KEX_SIDH_p434_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p434-sha384")
#define KEX_SIDH_p503_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p503-sha384")
#define KEX_SIDH_p610_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p610-sha384")
#define KEX_SIDH_p751_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p751-sha384")
#define KEX_SIDH_p434_compressed_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p434-compressed-sha384")
#define KEX_SIDH_p503_compressed_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p503-compressed-sha384")
#define KEX_SIDH_p610_compressed_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p610-compressed-sha384")
#define KEX_SIDH_p751_compressed_SHA384 PQ_OQS_KEX_SUFFIX("sidh-p751-compressed-sha384")
#define KEX_SIKE_p434_SHA384 PQ_OQS_KEX_SUFFIX("sike-p434-sha384")
#define KEX_SIKE_p503_SHA384 PQ_OQS_KEX_SUFFIX("sike-p503-sha384")
#define KEX_SIKE_p610_SHA384 PQ_OQS_KEX_SUFFIX("sike-p610-sha384")
#define KEX_SIKE_p751_SHA384 PQ_OQS_KEX_SUFFIX("sike-p751-sha384")
#define KEX_SIKE_p434_compressed_SHA384 PQ_OQS_KEX_SUFFIX("sike-p434-compressed-sha384")
#define KEX_SIKE_p503_compressed_SHA384 PQ_OQS_KEX_SUFFIX("sike-p503-compressed-sha384")
#define KEX_SIKE_p610_compressed_SHA384 PQ_OQS_KEX_SUFFIX("sike-p610-compressed-sha384")
#define KEX_SIKE_p751_compressed_SHA384 PQ_OQS_KEX_SUFFIX("sike-p751-compressed-sha384")
#define KEX_BABYBEAR_SHA384 PQ_OQS_KEX_SUFFIX("babybear-sha384")
#define KEX_BABYBEAR_EPHEM_SHA384 PQ_OQS_KEX_SUFFIX("babybear-ephem-sha384")
#define KEX_MAMABEAR_SHA384 PQ_OQS_KEX_SUFFIX("mamabear-sha384")
#define KEX_MAMABEAR_EPHEM_SHA384 PQ_OQS_KEX_SUFFIX("mamabear-ephem-sha384")
#define KEX_PAPABEAR_SHA384 PQ_OQS_KEX_SUFFIX("papabear-sha384")
#define KEX_PAPABEAR_EPHEM_SHA384 PQ_OQS_KEX_SUFFIX("papabear-ephem-sha384")
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_KEXS_END

#endif /* defined(WITH_OQS) && defined(WITH_PQ_KEX) */

#if defined(WITH_OQS) && defined(WITH_HYBRID_KEX)

#define KEX_ECDH_NISTP384_OQSDEFAULT_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-oqsdefault-sha384")
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_START
#define KEX_ECDH_NISTP384_BIKE1_L1_CPA_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l1-cpa-sha384")
#define KEX_ECDH_NISTP384_BIKE1_L3_CPA_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l3-cpa-sha384")
#define KEX_ECDH_NISTP384_BIKE1_L1_FO_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l1-fo-sha384")
#define KEX_ECDH_NISTP384_BIKE1_L3_FO_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-l3-fo-sha384")
#define KEX_ECDH_NISTP384_FRODO_640_AES_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-640-aes-sha384")
#define KEX_ECDH_NISTP384_FRODO_640_SHAKE_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-640-shake-sha384")
#define KEX_ECDH_NISTP384_FRODO_976_AES_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-976-aes-sha384")
#define KEX_ECDH_NISTP384_FRODO_976_SHAKE_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-976-shake-sha384")
#define KEX_ECDH_NISTP384_FRODO_1344_AES_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-1344-aes-sha384")
#define KEX_ECDH_NISTP384_FRODO_1344_SHAKE_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-1344-shake-sha384")
#define KEX_ECDH_NISTP384_KYBER_512_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-512-sha384")
#define KEX_ECDH_NISTP384_KYBER_768_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-768-sha384")
#define KEX_ECDH_NISTP384_KYBER_1024_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-1024-sha384")
#define KEX_ECDH_NISTP384_KYBER_512_90S_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-512-90s-sha384")
#define KEX_ECDH_NISTP384_KYBER_768_90S_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-768-90s-sha384")
#define KEX_ECDH_NISTP384_KYBER_1024_90S_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-kyber-1024-90s-sha384")
#define KEX_ECDH_NISTP384_NEWHOPE_512_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-newhope-512-sha384")
#define KEX_ECDH_NISTP384_NEWHOPE_1024_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-newhope-1024-sha384")
#define KEX_ECDH_NISTP384_NTRU_HPS_2048_509_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hps-2048-509-sha384")
#define KEX_ECDH_NISTP384_NTRU_HPS_2048_677_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hps-2048-677-sha384")
#define KEX_ECDH_NISTP384_NTRU_HRSS_701_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hrss-701-sha384")
#define KEX_ECDH_NISTP384_NTRU_HPS_4096_821_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-hps-4096-821-sha384")
#define KEX_ECDH_NISTP384_SABER_LIGHTSABER_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-saber-lightsaber-sha384")
#define KEX_ECDH_NISTP384_SABER_SABER_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-saber-saber-sha384")
#define KEX_ECDH_NISTP384_SABER_FIRESABER_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-saber-firesaber-sha384")
#define KEX_ECDH_NISTP384_SIDH_p434_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p434-sha384")
#define KEX_ECDH_NISTP384_SIDH_p503_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p503-sha384")
#define KEX_ECDH_NISTP384_SIDH_p610_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p610-sha384")
#define KEX_ECDH_NISTP384_SIDH_p751_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p751-sha384")
#define KEX_ECDH_NISTP384_SIDH_p434_compressed_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p434-compressed-sha384")
#define KEX_ECDH_NISTP384_SIDH_p503_compressed_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p503-compressed-sha384")
#define KEX_ECDH_NISTP384_SIDH_p610_compressed_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p610-compressed-sha384")
#define KEX_ECDH_NISTP384_SIDH_p751_compressed_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-p751-compressed-sha384")
#define KEX_ECDH_NISTP384_SIKE_p434_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p434-sha384")
#define KEX_ECDH_NISTP384_SIKE_p503_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p503-sha384")
#define KEX_ECDH_NISTP384_SIKE_p610_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p610-sha384")
#define KEX_ECDH_NISTP384_SIKE_p751_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p751-sha384")
#define KEX_ECDH_NISTP384_SIKE_p434_compressed_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p434-compressed-sha384")
#define KEX_ECDH_NISTP384_SIKE_p503_compressed_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p503-compressed-sha384")
#define KEX_ECDH_NISTP384_SIKE_p610_compressed_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p610-compressed-sha384")
#define KEX_ECDH_NISTP384_SIKE_p751_compressed_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-p751-compressed-sha384")
#define KEX_ECDH_NISTP384_BABYBEAR_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-babybear-sha384")
#define KEX_ECDH_NISTP384_BABYBEAR_EPHEM_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-babybear-ephem-sha384")
#define KEX_ECDH_NISTP384_MAMABEAR_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-mamabear-sha384")
#define KEX_ECDH_NISTP384_MAMABEAR_EPHEM_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-mamabear-ephem-sha384")
#define KEX_ECDH_NISTP384_PAPABEAR_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-papabear-sha384")
#define KEX_ECDH_NISTP384_PAPABEAR_EPHEM_SHA384 HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-papabear-ephem-sha384")
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_KEXS_END

#endif /* defined(WITH_OQS) && defined(WITH_HYBRID_KEX) */

#define COMP_NONE	0
/* pre-auth compression (COMP_ZLIB) is only supported in the client */
#define COMP_ZLIB	1
#define COMP_DELAYED	2

#define CURVE25519_SIZE 32

enum kex_init_proposals {
	PROPOSAL_KEX_ALGS,
	PROPOSAL_SERVER_HOST_KEY_ALGS,
	PROPOSAL_ENC_ALGS_CTOS,
	PROPOSAL_ENC_ALGS_STOC,
	PROPOSAL_MAC_ALGS_CTOS,
	PROPOSAL_MAC_ALGS_STOC,
	PROPOSAL_COMP_ALGS_CTOS,
	PROPOSAL_COMP_ALGS_STOC,
	PROPOSAL_LANG_CTOS,
	PROPOSAL_LANG_STOC,
	PROPOSAL_MAX
};

enum kex_modes {
	MODE_IN,
	MODE_OUT,
	MODE_MAX
};

enum kex_exchange {
	KEX_DH_GRP1_SHA1,
	KEX_DH_GRP14_SHA1,
	KEX_DH_GRP14_SHA256,
	KEX_DH_GRP16_SHA512,
	KEX_DH_GRP18_SHA512,
	KEX_DH_GEX_SHA1,
	KEX_DH_GEX_SHA256,
	KEX_ECDH_SHA2,
	KEX_C25519_SHA256,
	KEX_HY_ECDH_OQS,
	KEX_PQ_OQS,
	KEX_MAX
};

#define KEX_INIT_SENT	0x0001

struct sshenc {
	char	*name;
	const struct sshcipher *cipher;
	int	enabled;
	u_int	key_len;
	u_int	iv_len;
	u_int	block_size;
	u_char	*key;
	u_char	*iv;
};
struct sshcomp {
	u_int	type;
	int	enabled;
	char	*name;
};
struct newkeys {
	struct sshenc	enc;
	struct sshmac	mac;
	struct sshcomp  comp;
};

struct ssh;

struct kex {
	u_char	*session_id;
	size_t	session_id_len;
	struct newkeys	*newkeys[MODE_MAX];
	u_int	we_need;
	u_int	dh_need;
	int	server;
	char	*name;
	char	*hostkey_alg;
	int	hostkey_type;
	int	hostkey_nid;
	u_int	kex_type;
	char	*server_sig_algs;
	int	ext_info_c;
	struct sshbuf *my;
	struct sshbuf *peer;
	sig_atomic_t done;
	u_int	flags;
	int	hash_alg;
	int	ec_nid;
	char	*client_version_string;
	char	*server_version_string;
	char	*failed_choice;
	int	(*verify_host_key)(struct sshkey *, struct ssh *);
	struct sshkey *(*load_host_public_key)(int, int, struct ssh *);
	struct sshkey *(*load_host_private_key)(int, int, struct ssh *);
	int	(*host_key_index)(struct sshkey *, int, struct ssh *);
	int	(*sign)(struct sshkey *, struct sshkey *, u_char **, size_t *,
	    const u_char *, size_t, const char *, u_int);
	int	(*kex[KEX_MAX])(struct ssh *);
	/* kex specific state */
	DH	*dh;			/* DH */
	u_int	min, max, nbits;	/* GEX */
	EC_KEY	*ec_client_key;		/* ECDH */
	const EC_GROUP *ec_group;	/* ECDH */
	u_char c25519_client_key[CURVE25519_SIZE]; /* 25519 */
	u_char c25519_client_pubkey[CURVE25519_SIZE]; /* 25519 */
#ifdef WITH_HYBRID_KEX
	HYBRID_KEX_CTX *hybrid_kex_ctx; /* Hybrid key exchange context */
#endif /* WITH_HYBRID_KEX */
#ifdef WITH_PQ_KEX
	PQ_KEX_CTX *pq_kex_ctx;; /* PQ-only key exchange context */
#endif /* WITH_PQ_KEX */
};

int	 kex_names_valid(const char *);
char	*kex_alg_list(char);
char	*kex_names_cat(const char *, const char *);
int	 kex_assemble_names(char **, const char *, const char *);

int	 kex_new(struct ssh *, char *[PROPOSAL_MAX], struct kex **);
int	 kex_setup(struct ssh *, char *[PROPOSAL_MAX]);
void	 kex_free_newkeys(struct newkeys *);
void	 kex_free(struct kex *);

int	 kex_buf2prop(struct sshbuf *, int *, char ***);
int	 kex_prop2buf(struct sshbuf *, char *proposal[PROPOSAL_MAX]);
void	 kex_prop_free(char **);

int	 kex_send_kexinit(struct ssh *);
int	 kex_input_kexinit(int, u_int32_t, struct ssh *);
int	 kex_input_ext_info(int, u_int32_t, struct ssh *);
int	 kex_derive_keys(struct ssh *, u_char *, u_int, const struct sshbuf *);
int	 kex_derive_keys_bn(struct ssh *, u_char *, u_int, const BIGNUM *);
int	 kex_send_newkeys(struct ssh *);
int	 kex_start_rekex(struct ssh *);

int	 kexdh_client(struct ssh *);
int	 kexdh_server(struct ssh *);
int	 kexgex_client(struct ssh *);
int	 kexgex_server(struct ssh *);
int	 kexecdh_client(struct ssh *);
int	 kexecdh_server(struct ssh *);
int	 kexc25519_client(struct ssh *);
int	 kexc25519_server(struct ssh *);

int	 kex_dh_hash(int, const char *, const char *,
    const u_char *, size_t, const u_char *, size_t, const u_char *, size_t,
    const BIGNUM *, const BIGNUM *, const BIGNUM *, u_char *, size_t *);

int	 kexgex_hash(int, const char *, const char *,
    const u_char *, size_t, const u_char *, size_t, const u_char *, size_t,
    int, int, int,
    const BIGNUM *, const BIGNUM *, const BIGNUM *,
    const BIGNUM *, const BIGNUM *,
    u_char *, size_t *);

int kex_ecdh_hash(int, const EC_GROUP *, const char *, const char *,
    const u_char *, size_t, const u_char *, size_t, const u_char *, size_t,
    const EC_POINT *, const EC_POINT *, const BIGNUM *, u_char *, size_t *);

int	 kex_c25519_hash(int, const char *, const char *,
    const u_char *, size_t, const u_char *, size_t,
    const u_char *, size_t, const u_char *, const u_char *,
    const u_char *, size_t, u_char *, size_t *);

void	kexc25519_keygen(u_char key[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));
int	kexc25519_shared_key(const u_char key[CURVE25519_SIZE],
    const u_char pub[CURVE25519_SIZE], struct sshbuf *out)
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)));

#if defined(DEBUG_KEX) || defined(DEBUG_KEXDH) || defined(DEBUG_KEXECDH)
void	dump_digest(char *, u_char *, int);
#endif

#if !defined(WITH_OPENSSL) || !defined(OPENSSL_HAS_ECC)
# undef EC_KEY
# undef EC_GROUP
# undef EC_POINT
#endif

#endif
