/* $OpenBSD: ssh-oqs.c,v 1.8 2020/02/26 13:40:09 jsg Exp $ */
/*
 * Adapted from ssh-ed25519.c for OQS and hybrid algs.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <limits.h>

#include "crypto_api.h"

#include <string.h>
#include <stdarg.h>

#include "log.h"
#include "sshbuf.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "ssherr.h"
#include "ssh.h"

#include "oqs/oqs.h"

#define DEFINE_OQS_SIGN_FUNCTION(ALG, ALG_OQS, PQ_KEY_TYPE, RSA_KEY_TYPE, ECDSA_KEY_TYPE) \
int ssh_##ALG##_sign(const struct sshkey *key, u_char **sigp, size_t *lenp, \
		     const u_char *data, size_t datalen, u_int compat)	\
{									\
  u_char *sig = NULL;							\
  size_t slen = 0, len;							\
  int r;								\
  struct sshbuf *b = NULL;						\
									\
  if (lenp != NULL)							\
    *lenp = 0;								\
  if (sigp != NULL)							\
    *sigp = NULL;							\
									\
  if (key == NULL ||							\
      (sshkey_type_plain(key->type) != PQ_KEY_TYPE &&			\
       sshkey_type_plain(key->type) != RSA_KEY_TYPE &&			\
       sshkey_type_plain(key->type) != ECDSA_KEY_TYPE) ||		\
      key->oqs_sk == NULL)						\
    return SSH_ERR_INVALID_ARGUMENT;					\
  slen = OQS_SIG_##ALG_OQS##_length_signature;				\
  if ((sig = malloc(slen)) == NULL)					\
    return SSH_ERR_ALLOC_FAIL;						\
  if (OQS_SIG_##ALG_OQS##_sign(sig, &slen, data, datalen, key->oqs_sk) != OQS_SUCCESS) { \
    r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */		\
    goto out;								\
  }									\
  /* encode signature */						\
  if ((b = sshbuf_new()) == NULL) {					\
    r = SSH_ERR_ALLOC_FAIL;						\
    goto out;								\
  }									\
  if ((r = sshbuf_put_cstring(b, "ssh-"#ALG)) != 0 ||			\
      (r = sshbuf_put_string(b, sig, slen)) != 0)			\
    goto out;								\
  len = sshbuf_len(b);							\
  if (sigp != NULL) {							\
    if ((*sigp = malloc(len)) == NULL) {				\
      r = SSH_ERR_ALLOC_FAIL;						\
      goto out;								\
    }									\
    memcpy(*sigp, sshbuf_ptr(b), len);					\
  }									\
  if (lenp != NULL)							\
    *lenp = len;							\
  /* success */								\
  r = 0;								\
 out:									\
  sshbuf_free(b);							\
  if (sig != NULL)							\
    freezero(sig, slen);						\
									\
  return r;								\
}

#define DEFINE_OQS_VERIFY_FUNCTION(ALG, ALG_OQS, PQ_KEY_TYPE, RSA_KEY_TYPE, ECDSA_KEY_TYPE) \
int ssh_##ALG##_verify(const struct sshkey *key,			\
		       const u_char *signature, size_t signaturelen,	\
		       const u_char *data, size_t datalen, u_int compat) \
{									\
  struct sshbuf *b = NULL;						\
  char *ktype = NULL;							\
  const u_char *sigblob;						\
  size_t slen;								\
  int r;								\
									\
  if (key == NULL ||							\
      (sshkey_type_plain(key->type) != PQ_KEY_TYPE &&			\
       sshkey_type_plain(key->type) != RSA_KEY_TYPE &&			\
       sshkey_type_plain(key->type) != ECDSA_KEY_TYPE) ||		\
      key->oqs_pk == NULL ||						\
      signature == NULL || signaturelen == 0)				\
    return SSH_ERR_INVALID_ARGUMENT;					\
									\
  if ((b = sshbuf_from(signature, signaturelen)) == NULL)		\
    return SSH_ERR_ALLOC_FAIL;						\
  if ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||			\
      (r = sshbuf_get_string_direct(b, &sigblob, &slen)) != 0)		\
    goto out;								\
  if (strcmp("ssh-"#ALG, ktype) != 0) {					\
    r = SSH_ERR_KEY_TYPE_MISMATCH;					\
    goto out;								\
  }									\
  if (sshbuf_len(b) != 0) {						\
    r = SSH_ERR_UNEXPECTED_TRAILING_DATA;				\
    goto out;								\
  }									\
  if (slen > OQS_SIG_##ALG_OQS##_length_signature) {			\
    r = SSH_ERR_INVALID_FORMAT;						\
    goto out;								\
  }									\
									\
  if (OQS_SIG_##ALG_OQS##_verify(data, datalen, sigblob, slen, key->oqs_pk) != OQS_SUCCESS) { \
    r = SSH_ERR_SIGNATURE_INVALID;					\
    goto out;								\
  }									\
									\
  /* success */								\
  r = 0;								\
 out:									\
  sshbuf_free(b);							\
  free(ktype);								\
  return r;								\
}

#define DEFINE_OQS_SIG_FUNCTION(ALG, ALG_OQS, PQ_KEY_TYPE, RSA_KEY_TYPE, ECDSA_KEY_TYPE) \
  DEFINE_OQS_SIGN_FUNCTION(  ALG, ALG_OQS, PQ_KEY_TYPE, RSA_KEY_TYPE, ECDSA_KEY_TYPE)	\
  DEFINE_OQS_VERIFY_FUNCTION(ALG, ALG_OQS, PQ_KEY_TYPE, RSA_KEY_TYPE, ECDSA_KEY_TYPE)

/* Define the functions for each supported algorithms. Note that only L1 schemes have a RSA hybrid. */
// FIXMEOQS: TEMPLATE ////////////////////////////////
#ifdef OQS_ENABLE_SIG_dilithium_2
DEFINE_OQS_SIG_FUNCTION(dilithium2, dilithium_2, KEY_DILITHIUM_2, KEY_RSA3072_DILITHIUM_2, KEY_ECDSA_NISTP256_DILITHIUM_2)
#endif
#ifdef OQS_ENABLE_SIG_dilithium_3
DEFINE_OQS_SIG_FUNCTION(dilithium3, dilithium_3, KEY_DILITHIUM_3, KEY_UNSPEC,              KEY_ECDSA_NISTP384_DILITHIUM_3)
#endif
#ifdef OQS_ENABLE_SIG_dilithium_5
DEFINE_OQS_SIG_FUNCTION(dilithium5, dilithium_5, KEY_DILITHIUM_5, KEY_UNSPEC,              KEY_ECDSA_NISTP521_DILITHIUM_5)
#endif

// FIXMEOQS: TEMPLATE ////////////////////////////////
