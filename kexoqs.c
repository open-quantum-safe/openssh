/* $OpenBSD: kexoqs.c,v 1.3 2019/01/21 10:40:11 djm Exp $ */
/*
 * Adapted from kexsntrup4591761x25519.c for OQS algs.
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

#include "includes.h"

#if defined(WITH_OQS)

#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"
#include "oqs/oqs.h"

#define DEFINE_OQS_KEYPAIR_FUNCTION(ALG)     \
int kex_kem_##ALG##_keypair(struct kex *kex) \
{					     \
  struct sshbuf *buf = NULL;		     \
  u_char *cp = NULL;			     \
  int r;				     \
					     \
  if ((buf = sshbuf_new()) == NULL)	     \
    return SSH_ERR_ALLOC_FAIL;						\
  if ((r = sshbuf_reserve(buf, OQS_KEM_##ALG##_length_public_key, &cp)) != 0) \
    goto out;								\
									\
  if ((kex->oqs_client_key = malloc(OQS_KEM_##ALG##_length_secret_key)) == NULL) { \
    goto out;								\
  }									\
  if (OQS_KEM_##ALG##_keypair(cp, kex->oqs_client_key) != OQS_SUCCESS) { \
    goto out;								\
  }									\
  /* #ifdef DEBUG_KEXECDH						\
  // dump_digest("client public key ALG:", cp,				\
  // OQS_KEM_##ALG##_length_public_key);				\
  #endif */								\
  kex->client_pub = buf;						\
  buf = NULL;								\
 out:									\
  sshbuf_free(buf);							\
  return r;								\
}

#define DEFINE_OQS_ENC_FUNCTION(ALG)					\
int kex_kem_##ALG##_enc(struct kex *kex, const struct sshbuf *client_blob, \
			struct sshbuf **server_blobp, struct sshbuf **shared_secretp) \
{									\
  struct sshbuf *server_blob = NULL;					\
  struct sshbuf *buf = NULL;						\
  const u_char *client_pub;						\
  u_char *kem_key, *ciphertext;						\
  u_char hash[SSH_DIGEST_MAX_LENGTH];					\
  int r;								\
									\
  *server_blobp = NULL;							\
  *shared_secretp = NULL;						\
									\
  if (sshbuf_len(client_blob) != OQS_KEM_##ALG##_length_public_key) { \
    r = SSH_ERR_SIGNATURE_INVALID;					\
    goto out;								\
  }									\
  client_pub = sshbuf_ptr(client_blob);					\
  /* #ifdef DEBUG_KEXECDH						\
     dump_digest("client public key ALG:", client_pub, OQS_KEM_##ALG##_length_public_key);			\
     #endif */								\
  /* allocate buffer for the KEM key */					\
  /* the buffer will be hashed and the result is the shared secret */	\
  /* FIXMEOQS: do I need to hash for PQC only? */			\
  if ((buf = sshbuf_new()) == NULL) {					\
    r = SSH_ERR_ALLOC_FAIL;						\
    goto out;								\
  }									\
  if ((r = sshbuf_reserve(buf, OQS_KEM_##ALG##_length_shared_secret, &kem_key)) != 0) \
    goto out;								\
  /* allocate space for encrypted KEM key */				\
  if ((server_blob = sshbuf_new()) == NULL) {				\
    r = SSH_ERR_ALLOC_FAIL;						\
    goto out;								\
  }									\
  if ((r = sshbuf_reserve(server_blob, OQS_KEM_##ALG##_length_ciphertext, &ciphertext)) != 0) \
    goto out;								\
  /* generate and encrypt KEM key with client key */			\
  if (OQS_KEM_##ALG##_encaps(ciphertext, kem_key, client_pub) != OQS_SUCCESS) { \
    goto out;								\
  }									\
  if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0) \
    goto out;								\
  /* #ifdef DEBUG_KEXECDH						\
     dump_digest("server cipher text:", ciphertext, OQS_KEM_##ALG##_length_ciphertext);	\
     dump_digest("server kem key:", kem_key, sizeof(kem_key));		\
     dump_digest("KEM key:", sshbuf_ptr(buf), sshbuf_len(buf));		\
     #endif */								\
  /* string-encoded hash is resulting shared secret */			\
  sshbuf_reset(buf);							\
  if ((r = sshbuf_put_string(buf, hash, ssh_digest_bytes(kex->hash_alg))) != 0) \
    goto out;								\
  /* #ifdef DEBUG_KEXECDH						\
     dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf)); \
     #endif */								\
  *server_blobp = server_blob;						\
  *shared_secretp = buf;						\
  server_blob = NULL;							\
  buf = NULL;								\
 out:									\
  explicit_bzero(hash, sizeof(hash));					\
  sshbuf_free(server_blob);						\
  sshbuf_free(buf);							\
  return r;								\
}

#define DEFINE_OQS_DEC_FUNCTION(ALG)					\
int kex_kem_##ALG##_dec(struct kex *kex, const struct sshbuf *server_blob, \
			struct sshbuf **shared_secretp)			\
{									\
  struct sshbuf *buf = NULL;						\
  u_char *kem_key = NULL;						\
  const u_char *ciphertext;						\
  u_char hash[SSH_DIGEST_MAX_LENGTH];					\
  int r;								\
									\
  *shared_secretp = NULL;						\
									\
  if (sshbuf_len(server_blob) != OQS_KEM_##ALG##_length_ciphertext) {	\
    r = SSH_ERR_SIGNATURE_INVALID;					\
    goto out;								\
  }									\
  ciphertext = sshbuf_ptr(server_blob);					\
  /* #ifdef DEBUG_KEXECDH						\
    dump_digest("server cipher text:", ciphertext, OQS_KEM_##ALG##_length_ciphertext); \
    #endif */								\
  /* hash KEM key */							\
  if ((buf = sshbuf_new()) == NULL) {					\
    r = SSH_ERR_ALLOC_FAIL;						\
    goto out;								\
  }									\
  if ((r = sshbuf_reserve(buf, OQS_KEM_##ALG##_length_shared_secret, &kem_key)) != 0) \
    goto out;								\
  if (OQS_KEM_##ALG##_decaps(kem_key, ciphertext, kex->oqs_client_key) != OQS_SUCCESS) { \
    goto out;								\
  }									\
  if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0) \
    goto out;								\
  /* #ifdef DEBUG_KEXECDH						\
    dump_digest("client kem key:", kem_key, sizeof(kem_key));		\
  dump_digest("KEM shared key:", sshbuf_ptr(buf), sshbuf_len(buf));	\
  #endif */								\
  sshbuf_reset(buf);							\
  if ((r = sshbuf_put_string(buf, hash, ssh_digest_bytes(kex->hash_alg))) != 0) \
    goto out;								\
  /* #ifdef DEBUG_KEXECDH						\
    dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf)); \
    #endif */								\
  *shared_secretp = buf;						\
  buf = NULL;								\
 out:									\
  explicit_bzero(hash, sizeof(hash));					\
  sshbuf_free(buf);							\
  return r;								\
}

#define DEFINE_OQS_FUNCTION(ALG)	\
  DEFINE_OQS_KEYPAIR_FUNCTION(ALG)	\
  DEFINE_OQS_ENC_FUNCTION(ALG)		\
  DEFINE_OQS_DEC_FUNCTION(ALG)

// FIXMEOQS: TEMPLATE ////////////////////////////////
#ifdef OQS_ENABLE_KEM_frodokem_640_aes
DEFINE_OQS_FUNCTION(frodokem_640_aes)
#endif
#ifdef OQS_ENABLE_KEM_sike_p434
DEFINE_OQS_FUNCTION(sike_p434)
#endif
// FIXMEOQS: TEMPLATE ////////////////////////////////

#endif /* defined(WITH_OQS) */
