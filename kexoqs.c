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

static int kex_kem_generic_keypair(OQS_KEM *kem, struct kex *kex)
{
  struct sshbuf *buf = NULL;
  u_char *cp = NULL;
  int r;
  if ((buf = sshbuf_new()) == NULL)
    return SSH_ERR_ALLOC_FAIL;
  if ((r = sshbuf_reserve(buf, kem->length_public_key, &cp)) != 0) \
    goto out;
  kex->oqs_client_key_size = kem->length_secret_key;
  if ((kex->oqs_client_key = malloc(kex->oqs_client_key_size)) == NULL ||
      OQS_KEM_keypair(kem, cp, kex->oqs_client_key) != OQS_SUCCESS) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  kex->client_pub = buf;
  buf = NULL;
 out:
  sshbuf_free(buf);
  return r;
}

static int kex_kem_generic_enc(OQS_KEM *kem, struct kex *kex,
                               const struct sshbuf *client_blob,
                               struct sshbuf **server_blobp,
                               struct sshbuf **shared_secretp)
{
  struct sshbuf *server_blob = NULL;
  struct sshbuf *buf = NULL;
  const u_char *client_pub;
  u_char *kem_key, *ciphertext;
  int r;
  *server_blobp = NULL;
  *shared_secretp = NULL;
  if (sshbuf_len(client_blob) != kem->length_public_key) {
    r = SSH_ERR_SIGNATURE_INVALID;
    goto out;
  }
  client_pub = sshbuf_ptr(client_blob);
  if ((buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_reserve(buf, kem->length_shared_secret, &kem_key)) != 0)
    goto out;
  /* allocate space for encrypted KEM key */
  if ((server_blob = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_reserve(server_blob, kem->length_ciphertext, &ciphertext)) != 0)
    goto out;
  /* generate and encrypt KEM key with client key */
  if (OQS_KEM_encaps(kem, ciphertext, kem_key, client_pub) != OQS_SUCCESS) {
    goto out;
  }
  *server_blobp = server_blob;
  *shared_secretp = buf;
  server_blob = NULL;
  buf = NULL;
 out:
  sshbuf_free(server_blob);
  sshbuf_free(buf);
  return r;
}

static int kex_kem_generic_dec(OQS_KEM *kem,
                               struct kex *kex,
                               const struct sshbuf *server_blob,
                               struct sshbuf **shared_secretp)
{
  struct sshbuf *buf = NULL;
  u_char *kem_key = NULL;
  const u_char *ciphertext;
  int r;
  *shared_secretp = NULL;
  if (sshbuf_len(server_blob) != kem->length_ciphertext) {
    r = SSH_ERR_SIGNATURE_INVALID;
    goto out;
  }
  ciphertext = sshbuf_ptr(server_blob);
  /* #ifdef DEBUG_KEXECDH
    dump_digest("server cipher text:", ciphertext, OQS_KEM_##ALG##_length_ciphertext);
    #endif */
  /* decrypt the KEM key */
  if ((buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  if ((r = sshbuf_reserve(buf, kem->length_shared_secret, &kem_key)) != 0)
    goto out;
  if (OQS_KEM_decaps(kem, kem_key, ciphertext, kex->oqs_client_key) != OQS_SUCCESS) {
    goto out;
  }
  *shared_secretp = buf;
  buf = NULL;
 out:
  sshbuf_free(buf);
  return r;
}

///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEX_METHODS_START
/*---------------------------------------------------
 * OQS_DEFAULT METHODS
 *---------------------------------------------------
 */
int kex_kem_oqs_default_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_default);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_oqs_default_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_default);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_oqs_default_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_default);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * FRODOKEM_640_AES METHODS
 *---------------------------------------------------
 */
int kex_kem_frodokem_640_aes_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_frodokem_640_aes_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_640_aes_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * FRODOKEM_976_AES METHODS
 *---------------------------------------------------
 */
int kex_kem_frodokem_976_aes_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_frodokem_976_aes_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_976_aes_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_976_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * FRODOKEM_1344_AES METHODS
 *---------------------------------------------------
 */
int kex_kem_frodokem_1344_aes_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_frodokem_1344_aes_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_1344_aes_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_1344_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------
 * SIKE_P434 METHODS
 *---------------------------------------------------
 */
int kex_kem_sike_p434_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}
int kex_kem_sike_p434_enc(struct kex *kex,
                                  const struct sshbuf *client_blob,
                                  struct sshbuf **server_blobp,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_sike_p434_dec(struct kex *kex,
                                  const struct sshbuf *server_blob,
                                  struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_sike_p434);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_dec(kem, kex, server_blob, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEX_METHODS_END
