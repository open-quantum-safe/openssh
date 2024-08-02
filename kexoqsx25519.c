/*
 * Adapted from kexoqsecdh.c and kexsntrup761x25519.c for hybrid PQC algs.
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

#include "oqs/oqs.h"

#include "digest.h"
#include "kex.h"
#include "sshbuf.h"
#include "ssherr.h"

static int kex_kem_generic_with_x25519_keypair(OQS_KEM *kem, struct kex *kex)
{
  /* the client public key to send to the server. */
  struct sshbuf *buf = NULL;
  u_char *public_key = NULL;
  size_t hybrid_key_length = kem->length_public_key + CURVE25519_SIZE;
  int r;

  /* allocate space for PQC public key (x25519 will be concatenated later) */
  if ((buf = sshbuf_new()) == NULL) {
    return SSH_ERR_ALLOC_FAIL;
  }
  if ((r = sshbuf_reserve(buf, hybrid_key_length, &public_key)) != 0) {
    goto out;
  }

  /* generate the PQC key */
  kex->oqs_client_key_size = kem->length_secret_key;
  if ((kex->oqs_client_key = malloc(kex->oqs_client_key_size)) == NULL ||
      OQS_KEM_keypair(kem, public_key, kex->oqs_client_key)
      != OQS_SUCCESS) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }

  /* generate the x25519 key */
  public_key += kem->length_public_key;
  kexc25519_keygen(kex->c25519_client_key, public_key);

  /* store the values for decryption */
  kex->client_pub = buf;
  buf = NULL;
out:
  sshbuf_free(buf);
  return r;
}

static int kex_kem_generic_with_x25519_enc(OQS_KEM *kem, struct kex *kex,
                                           const struct sshbuf *client_blob,
                                           struct sshbuf **server_blobp,
                                           struct sshbuf **shared_secretp)
{
  /* the server's PQC KEM key and x25519 shared secret */
  struct sshbuf *buf = NULL;
  /* the server's PQC ciphertext and x25519 data to send to the client */
  struct sshbuf *server_blob = NULL;
  const u_char *client_pub;
  u_char *private_key, *public_key;
  u_char server_key[CURVE25519_SIZE];
  u_char hash[SSH_DIGEST_MAX_LENGTH];
  size_t needed = 0;
  int r;

  *server_blobp = NULL;
  *shared_secretp = NULL;

  /* get a pointer to the client PQC public key */
  client_pub = sshbuf_ptr(client_blob);

  /* allocate buffer for concatenation of KEM key and x25519 shared key */
  /* the buffer will be hashed and the result is the shared secret */
  if ((buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  needed = kem->length_shared_secret;
  if ((r = sshbuf_reserve(buf, needed, &private_key))
      != 0) {
    goto out;
  }

  /* allocate buffer for encrypted KEM key and x25519 value */
  if ((server_blob = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  needed = kem->length_ciphertext + CURVE25519_SIZE;
  if ((r = sshbuf_reserve(server_blob, needed,
                      &public_key)) != 0) {
    goto out;
  }

  /* generate and encrypt KEM key with client key */
  if (OQS_KEM_encaps(kem, public_key, private_key, client_pub)
      != OQS_SUCCESS) {
    goto out;
  }
  client_pub += kem->length_public_key;
  public_key += kem->length_ciphertext;

  kexc25519_keygen(server_key, public_key);
  if ((r = kexc25519_shared_key_ext(server_key, client_pub, buf, 1)) < 0) {
    goto out;
  }

  /* hash concatenation of KEM key and x25519 shared key*/
  if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash)))
      != 0) {
    goto out;
  }

  /* string-encoded hash is resulting shared secret */
  sshbuf_reset(buf);
  if ((r = sshbuf_put_string(buf, hash,
                             ssh_digest_bytes(kex->hash_alg))) != 0) {
    goto out;
  }

  *server_blobp = server_blob;
  *shared_secretp = buf;
  server_blob = NULL;
  buf = NULL;
out:
  explicit_bzero(server_key, CURVE25519_SIZE);
  explicit_bzero(hash, sizeof(hash));
  sshbuf_free(server_blob);
  sshbuf_free(buf);
  return r;
}

static int kex_kem_generic_with_x25519_dec(OQS_KEM *kem, struct kex *kex,
                                           const struct sshbuf *server_blob,
                                           struct sshbuf **shared_secretp)
{
  /* the server's PQC KEM key and x25519 shared secret */
  struct sshbuf *buf = NULL;
  u_char *private_key = NULL;
  const u_char *public_key;
  size_t needed = 0;
  /* x25519 values */
  u_char hash[SSH_DIGEST_MAX_LENGTH];
  int r;

  *shared_secretp = NULL;

  /* get a pointer to the server PQC ciphertext */
  public_key = sshbuf_ptr(server_blob);

  /* allocate buffer for concatenation of KEM key and x25519 shared key */
  /* the buffer will be hashed and the result is the shared secret */
  if ((buf = sshbuf_new()) == NULL) {
    r = SSH_ERR_ALLOC_FAIL;
    goto out;
  }
  needed = kem->length_shared_secret;
  if ((r = sshbuf_reserve(buf, needed, &private_key)) != 0) {
    goto out;
  }

  /* decapsulate the post-quantum secret */
  if (OQS_KEM_decaps(kem, private_key, public_key,
                     kex->oqs_client_key) != OQS_SUCCESS) {
    goto out;
  }
  public_key += kem->length_ciphertext;

  if ((r = kexc25519_shared_key_ext(kex->c25519_client_key, public_key,
                                    buf, 1)) < 0) {
    goto out;
  }

  /* hash concatenation of KEM key and x25519 shared key*/
  if ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0) {
    goto out;
  }
  sshbuf_reset(buf);
  if ((r = sshbuf_put_string(buf, hash,
                             ssh_digest_bytes(kex->hash_alg))) != 0) {
    goto out;
  }
  *shared_secretp = buf;
  buf = NULL;
out:
  explicit_bzero(hash, sizeof(hash));
  sshbuf_free(buf);
  return r;
}

///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEX_WITH_X25519_METHODS_START
/*---------------------------------------------------------------
 * FRODOKEM_640_AES_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_frodokem_640_aes_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_640_aes_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_640_aes_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_aes);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * FRODOKEM_640_SHAKE_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_frodokem_640_shake_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_640_shake_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_frodokem_640_shake_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_frodokem_640_shake);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * KYBER_512_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_kyber_512_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_kyber_512_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_kyber_512_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * BIKE_L1_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_bike_l1_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike_l1);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_bike_l1_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike_l1);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_bike_l1_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_bike_l1);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * CLASSIC_MCELIECE_348864_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_classic_mceliece_348864_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_348864_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_348864_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * CLASSIC_MCELIECE_348864F_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_classic_mceliece_348864f_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_348864f_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_classic_mceliece_348864f_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_classic_mceliece_348864f);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * HQC_128_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_hqc_128_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_hqc_128_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_hqc_128_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_hqc_128);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * ML_KEM_512_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_ml_kem_512_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ml_kem_512_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ml_kem_512_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_512);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * ML_KEM_768_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_ml_kem_768_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ml_kem_768_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ml_kem_768_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
/*---------------------------------------------------------------
 * NTRUPRIME_SNTRUP761_X25519 METHODS
 *---------------------------------------------------------------
 */
int kex_kem_ntruprime_sntrup761_x25519_keypair(struct kex *kex)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup761);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_keypair(kem, kex);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntruprime_sntrup761_x25519_enc(struct kex *kex,
                                   const struct sshbuf *client_blob,
                                   struct sshbuf **server_blobp,
                                   struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup761);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_enc(kem, kex, client_blob, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}

int kex_kem_ntruprime_sntrup761_x25519_dec(struct kex *kex,
                                       const struct sshbuf *server_blobp,
                                       struct sshbuf **shared_secretp)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ntruprime_sntrup761);
    if (kem == NULL) {
        return SSH_ERR_ALLOC_FAIL;
    }
    int r = kex_kem_generic_with_x25519_dec(kem, kex, server_blobp, shared_secretp);
    OQS_KEM_free(kem);
    return r;
}
///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEX_WITH_X25519_METHODS_END
