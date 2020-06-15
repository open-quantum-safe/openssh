/* OQS authentication methods. */

#include "includes.h"

#include <string.h>
#include <oqs/oqs.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "ssh-oqs.h"
#include "oqs-utils.h"
#if defined(WITH_PQ_AUTH) || defined(WITH_HYBRID_AUTH)

/*
 * Maps OpenSSH key types to OQS IDs
 */
const char* get_oqs_alg_name(int openssh_type)
{
	switch (openssh_type)
	{
///// OQS_TEMPLATE_FRAGMENT_OSSH_KT_TO_OQS_METH_START
		case KEY_OQSDEFAULT:
		case KEY_RSA3072_OQSDEFAULT:
		case KEY_P256_OQSDEFAULT:
			return OQS_SIG_alg_default;
		case KEY_RAINBOW_VC_CLASSIC:
		case KEY_P521_RAINBOW_VC_CLASSIC:
			return OQS_SIG_alg_rainbow_Vc_classic;
		case KEY_RAINBOW_VC_CYCLIC:
		case KEY_P521_RAINBOW_VC_CYCLIC:
			return OQS_SIG_alg_rainbow_Vc_cyclic;
		case KEY_RAINBOW_VC_CYCLIC_COMPRESSED:
		case KEY_P521_RAINBOW_VC_CYCLIC_COMPRESSED:
			return OQS_SIG_alg_rainbow_Vc_cyclic_compressed;
///// OQS_TEMPLATE_FRAGMENT_OSSH_KT_TO_OQS_METH_END
		default:
			return NULL;
	}
}

int
sshkey_oqs_generate_private_key(struct sshkey *k, int type)
{
	int ret = SSH_ERR_INTERNAL_ERROR;
	const char* oqs_alg_name = get_oqs_alg_name(type);

	/* generate PQC key */
	if ((k->oqs_sig = OQS_SIG_new(oqs_alg_name)) == NULL) {
		return ret;
	}
	if ((k->oqs_sk = malloc(k->oqs_sig->length_secret_key)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	if ((k->oqs_pk = malloc(k->oqs_sig->length_public_key)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto err;
	}
	if (OQS_SIG_keypair(k->oqs_sig, k->oqs_pk, k->oqs_sk) != OQS_SUCCESS) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto err;
	}

  return 0;

err:
	free(k->oqs_sk);
	free(k->oqs_pk);
	OQS_SIG_free(k->oqs_sig);
	return ret;
}

int
ssh_oqs_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	u_char *sig = NULL;
	size_t siglen = 0, len;
	int ret;
	struct sshbuf *b = NULL;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL ||
	    !IS_OQS_KEY_TYPE(sshkey_type_plain(key->type)) ||
	    key->oqs_sk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	siglen = key->oqs_sig->length_signature;
	if ((sig = malloc(siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (OQS_SIG_sign(key->oqs_sig, sig, &siglen, data, datalen, key->oqs_sk) != OQS_SUCCESS) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* OQS note: all the OQS algs use the same format, so we identify the signature as "ssh-oqs" */
	if ((ret = sshbuf_put_cstring(b, "ssh-oqs")) != 0 ||
	    (ret = sshbuf_put_string(b, sig, siglen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;

	/* success */
	ret = 0;
 out:
	sshbuf_free(b);
	if (sig != NULL) {
		explicit_bzero(sig, siglen);
		free(sig);
	}

	return ret;
}

int
ssh_oqs_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	const u_char *sigblob;
	u_char *m = NULL;
	size_t slen;
	unsigned long long smlen = 0;
	int ret;

	if (key == NULL ||
	    !IS_OQS_KEY_TYPE(sshkey_type_plain(key->type)) ||
	    key->oqs_pk == NULL ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((ret = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, &sigblob, &slen)) != 0)
		goto out;
	/* OQS note: all the OQS algs use the same format, so we identify the signature as "ssh-oqs" */
	if (strcmp("ssh-oqs", ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if (slen > key->oqs_sig->length_signature) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (OQS_SIG_verify(key->oqs_sig, data, datalen, sigblob, slen, key->oqs_pk) != OQS_SUCCESS) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

	/* success */
	ret = 0;
 out:
	if (m != NULL) {
		explicit_bzero(m, smlen);
		free(m);
	}
	sshbuf_free(b);
	free(ktype);
	return ret;
}


#endif /* WITH_PQ_AUTH */
