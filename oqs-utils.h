#ifndef OQS_UTIL_H
#define OQS_UTIL_H

// FIXMEOQS: TEMPLATE (all file)
// FIXMEOQS: make sure all these macros are (still) in use

/* FIXMEOQS: delete me
#define IS_RSA_HYBRID_ALG_NAME(alg) ( \
				     strcmp(alg, "ssh-rsa3072-dilithium2") == 0)
*/
#define IS_RSA_HYBRID(alg) ( \
				alg == KEY_RSA3072_DILITHIUM_2)

#define IS_ECDSA_HYBRID(alg) ( \
				alg == KEY_ECDSA_NISTP256_DILITHIUM_2 || \
				alg == KEY_ECDSA_NISTP384_DILITHIUM_3 || \
				alg == KEY_ECDSA_NISTP521_DILITHIUM_4)
				
#define IS_HYBRID(alg) (IS_RSA_HYBRID(alg) || IS_ECDSA_HYBRID(alg))

/* FIXMEOQS: delete
#define IS_OQS_KEY_TYPE(type) ( \
				(type) == KEY_DILITHIUM_2 || \
				IS_HYBRID(type))
*/

// FIXMEOQS: add openssl ECC guards

// FIXMEOQS: TEMPLATE
#define CASE_KEY_OQS \
	case KEY_DILITHIUM_2: \
	case KEY_DILITHIUM_3: \
	case KEY_DILITHIUM_4	
// FIXMEOQS: TEMPLATE

// FIXMEOQS: TEMPLATE
#define CASE_KEY_RSA_HYBRID \
	case KEY_RSA3072_DILITHIUM_2

#define CASE_KEY_ECDSA_HYBRID \
	case KEY_ECDSA_NISTP256_DILITHIUM_2: \
	case KEY_ECDSA_NISTP384_DILITHIUM_3: \
	case KEY_ECDSA_NISTP521_DILITHIUM_4
// FIXMEOQS: TEMPLATE

#define CASE_KEY_HYBRID \
	CASE_KEY_RSA_HYBRID: \
	CASE_KEY_ECDSA_HYBRID

#endif /* OQS_UTIL_H */
