#ifndef OQS_UTIL_H
#define OQS_UTIL_H

/* ADD_MORE_OQS_SIG_HERE (as appropriate in the following macros) */

#define IS_RSA_HYBRID_ALG_NAME(alg) (strcmp(alg, "ssh-rsa3072-oqsdefault") == 0 || \
				     strcmp(alg, "ssh-rsa3072-qteslai") == 0 || \
				     strcmp(alg, "ssh-rsa3072-picnicl1fs") == 0 || \
				     strcmp(alg, "ssh-rsa3072-picnic2l1fs")

#define IS_RSA_HYBRID(alg) (alg == KEY_RSA3072_OQSDEFAULT || \
			    alg == KEY_RSA3072_QTESLA_I || \
			    alg == KEY_RSA3072_PICNIC_L1FS || \
			    alg == KEY_RSA3072_PICNIC2_L1FS)

#define IS_ECDSA_HYBRID(alg) (alg == KEY_P256_OQSDEFAULT || \
			      alg == KEY_P256_QTESLA_I || \
			      alg == KEY_P384_QTESLA_III_SPEED || \
			      alg == KEY_P384_QTESLA_III_SIZE || \
			      alg == KEY_P256_PICNIC_L1FS || \
			      alg == KEY_P256_PICNIC2_L1FS || \
			      alg == KEY_P384_PICNIC2_L3FS || \
			      alg == KEY_P521_PICNIC2_L5FS)

#define IS_HYBRID(alg) (IS_RSA_HYBRID(alg) || IS_ECDSA_HYBRID(alg))

#define IS_OQS_KEY_TYPE(type) ((type) == KEY_OQSDEFAULT || \
			       (type) == KEY_PICNIC_L1FS || \
			       (type) == KEY_PICNIC2_L1FS || \
			       (type) == KEY_PICNIC2_L3FS || \
			       (type) == KEY_PICNIC2_L5FS || \
			       (type) == KEY_QTESLA_I || \
			       (type) == KEY_QTESLA_III_SIZE || \
			       (type) == KEY_QTESLA_III_SPEED || \
			       IS_HYBRID(type))

#define CASE_KEY_OQS \
	case KEY_OQSDEFAULT: \
	case KEY_QTESLA_I: \
	case KEY_QTESLA_III_SPEED: \
	case KEY_QTESLA_III_SIZE: \
	case KEY_PICNIC_L1FS: \
	case KEY_PICNIC2_L1FS: \
	case KEY_PICNIC2_L3FS: \
	case KEY_PICNIC2_L5FS

#define CASE_KEY_RSA_HYBRID \
	case KEY_RSA3072_OQSDEFAULT: \
	case KEY_RSA3072_QTESLA_I: \
	case KEY_RSA3072_PICNIC_L1FS: \
	case KEY_RSA3072_PICNIC2_L1FS

#define CASE_KEY_ECDSA_HYBRID \
	case KEY_P256_OQSDEFAULT: \
	case KEY_P256_QTESLA_I: \
	case KEY_P384_QTESLA_III_SPEED: \
	case KEY_P384_QTESLA_III_SIZE: \
	case KEY_P256_PICNIC_L1FS: \
	case KEY_P256_PICNIC2_L1FS: \
	case KEY_P384_PICNIC2_L3FS: \
	case KEY_P521_PICNIC2_L5FS

#define CASE_KEY_HYBRID \
	CASE_KEY_RSA_HYBRID: \
	CASE_KEY_ECDSA_HYBRID

#endif /* OQS_UTIL_H */
