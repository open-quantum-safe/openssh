#ifndef OQS_UTIL_H
#define OQS_UTIL_H

///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_MACROS_START
#define IS_RSA_HYBRID_ALG_NAME(alg) ( \
				strcmp(alg, "ssh-rsa3072-oqsdefault") == 0 || \
				strcmp(alg, "ssh-rsa3072-dilithium2") == 0 || \
				strcmp(alg, "ssh-rsa3072-falcon512") == 0 || \
				strcmp(alg, "ssh-rsa3072-mqdss3148") == 0 || \
				strcmp(alg, "ssh-rsa3072-picnicl1fs") == 0 || \
				strcmp(alg, "ssh-rsa3072-qteslapi") == 0 || \
				strcmp(alg, "ssh-rsa3072-rainbowiaclassic") == 0 || \
				strcmp(alg, "ssh-rsa3072-sphincsharaka128frobust") == 0)

#define IS_RSA_HYBRID(alg) ( \
				alg == KEY_RSA3072_OQSDEFAULT || \
				alg == KEY_RSA3072_DILITHIUM_2 || \
				alg == KEY_RSA3072_FALCON_512 || \
				alg == KEY_RSA3072_MQDSS_31_48 || \
				alg == KEY_RSA3072_PICNIC_L1FS || \
				alg == KEY_RSA3072_QTESLA_P_I || \
				alg == KEY_RSA3072_RAINBOW_IA_CLASSIC || \
				alg == KEY_RSA3072_SPHINCS_HARAKA_128F_ROBUST)

#define IS_ECDSA_HYBRID(alg) ( \
				alg == KEY_P256_OQSDEFAULT || \
				alg == KEY_P256_DILITHIUM_2 || \
				alg == KEY_P256_FALCON_512 || \
				alg == KEY_P256_MQDSS_31_48 || \
				alg == KEY_P256_PICNIC_L1FS || \
				alg == KEY_P256_QTESLA_P_I || \
				alg == KEY_P256_RAINBOW_IA_CLASSIC || \
				alg == KEY_P256_SPHINCS_HARAKA_128F_ROBUST || \
				alg == KEY_P521_FALCON_1024 || \
				alg == KEY_P521_PICNIC2_L5FS)
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_MACROS_END

#define IS_HYBRID(alg) (IS_RSA_HYBRID(alg) || IS_ECDSA_HYBRID(alg))

///// OQS_TEMPLATE_FRAGMENT_ASSIGN_PQ_KT_START
#define IS_OQS_KEY_TYPE(type) ( \
				(type) == KEY_OQSDEFAULT || \
				(type) == KEY_DILITHIUM_2 || \
				(type) == KEY_FALCON_512 || \
				(type) == KEY_FALCON_1024 || \
				(type) == KEY_MQDSS_31_48 || \
				(type) == KEY_PICNIC_L1FS || \
				(type) == KEY_PICNIC2_L5FS || \
				(type) == KEY_QTESLA_P_I || \
				(type) == KEY_RAINBOW_IA_CLASSIC || \
				(type) == KEY_SPHINCS_HARAKA_128F_ROBUST || \
				IS_HYBRID(type))
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_PQ_KT_END

///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_SWITCH_CASES_START
#define CASE_KEY_OQS \
	case KEY_OQSDEFAULT: \
	case KEY_DILITHIUM_2: \
	case KEY_FALCON_512: \
	case KEY_FALCON_1024: \
	case KEY_MQDSS_31_48: \
	case KEY_PICNIC_L1FS: \
	case KEY_PICNIC2_L5FS: \
	case KEY_QTESLA_P_I: \
	case KEY_RAINBOW_IA_CLASSIC: \
	case KEY_SPHINCS_HARAKA_128F_ROBUST
///// OQS_TEMPLATE_FRAGMENT_DEFINE_PQ_SWITCH_CASES_END

///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_SWITCH_CASES_START
#define CASE_KEY_RSA_HYBRID \
	case KEY_RSA3072_OQSDEFAULT: \
	case KEY_RSA3072_DILITHIUM_2: \
	case KEY_RSA3072_FALCON_512: \
	case KEY_RSA3072_MQDSS_31_48: \
	case KEY_RSA3072_PICNIC_L1FS: \
	case KEY_RSA3072_QTESLA_P_I: \
	case KEY_RSA3072_RAINBOW_IA_CLASSIC: \
	case KEY_RSA3072_SPHINCS_HARAKA_128F_ROBUST

#define CASE_KEY_ECDSA_HYBRID \
	case KEY_P256_OQSDEFAULT: \
	case KEY_P256_DILITHIUM_2: \
	case KEY_P256_FALCON_512: \
	case KEY_P256_MQDSS_31_48: \
	case KEY_P256_PICNIC_L1FS: \
	case KEY_P256_QTESLA_P_I: \
	case KEY_P256_RAINBOW_IA_CLASSIC: \
	case KEY_P256_SPHINCS_HARAKA_128F_ROBUST: \
	case KEY_P521_FALCON_1024: \
	case KEY_P521_PICNIC2_L5FS
///// OQS_TEMPLATE_FRAGMENT_DEFINE_HYBRID_SWITCH_CASES_END

#define CASE_KEY_HYBRID \
	CASE_KEY_RSA_HYBRID: \
	CASE_KEY_ECDSA_HYBRID

#endif /* OQS_UTIL_H */
