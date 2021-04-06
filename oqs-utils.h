#ifndef OQS_UTIL_H
#define OQS_UTIL_H


// OQS-TODO: Replace these macros with the functions below
///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEY_CASE_MACROS_START
#define CASE_KEY_OQS \
	case KEY_DILITHIUM_2: \
	case KEY_DILITHIUM_3: \
	case KEY_DILITHIUM_5

#define CASE_KEY_RSA_HYBRID \
	case KEY_RSA3072_DILITHIUM_2

#define CASE_KEY_ECDSA_HYBRID \
	case KEY_ECDSA_NISTP256_DILITHIUM_2: \
	case KEY_ECDSA_NISTP384_DILITHIUM_3: \
	case KEY_ECDSA_NISTP521_DILITHIUM_5
///// OQS_TEMPLATE_FRAGMENT_DEFINE_KEY_CASE_MACROS_END

#define CASE_KEY_HYBRID \
	CASE_KEY_RSA_HYBRID: \
	CASE_KEY_ECDSA_HYBRID

static int is_oqs_rsa_hybrid(int keytype) {
    switch(keytype) {
///// OQS_TEMPLATE_FRAGMENT_LIST_RSA_HYBRIDS_START
        case KEY_RSA3072_DILITHIUM_2:
            return 1;
///// OQS_TEMPLATE_FRAGMENT_LIST_RSA_HYBRIDS_END
    }
    return 0;
}

static int is_oqs_ecdsa_hybrid(int keytype) {
    switch(keytype) {
///// OQS_TEMPLATE_FRAGMENT_LIST_ECDSA_HYBRIDS_START
        case KEY_ECDSA_NISTP256_DILITHIUM_2:
            return 1;
        case KEY_ECDSA_NISTP384_DILITHIUM_3:
            return 1;
        case KEY_ECDSA_NISTP521_DILITHIUM_5:
            return 1;
///// OQS_TEMPLATE_FRAGMENT_LIST_ECDSA_HYBRIDS_END
    }
    return 0;
}

static int is_oqs_hybrid(int keytype) {
    return is_oqs_rsa_hybrid(keytype) || is_oqs_ecdsa_hybrid(keytype);
}

#endif /* OQS_UTIL_H */
