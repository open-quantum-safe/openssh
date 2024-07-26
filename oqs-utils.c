#include "oqs-utils.h"

int oqs_utils_is_rsa_hybrid(int keytype) {
    switch(keytype) {
///// OQS_TEMPLATE_FRAGMENT_LIST_RSA_HYBRIDS_START
        case KEY_RSA3072_FALCON_512:
            return 1;
        case KEY_RSA3072_SPHINCS_SHA2_128F_SIMPLE:
            return 1;
        case KEY_RSA3072_ML_DSA_44:
            return 1;
        case KEY_RSA3072_MAYO_2:
            return 1;
///// OQS_TEMPLATE_FRAGMENT_LIST_RSA_HYBRIDS_END
    }
    return 0;
}

int oqs_utils_is_ecdsa_hybrid(int keytype) {
    switch(keytype) {
///// OQS_TEMPLATE_FRAGMENT_LIST_ECDSA_HYBRIDS_START
        case KEY_ECDSA_NISTP256_FALCON_512:
            return 1;
        case KEY_ECDSA_NISTP521_FALCON_1024:
            return 1;
        case KEY_ECDSA_NISTP256_SPHINCS_SHA2_128F_SIMPLE:
            return 1;
        case KEY_ECDSA_NISTP521_SPHINCS_SHA2_256F_SIMPLE:
            return 1;
        case KEY_ECDSA_NISTP256_ML_DSA_44:
            return 1;
        case KEY_ECDSA_NISTP384_ML_DSA_65:
            return 1;
        case KEY_ECDSA_NISTP521_ML_DSA_87:
            return 1;
        case KEY_ECDSA_NISTP256_MAYO_2:
            return 1;
        case KEY_ECDSA_NISTP384_MAYO_3:
            return 1;
        case KEY_ECDSA_NISTP521_MAYO_5:
            return 1;
///// OQS_TEMPLATE_FRAGMENT_LIST_ECDSA_HYBRIDS_END
    }
    return 0;
}

int oqs_utils_is_hybrid(int keytype) {
    return oqs_utils_is_rsa_hybrid(keytype) || oqs_utils_is_ecdsa_hybrid(keytype);
}
