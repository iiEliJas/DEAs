/**
 * DES unit tests
 *
 *   - NIST FIPS 46-3 known-answer test vector for ECB
 *   - Encrypt -> decrypt roundtrip for ECB, CBC, and CTR modes
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../src/des.h"
#include "../utils/utils.h"
#include "test.h"


//////////////////////////////////////////////////////////////////////
// VECTORS
// KAT ... Known-Answer Test
// PT ... Plaintext
// CT ... Ciphertext

// FIPS 46-3 Appendix B test vector
static const uint64_t KAT_KEY = 0x133457799BBCDFF1ULL;
static const uint64_t KAT_PT  = 0x0123456789ABCDEFULL;
static const uint64_t KAT_CT  = 0x85E813540F0AB405ULL;

//////////////////////////////////////////////////////////////////////
// ECB KAT

static void test_des_ecb_kat(void){
    uint64_t ct = 0, pt = 0;

    des_ecb_encrypt(&KAT_PT, &ct, 1, KAT_KEY);
    if (ct != KAT_CT){
        fail(__func__, "DES ECB encryption KAT failed");
        return;
    }

    des_ecb_decrypt(&ct, &pt, 1, KAT_KEY);
    if (pt != KAT_PT){
        fail(__func__, "DES ECB decryption KAT failed");
        return;
    }
    pass(__func__);
}

//////////////////////////////////////////////////////////////////////
// ECB multi-block roundtrip

static void test_des_ecb_multiblock(void){
    const uint64_t pt[4] = {
        0x0123456789ABCDEFULL,
        0xFEDCBA9876543210ULL,
        0xAABBCCDDEEFF0011ULL,
        0x1122334455667788ULL
    };
    uint64_t ct[4] = {0};
    uint64_t result[4] = {0};

    des_ecb_encrypt(pt, ct, 4, KAT_KEY);
    des_ecb_decrypt(ct, result, 4, KAT_KEY);

    if (memcmp(result, pt, sizeof(pt)) != 0){
        fail(__func__, "DES ECB multi-block roundtrip failed");
        return;
    }
    pass(__func__);
}

//////////////////////////////////////////////////////////////////////
// CBC roundtrip

static void test_des_cbc_roundtrip(void){
    const uint64_t iv = 0xDEADBEEFCAFEBABEULL;
    const uint64_t pt[3] = {
        0x0123456789ABCDEFULL,
        0xFEDCBA9876543210ULL,
        0xAABBCCDDEEFF0011ULL
    };
    uint64_t ct[3] = {0};
    uint64_t result[3] = {0};

    des_cbc_encrypt(pt, ct,     3, KAT_KEY, iv);
    des_cbc_decrypt(ct, result, 3, KAT_KEY, iv);

    if (memcmp(result, pt, sizeof(pt)) != 0){
        fail(__func__, "DES CBC roundtrip failed");
        return;
    }
    pass(__func__);
}

//////////////////////////////////////////////////////////////////////
// CBC IV sensitivity

static void test_des_cbc_iv_sensitivity(void){
    const uint64_t iv_a = 0xDEADBEEFCAFEBABEULL;
    const uint64_t iv_b = 0xDEADBEEFCAFEBABFULL;  // 1 bit different
    const uint64_t pt[2] = {
        0x0123456789ABCDEFULL,
        0xFEDCBA9876543210ULL
    };
    uint64_t ct_a[2] = {0};
    uint64_t ct_b[2] = {0};

    des_cbc_encrypt(pt, ct_a, 2, KAT_KEY, iv_a);
    des_cbc_encrypt(pt, ct_b, 2, KAT_KEY, iv_b);

    // Different IVs must produce different ciphertexts
    if (ct_a[0] == ct_b[0] && ct_a[1] == ct_b[1]){
        fail(__func__, "DES CBC IV sensitivity: different IVs produced identical ciphertext");
        return;
    }
    pass(__func__);
}

//////////////////////////////////////////////////////////////////////
// CTR roundtrip

static void test_des_ctr_roundtrip(void){
    const uint64_t nonce = 0xFEDCBA9876543210ULL;
    const uint64_t pt[3] = {
        0x0123456789ABCDEFULL,
        0xFEDCBA9876543210ULL,
        0xAABBCCDDEEFF0011ULL
    };
    uint64_t ct[3]     = {0};
    uint64_t result[3] = {0};

    des_ctr_encrypt(pt, ct, 3, KAT_KEY, nonce);
    des_ctr_decrypt(ct, result, 3, KAT_KEY, nonce);

    if (memcmp(result, pt, sizeof(pt)) != 0){
        fail(__func__, "DES CTR roundtrip mismatch");
        return;
    }
    pass(__func__);
}


//////////////////////////////////////////////////////////////////////
// mode isolation

static void test_des_modes_produce_different_ciphertexts(void){
    /*
     * ECB, CBC, and CTR must produce different ciphertexts for the same
     * plaintext (for optimal IV/nonce).
     */
    const uint64_t iv    = 0xDEADBEEFCAFEBABEULL;
    const uint64_t nonce = 0xFEDCBA9876543210ULL;
    const uint64_t pt[2] = {
        0x0123456789ABCDEFULL,
        0xFEDCBA9876543210ULL
    };
    uint64_t ecb[2] = {0};
    uint64_t cbc[2] = {0};
    uint64_t ctr[2] = {0};

    des_ecb_encrypt(pt, ecb, 2, KAT_KEY);
    des_cbc_encrypt(pt, cbc, 2, KAT_KEY, iv);
    des_ctr_encrypt(pt, ctr, 2, KAT_KEY, nonce);

    if (memcmp(ecb, cbc, sizeof(ecb)) == 0 || memcmp(ecb, ctr, sizeof(ecb)) == 0 || memcmp(cbc, ctr, sizeof(cbc)) == 0){
        fail(__func__, "Two or more modes produced identical ciphertexts");
        return;
    }
    pass(__func__);
}

//////////////////////////////////////////////////////////////////////
// MAIN

int main(void){
    printf("--- DES Tests ---\n");

    printf("\n--- ECB Known-Answer Test (FIPS 46-3) ---\n");
    test_des_ecb_kat();

    printf("\n--- ECB Multi-block roundtrip ---\n");
    test_des_ecb_multiblock();

    printf("\n--- CBC Roundtrip & IV sensitivity ---\n");
    test_des_cbc_roundtrip();
    test_des_cbc_iv_sensitivity();

    printf("\n--- CTR Roundtrip ---\n");
    test_des_ctr_roundtrip();

    printf("\n--- Mode isolation ---\n");
    test_des_modes_produce_different_ciphertexts();

    printf("\nResult: %d / %d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}