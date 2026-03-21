/*
 *  AES-NI unit tests
 *
 *   - NIST FIPS 197 known-answer test vectors for ECB (AES-128, AES-256)
 *   - Encrypt -> decrypt roundtrip for ECB, CBC, and CTR modes
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../src/aesni_core.h"
#include "../src/aes_core.h"
#include "../utils/utils.h"


static int tests_run    = 0;
static int tests_passed = 0;

static void pass(const char *name) {
    tests_passed++;
    tests_run++;
    printf("  [PASS] %s\n", name);
}

static void fail(const char *name, const char *msg) {
    tests_run++;
    printf("  [FAIL] %s — %s\n", name, msg);
}

//////////////////////////////////////////////////////////////////////
// VECTORS
// KAT ... Known-Answer Test
// PT ... Plaintext
// CT ... Ciphertext

// FIPS 197 Appendix B - AES-128
static const uint8_t KAT_128_KEY[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
static const uint8_t KAT_128_PT[16] = {
    0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
    0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
};
static const uint8_t KAT_128_CT[16] = {
    0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
    0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
};

// FIPS 197 Appendix B - AES-256
static const uint8_t KAT_256_KEY[32] = {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
static const uint8_t KAT_256_PT[16] = {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
static const uint8_t KAT_256_CT[16] = {
    0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
    0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
};

//////////////////////////////////////////////////////////////////////
// ECB KAT

static void test_aesni128_ecb_kat()
{
    AESNI_Ctx ctx;
    uint8_t ct[16], pt[16];

    aesni_init(KAT_128_KEY, AESNI_128, &ctx);
    aesni_encrypt(KAT_128_PT, ct, &ctx);
    aesni_decrypt(ct, pt, &ctx);

    if (memcmp(ct, KAT_128_CT, 16) != 0) {
        printAES_state("expected", KAT_128_CT, 1);
        printAES_state("got",      ct,         1);
        fail(__func__, "AES-NI-128 ECB encryption fail");
        return;
    }
    if (memcmp(pt, KAT_128_PT, 16) != 0) {
        fail(__func__, "AES-NI-128 ECB decryption fail");
        return;
    }
    pass(__func__);
}

static void test_aesni256_ecb_kat()
{
    AESNI_Ctx ctx;
    uint8_t ct[16], pt[16];

    aesni_init(KAT_256_KEY, AESNI_256, &ctx);
    aesni_encrypt(KAT_256_PT, ct, &ctx);
    aesni_decrypt(ct, pt, &ctx);

    if (memcmp(ct, KAT_256_CT, 16) != 0) {
        printAES_state("expected", KAT_256_CT, 1);
        printAES_state("got",      ct,         1);
        fail(__func__, "AES-NI-256 ECB encryption fail");
        return;
    }
    if (memcmp(pt, KAT_256_PT, 16) != 0) {
        fail(__func__, "AES-NI-256 ECB decryption fail");
        return;
    }
    pass(__func__);
}

//////////////////////////////////////////////////////////////////////
// CBC roundtrip

static void test_aesni_cbc_roundtrip()
{
    AESNI_Ctx ctx;
    aesni_init(KAT_256_KEY, AESNI_256, &ctx);

    const uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t pt[48] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
    };
    uint8_t ct[48], result[48];

    aesni_cbc_encrypt(pt, ct,     3, &ctx, iv);
    aesni_cbc_decrypt(ct, result, 3, &ctx, iv);

    if (memcmp(result, pt, 48) != 0) {
        fail(__func__, "AES-NI-256 CBC roundtrip fail");
        return;
    }
    pass(__func__);
}

//////////////////////////////////////////////////////////////////////
// CTR roundtrip

static void test_aesni_ctr_roundtrip()
{
    AESNI_Ctx ctx;
    aesni_init(KAT_128_KEY, AESNI_128, &ctx);

    const uint8_t nonce[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    const uint8_t pt[32] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
    };
    uint8_t ct[32], result[32];

    aesni_ctr_encrypt(pt, ct,     2, &ctx, nonce);
    aesni_ctr_decrypt(ct, result, 2, &ctx, nonce);

    if (memcmp(result, pt, 32) != 0) {
        fail(__func__, "AES-NI-128 CTR roundtrip fail");
        return;
    }
    pass(__func__);
}


//////////////////////////////////////////////////////////////////////
// main

int main(void)
{
    printf("--- AES-NI Tests ---\n");

    printf("\n--- ECB Known-Answer Tests (FIPS 197) ---\n");
    test_aesni128_ecb_kat();
    test_aesni256_ecb_kat();

    printf("\n--- CBC Roundtrip ---\n");
    test_aesni_cbc_roundtrip();

    printf("\n--- CTR Roundtrip ---\n");
    test_aesni_ctr_roundtrip();

    printf("\nResult: %d / %d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}



