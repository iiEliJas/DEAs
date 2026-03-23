/*
 *  AES256GCM unit tests
 *
 *   - NIST SP 800-38D dedicated test vectors for GCM
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../src/aes256gcm.h"
#include "test.h"

//////////////////////////////////////////////////////////////////////
// VECTORS
//
 
static const uint8_t TC13_KEY[32] = {0};
static const uint8_t TC13_IV[12]  = {0};
static const uint8_t TC13_TAG[16] = {
    0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
    0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b
};
static const uint8_t TC14_KEY[32] = {0};
static const uint8_t TC14_IV[12]  = {0};
static const uint8_t TC14_PT[16]  = {0};
static const uint8_t TC14_CT[16]  = {
    0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
    0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18
};
static const uint8_t TC14_TAG[16] = {
    0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
    0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19
};
 
static const uint8_t TC15_KEY[32] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};
static const uint8_t TC15_IV[12] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
    0xde, 0xca, 0xf8, 0x88
};
static const uint8_t TC15_PT[64] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
    0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
    0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
    0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55
};
static const uint8_t TC15_CT[64] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
    0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
    0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
    0xbc, 0xc9, 0xf6, 0x62, 0x89, 0x80, 0x15, 0xad
};
static const uint8_t TC15_TAG[16] = {
    0xb0, 0x94, 0xda, 0xc5, 0xd9, 0x34, 0x71, 0xbd,
    0xec, 0x1a, 0x50, 0x22, 0x70, 0xe3, 0xcc, 0x6c
};
static const uint8_t TC16_AAD[20] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
    0xab, 0xad, 0xda, 0xd2
};
static const uint8_t TC16_CT[60] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
    0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
    0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
    0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
    0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
    0xbc, 0xc9, 0xf6, 0x62
};
static const uint8_t TC16_TAG[16] = {
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
    0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b
};

//////////////////////////////////////////////////////////////////////
// KAT — Known-Answer Tests
 
static void test_gcm_tc13_empty(){
    uint8_t tag[16];
    aes256gcm_encrypt(NULL, 0, NULL, 0, TC13_KEY, TC13_IV, NULL, tag);
 
    if (memcmp(tag, TC13_TAG, 16) != 0){
        fail(__func__, "tag mismatch");
        return;
    }
    pass(__func__);
}
 
static void test_gcm_tc14_encrypt(){
    uint8_t ct[16], tag[16];
    aes256gcm_encrypt(TC14_PT, 16, NULL, 0, TC14_KEY, TC14_IV, ct, tag);
 
    if (memcmp(ct, TC14_CT, 16) != 0){
        fail(__func__, "ciphertext mismatch");
        return;
    }
    if (memcmp(tag, TC14_TAG, 16) != 0){
        fail(__func__, "tag mismatch");
        return;
    }
    pass(__func__);
}
 
static void test_gcm_tc15_encrypt(){
    uint8_t ct[64], tag[16];
    aes256gcm_encrypt(TC15_PT, 64, NULL, 0, TC15_KEY, TC15_IV, ct, tag);
 
    if (memcmp(ct, TC15_CT, 64) != 0){
        fail(__func__, "ciphertext mismatch");
        return;
    }
    if (memcmp(tag, TC15_TAG, 16) != 0){
        fail(__func__, "tag mismatch");
        return;
    }
    pass(__func__);
}
 
static void test_gcm_tc16_with_aad(){
    uint8_t ct[60], tag[16];
    // TC16 uses first 60 bytes of TC15_PT
    aes256gcm_encrypt(TC15_PT, 60, TC16_AAD, 20, TC15_KEY, TC15_IV, ct, tag);
 
    if (memcmp(ct, TC16_CT, 60) != 0){
        fail(__func__, "ciphertext mismatch");
        return;
    }
    if (memcmp(tag, TC16_TAG, 16) != 0){
        fail(__func__, "tag mismatch");
        return;
    }
    pass(__func__);
}
 
 
//////////////////////////////////////////////////////////////////////
// Roundtrip tests
 
static void test_gcm_roundtrip_no_aad(){
    static const uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    static const uint8_t iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b
    };
    static const uint8_t pt[48] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
    };
 
    uint8_t ct[48], tag[16], result[48];
    aes256gcm_encrypt(pt, 48, NULL, 0, key, iv, ct, tag);
 
    if (aes256gcm_decrypt(ct, 48, NULL, 0, key, iv, tag, result) != 0){
        fail(__func__, "decrypt returned error");
        return;
    }
    if (memcmp(result, pt, 48) != 0){
        fail(__func__, "roundtrip mismatch");
        return;
    }
    pass(__func__);
}
 
static void test_gcm_roundtrip_with_aad(){
    static const uint8_t key[32] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    static const uint8_t iv[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };
    static const uint8_t aad[13] = "entry-id:0042";
    static const uint8_t pt[32]  = {
        0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x70, 0x61,
        0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30,
        0x21, 0x40, 0x23, 0x24, 0x25, 0x5e, 0x26, 0x2a
    };
 
    uint8_t ct[32], tag[16], result[32];
    aes256gcm_encrypt(pt, 32, aad, 13, key, iv, ct, tag);
 
    if (aes256gcm_decrypt(ct, 32, aad, 13, key, iv, tag, result) != 0){
        fail(__func__, "decrypt returned error");
        return;
    }
    if (memcmp(result, pt, 32) != 0){
        fail(__func__, "roundtrip mismatch");
        return;
    }
    pass(__func__);
}
 
static void test_gcm_roundtrip_partial_block(){
    // plaintext is 25 bytes so its not a multiple of 16
    //tests partial block handling
    static const uint8_t key[32] = {0xab};
    static const uint8_t iv[12]  = {0x01, 0x02, 0x03};
    static const uint8_t pt[25]  = "this is not 16 bytesss!";
 
    uint8_t ct[25], tag[16], result[25];
    aes256gcm_encrypt(pt, 25, NULL, 0, key, iv, ct, tag);
 
    if (aes256gcm_decrypt(ct, 25, NULL, 0, key, iv, tag, result) != 0){
        fail(__func__, "decrypt returned error");
        return;
    }
    if (memcmp(result, pt, 25) != 0){
        fail(__func__, "roundtrip mismatch");
        return;
    }
    pass(__func__);
}
 
 
//////////////////////////////////////////////////////////////////////
// Authentication failure tests
// Every test here MUST return -1 from decrypt and leave output zeroed.
 
static void test_gcm_tampered_ciphertext(){
    uint8_t ct[16], tag[16], out[16];
    aes256gcm_encrypt(TC14_PT, 16, NULL, 0, TC14_KEY, TC14_IV, ct, tag);
 
    ct[0] ^= 0x01;   // one bit is changed
 
    if (aes256gcm_decrypt(ct, 16, NULL, 0, TC14_KEY, TC14_IV, tag, out) != -1){
        fail(__func__, "ciphertext should have been rejected");
        return;
    }
    uint8_t zero[16] = {0};
    if (memcmp(out, zero, 16) != 0){
        fail(__func__, "output not zeroed after failure");
        return;
    }
    pass(__func__);
}
 
static void test_gcm_tampered_tag(){
    uint8_t ct[16], tag[16], out[16];
    aes256gcm_encrypt(TC14_PT, 16, NULL, 0, TC14_KEY, TC14_IV, ct, tag);
 
    tag[7] ^= 0xFF;
 
    if (aes256gcm_decrypt(ct, 16, NULL, 0, TC14_KEY, TC14_IV, tag, out) != -1){
        fail(__func__, "tag should have been rejected");
        return;
    }
    pass(__func__);
}
 
static void test_gcm_tampered_aad(){
    static const uint8_t key[32] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    static const uint8_t iv[12]      = { 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
                                          0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
    static const uint8_t aad_enc[8]  = "entry-01";
    static const uint8_t aad_dec[8]  = "entry-02";   // different AAD on decrypt
    static const uint8_t pt[16]      = "supersecretttt!";
 
    uint8_t ct[16], tag[16], out[16];
    aes256gcm_encrypt(pt, 16, aad_enc, 8, key, iv, ct, tag);
 
    if (aes256gcm_decrypt(ct, 16, aad_dec, 8, key, iv, tag, out) != -1){
        fail(__func__, "AAD should have been rejected");
        return;
    }
    pass(__func__);
}
 
static void test_gcm_wrong_iv(){
    uint8_t ct[16], tag[16], out[16];
    aes256gcm_encrypt(TC14_PT, 16, NULL, 0, TC14_KEY, TC14_IV, ct, tag);
 
    uint8_t wrong_iv[12] = {0};
    wrong_iv[11] = 0x01;
 
    if (aes256gcm_decrypt(ct, 16, NULL, 0, TC14_KEY, wrong_iv, tag, out) != -1){
        fail(__func__, "IV should have been rejected");
        return;
    }
    pass(__func__);
}
 
static void test_gcm_wrong_key(){
    uint8_t ct[16], tag[16], out[16];
    aes256gcm_encrypt(TC14_PT, 16, NULL, 0, TC14_KEY, TC14_IV, ct, tag);
 
    uint8_t wrong_key[32] = {0};
    wrong_key[0] = 0x01;
 
    if (aes256gcm_decrypt(ct, 16, NULL, 0, wrong_key, TC14_IV, tag, out) != -1){
        fail(__func__, "key should have been rejected");
        return;
    }
    pass(__func__);
}
 
 
//////////////////////////////////////////////////////////////////////
// main
 
int main(void){
    printf("--- AES-256-GCM Tests ---\n");
 
    printf("\n--- NIST SP 800-38D Known-Answer Tests ---\n");
    test_gcm_tc13_empty();
    test_gcm_tc14_encrypt();
    test_gcm_tc15_encrypt();
    test_gcm_tc16_with_aad();
 
    printf("\n--- Roundtrip Tests ---\n");
    test_gcm_roundtrip_no_aad();
    test_gcm_roundtrip_with_aad();
    test_gcm_roundtrip_partial_block();
 
    printf("\n--- Authentication Failure Tests ---\n");
    test_gcm_tampered_ciphertext();
    test_gcm_tampered_tag();
    test_gcm_tampered_aad();
    test_gcm_wrong_iv();
    test_gcm_wrong_key();
 
    printf("\nResult: %d / %d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
