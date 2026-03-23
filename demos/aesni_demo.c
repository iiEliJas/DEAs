#include <stdio.h>
#include "aesni.h"
#include "../utils/utils.h"



int main(void){
    //////////////////////////////
    /// key and message
    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4      // 256 bit
    };
    // -- IV for CBC
    uint8_t iv[16] = {
         0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
         0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe
    };
    // Nonce for CTR 
    uint8_t nonce[16] = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    uint8_t message[48] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,  // block 0
        0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
        0xb2, 0xfb, 0x13, 0x66, 0xea, 0x95, 0x7d, 0x3e,  // block 1
        0x4d, 0x2c, 0x6d, 0xfc, 0x10, 0xac, 0x29, 0x01,
        0xd1, 0x92, 0xb8, 0x29, 0x7c, 0x1d, 0x9e, 0x4f   // block 2
    };
    uint8_t cipher[48];
    uint8_t decrypted[48];

    
    //////////////////////////////
    // Setup AESNI 
    //
    AESNI_Ctx ctx;
    aesni_init(key, AESNI_256, &ctx);
    
    printAES_state("Message", message, 3);
    printAES_state("Key", key, 2);

    //////////////////////////////
    /// Encrypt
    /// 
    // -- ECB ----------------------------------------------- 
    printf("\n--- ECB ---\n");
    aesni_ecb_encrypt(message, cipher, 3, &ctx);
    printAES_state("Encrypted", cipher, 3);
    aesni_ecb_decrypt(cipher, decrypted, 3, &ctx);
    printAES_state("Decrypted", decrypted, 3);

    // -- CBC ----------------------------------------------- 
    printf("\n--- CBC ---\n");
    printAES_state("IV", iv, 1);
    aesni_cbc_encrypt(message, cipher, 3, &ctx, iv);
    printAES_state("Encrypted", cipher, 3);
    aesni_cbc_decrypt(cipher, decrypted, 3, &ctx, iv);
    printAES_state("Decrypted", decrypted, 3);

    // -- CTR ----------------------------------------------- 
    printf("\n--- CTR ---\n");
    printAES_state("Nonce", nonce, 1);
    aesni_ctr_encrypt(message, cipher, 3, &ctx, nonce);
    printAES_state("Encrypted", cipher, 3);
    aesni_ctr_decrypt(cipher, decrypted, 3, &ctx, nonce);
    printAES_state("Decrypted", decrypted, 3);
    return 0;
}



