#include <stdio.h>
#include <string.h>
#include "aes256gcm.h"
#include "../utils/utils.h"


int main(void){
    //////////////////////////////
    /// Key, IV, message and AAD

    uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    // GCM uses a 12-byte IV
    uint8_t iv[12] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88
    };
    uint8_t message[48] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,  // block 0
        0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08,
        0xb2, 0xfb, 0x13, 0x66, 0xea, 0x95, 0x7d, 0x3e,  // block 1
        0x4d, 0x2c, 0x6d, 0xfc, 0x10, 0xac, 0x29, 0x01,
        0xd1, 0x92, 0xb8, 0x29, 0x7c, 0x1d, 0x9e, 0x4f   // block 2
    };
    // AAD is authenticated but not encrypted
    const char *aad = "entry-id:0042";

    uint8_t cipher[48];
    uint8_t tag[16];
    uint8_t decrypted[48];

    printAES_state("Message", message, 3);
    printAES_state("Key", key, 2);
    printf("IV:  ");
    for (int i = 0; i < 12; i++) printf("%02x ", iv[i]);
    printf("\nAAD: %s\n", aad);


    //////////////////////////////
    /// GCM without AAD

    printf("\n--- GCM (no AAD) ---\n");
    aes256gcm_encrypt(message, 48, NULL, 0, key, iv, cipher, tag);
    printAES_state("Encrypted", cipher, 3);
    printf("Tag: ");
    for (int i = 0; i < 16; i++) printf("%02x ", tag[i]);
    printf("\n");

    int result = aes256gcm_decrypt(cipher, 48, NULL, 0, key, iv, tag, decrypted);
    printf("Auth: %s\n", result == 0 ? "OK" : "FAIL");
    printAES_state("Decrypted", decrypted, 3);


    //////////////////////////////
    /// GCM with AAD

    printf("\n--- GCM (with AAD) ---\n");
    printf("AAD: %s\n", aad);
    aes256gcm_encrypt(message, 48, (uint8_t*)aad, strlen(aad), key, iv, cipher, tag);
    printAES_state("Encrypted", cipher, 3);
    printf("Tag: ");
    for (int i = 0; i < 16; i++) printf("%02x ", tag[i]);
    printf("\n");

    result = aes256gcm_decrypt(cipher, 48, (uint8_t*)aad, strlen(aad), key, iv, tag, decrypted);
    printf("Auth: %s\n", result == 0 ? "OK" : "FAIL");
    printAES_state("Decrypted", decrypted, 3);

    return 0;
} 
