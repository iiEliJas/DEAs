#include <stdio.h>
#include "des_core.h"
#include "utils.h"



int main(void) {
    uint64_t key  = 0x133457799BBCDFF1;
    uint64_t iv   = 0xDEADBEEFCAFEBABE;   // for CBC
    uint64_t nonce = 0xFEDCBA9876543210;  // for CTR 

    uint64_t message[3] = {
        0x0123456789ABCDEF,
        0xFEDCBA9876543210,
        0xAABBCCDDEEFF0011
    };

    uint64_t ciphertext[3] = {0};
    uint64_t decrypted[3]  = {0};

    printf("----------------------------------------------\n");
    printf("  Key: 0x%016llX\n\n", (unsigned long long)key);
    print_blocks("Message: ", message, 3);

    // -- ECB
    printf("\n--- ECB ---\n");
    des_ecb_encrypt(message, ciphertext, 3, key);
    print_blocks("Encrypted", ciphertext, 3);
    des_ecb_decrypt(ciphertext, decrypted, 3, key);
    print_blocks("Decrypted", decrypted, 3);

    // -- CBC
    printf("\n--- CBC (IV: 0x%016llX) ---\n", (unsigned long long)iv);
    des_cbc_encrypt(message, ciphertext, 3, key, iv);
    print_blocks("Encrypted", ciphertext, 3);
    des_cbc_decrypt(ciphertext, decrypted, 3, key, iv);
    print_blocks("Decrypted", decrypted, 3);

    // -- CTR
    printf("\n--- CTR (nonce: 0x%016llX) ---\n", (unsigned long long)nonce);
    des_ctr_encrypt(message, ciphertext, 3, key, nonce);
    print_blocks("Encrypted", ciphertext, 3);
    des_ctr_decrypt(ciphertext, decrypted, 3, key, nonce);
    print_blocks("Decrypted", decrypted, 3);

    printf("\n----------------------------------------------\n");
    return 0;
}
