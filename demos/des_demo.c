#include <stdio.h>
#include "des_core.h"
#include "utils.h"



int main(void) {
    //////////////////////////////
    /// key and message
    uint64_t key  = 0x133457799BBCDFF1;
    // -- IV for CBC
    uint64_t iv   = 0xDEADBEEFCAFEBABE;
    // Nonce for CTR 
    uint64_t nonce = 0xFEDCBA9876543210; 
    uint64_t message[3] = {
        0x0123456789ABCDEF,
        0xFEDCBA9876543210,
        0xAABBCCDDEEFF0011
    };
    uint64_t cipher[3];
    uint64_t decrypted[3];

    print_blocks("Key: ", &key, 1);
    print_blocks("Message: ", message, 3);

    // -- ECB
    printf("\n--- ECB ---\n");
    des_ecb_encrypt(message, cipher, 3, key);
    print_blocks("Encrypted", cipher, 3);
    des_ecb_decrypt(cipher, decrypted, 3, key);
    print_blocks("Decrypted", decrypted, 3);

    // -- CBC
    printf("\n--- CBC ---\n");
    des_cbc_encrypt(message, cipher, 3, key, iv);
    print_blocks("Encrypted", cipher, 3);
    des_cbc_decrypt(cipher, decrypted, 3, key, iv);
    print_blocks("Decrypted", decrypted, 3);

    // -- CTR
    printf("\n--- CTR ---\n");
    des_ctr_encrypt(message, cipher, 3, key, nonce);
    print_blocks("Encrypted", cipher, 3);
    des_ctr_decrypt(cipher, decrypted, 3, key, nonce);
    print_blocks("Decrypted", decrypted, 3);

    return 0;
}
