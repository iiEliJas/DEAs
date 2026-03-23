#include <stdio.h>
#include "aes.h"
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
    // Setup AES 
    //
    AES_Ctx ctx;
    aes_init(key, AES_256, &ctx);
    
    printAES_state("Message", message, 3);
    printAES_state("Key", key, 2);

    //////////////////////////////
    /// Encrypt
    /// 
    // -- ECB ----------------------------------------------- 
    printf("\n--- ECB ---\n");
    aes_ecb_encrypt(message, cipher, 3, &ctx);
    printAES_state("Encrypted", cipher, 3);
    aes_ecb_decrypt(cipher, decrypted, 3, &ctx);
    printAES_state("Decrypted", decrypted, 3);

    // -- CBC ----------------------------------------------- 
    printf("\n--- CBC ---\n");
    printAES_state("IV", iv, 1);
    aes_cbc_encrypt(message, cipher, 3, &ctx, iv);
    printAES_state("Encrypted", cipher, 3);
    aes_cbc_decrypt(cipher, decrypted, 3, &ctx, iv);
    printAES_state("Decrypted", decrypted, 3);

    // -- CTR ----------------------------------------------- 
    printf("\n--- CTR ---\n");
    printAES_state("Nonce", nonce, 1);
    aes_ctr_encrypt(message, cipher, 3, &ctx, nonce);
    printAES_state("Encrypted", cipher, 3);
    aes_ctr_decrypt(cipher, decrypted, 3, &ctx, nonce);
    printAES_state("Decrypted", decrypted, 3);
    return 0;
}



//////////// TEST ////////////////////////////
/*
    This is the output of a test encryption. The solutions can be compared to the official FIPS 197 document [Appendix B]


KEY:  2b7e1516  28aed2a6  abf71588  09cf4f3c

Subkey 0 :  2b7e1516  28aed2a6  abf71588  09cf4f3c

Subkey 1 :  a0fafe17  88542cb1  23a33939  2a6c7605

Subkey 2 :  f2c295f2  7a96b943  5935807a  7359f67f

Subkey 3 :  3d80477d  4716fe3e  1e237e44  6d7a883b

Subkey 4 :  ef44a541  a8525b7f  b671253b  db0bad00

Subkey 5 :  d4d1c6f8  7c839d87  caf2b8bc  11f915bc

Subkey 6 :  6d88a37a  110b3efd  dbf98641  ca0093fd

Subkey 7 :  4e54f70e  5f5fc9f3  84a64fb2  4ea6dc4f

Subkey 8 :  ead27321  b58dbad2  312bf560  7f8d292f

Subkey 9 :  ac7766f3  19fadc21  28d12941  575c006e

Subkey 10 :  d014f9a8  c9ee2589  e13f0cc8  b6630ca6


Message:
 32  88  31  e0
 43  5a  31  37
 f6  30  98  07
 a8  8d  a2  34

Round 1:
 a4  68  6b  02
 9c  9f  5b  6a
 7f  35  ea  50
 f2  2b  43  49

Round 2:
 aa  61  82  68
 8f  dd  d2  32
 5f  e3  4a  46
 03  ef  d2  9a

Round 3:
 48  67  4d  d6
 6c  1d  e3  5f
 4e  9d  b1  58
 ee  0d  38  e7

Round 4:
 e0  c8  d9  85
 92  63  b1  b8
 7f  63  35  be
 e8  c0  50  01

Round 5:
 f1  c1  7c  5d
 00  92  c8  b5
 6f  4c  8b  d5
 55  ef  32  0c

Round 6:
 26  3d  e8  fd
 0e  41  64  d2
 2e  b7  72  8b
 17  7d  a9  25

Round 7:
 5a  19  a3  7a
 41  49  e0  8c
 42  dc  19  04
 b1  1f  65  0c

Round 8:
 ea  04  65  85
 83  45  5d  96
 5c  33  98  b0
 f0  2d  ad  c5

Round 9:
 eb  59  8b  1b
 40  2e  a1  c3
 f2  38  13  42
 1e  84  e7  d2

Round 10:
 39  02  dc  19
 25  dc  11  6a
 84  09  85  0b
 1d  fb  97  32

Cipher:
 39  02  dc  19
 25  dc  11  6a
 84  09  85  0b
 1d  fb  97  32
*/
