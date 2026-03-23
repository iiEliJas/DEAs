#ifndef AES_CORE
#define AES_CORE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>



typedef enum {
        AES_128 = 4,
        AES_192 = 6,
        AES_256 = 8
} AES_KEYSIZE;


typedef struct {
        uint32_t words[60];   // keywords
        int nr;               // number of rounds (10,12,14)
} AES_Ctx;




// Generates all words and puts them into the words array
// key ... the key containing all 128/192/256 bits (must be in seperate 32 bit integer values)
// words .... output array either words128[44], words192[52] or words256[60]
// Nk ... length of uint32_t key. So Nk=4 for 128bit, 6 for 192bit and 8 for 256bit
//
void aes_keyexpansion(const uint32_t *key, uint32_t *words, int Nk);




// Init function ... setup for aes_encrypt
// takes in  AES_Ctx pointer, which will be passed into aes_encrypt
//
void aes_init(const uint8_t *key, AES_KEYSIZE keysize, AES_Ctx *ctx);




// AES key encryption
// takes in a message (in) and outputs a cipher (out)
// AES_Ctx must be initialized beforehand
//
void aes_encrypt(const uint8_t in[16], uint8_t out[16], const AES_Ctx *ctx);




// AES key decryption 
// takes in a cipher (in) and outputs the encrypted message (out)
// AES_Ctx must be initialized beforehand
//
void aes_decrypt(const uint8_t in[16], uint8_t out[16], const AES_Ctx *ctx);










////////////////////////////////////////////////////////////////////////////////////////
///                     MODES
///


//ECB — Electronic Codebook
//Each block is encrypted independently with the same key
//
void aes_ecb_encrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AES_Ctx *ctx);
void aes_ecb_decrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AES_Ctx *ctx);



//CBC — Cipher Block Chaining
//Each plaintext block is XORed with the previous ciphertext block before encryption
//
void aes_cbc_encrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AES_Ctx *ctx, uint8_t iv[16]);
void aes_cbc_decrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AES_Ctx *ctx, uint8_t iv[16]);



//CTR — Counter Mode
//Encrypts a nonce||counter value and XORs the result with plaintext
//
void aes_ctr_encrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AES_Ctx *ctx, uint8_t nonce[16]);
void aes_ctr_decrypt(const uint8_t *in, uint8_t *out, int num_blocks, const AES_Ctx *ctx, uint8_t nonce[16]);












#endif
