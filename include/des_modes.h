#ifndef DES_MODES
#define DES_MODES

#include <stdint.h>
#include <stddef.h>



//ECB — Electronic Codebook
//Each block is encrypted independently with the same key.
//
void des_ecb_encrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key);
void des_ecb_decrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key);



//CBC — Cipher Block Chaining
//Each plaintext block is XORed with the previous ciphertext block before encryption.
//
void des_cbc_encrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t iv);
void des_cbc_decrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t iv);



//CTR — Counter Mode
//Encrypts a nonce||counter value and XORs the result with plaintext.
//
void des_ctr_encrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t nonce);
void des_ctr_decrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t nonce);


#endif
