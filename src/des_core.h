#ifndef DES_CORE
#define DES_CORE

#include <stdint.h>
#include <stddef.h>


// Bit permutation
// out_width : output bits (length of the table)
// in_width  : input bits
//
uint64_t permutate(uint64_t num, const int *table, int out_width, int in_width);




// Generate all 16 subkeys
// 1 subkey : 48 bits
//
void subkeyGen(uint64_t key, uint64_t subkeys[16]);




// R: 32 bits, key: 48 bits
// Feistel function
// Expands R and XOR it with the key, puts blocks of 6 bits into the SBOX and finally does a permutation P
//
uint32_t feistel(uint32_t R, uint64_t key);




// takes a 64 bit message and 64 bit key and creates a 64 bit cipher-message
//
uint64_t des_encrypt(const uint64_t message, uint64_t subkeys[16]);




// reverse of des_encrypt
//
uint64_t des_decrypt(const uint64_t cipher, uint64_t subkeys[16]);



//////////////////////////////////////////////////////////////////////////
///                          MODES
///


//ECB — Electronic Codebook
//Each block is encrypted independently with the same key
//
void des_ecb_encrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key);
void des_ecb_decrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key);



//CBC — Cipher Block Chaining
//Each plaintext block is XORed with the previous ciphertext block before encryption
//
void des_cbc_encrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t iv);
void des_cbc_decrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t iv);



//CTR — Counter Mode
//Encrypts a nonce||counter value and XORs the result with plaintext
//
void des_ctr_encrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t nonce);
void des_ctr_decrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t nonce);



#endif
