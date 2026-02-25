#include "des_modes.h"
#include "des_core.h"

// ECB — Electronic Codebook
//
// Every block is encrypted independently with the same key.
// subkeyGen is called once; the same subkeys are reused for every block.
// 
// WARNING: identical plaintext blocks produce identical ciphertext blocks,
// making data patterns visible. Do not use ECB for real data.
//
void des_ecb_encrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key) {
    uint64_t subkeys[16];
    subkeyGen(key, subkeys);
    for (size_t i = 0; i < num_blocks; i++)
        out[i] = des_encrypt(in[i], subkeys);
}

void des_ecb_decrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key) {
    uint64_t subkeys[16];
    subkeyGen(key, subkeys);
    for (size_t i = 0; i < num_blocks; i++)
        out[i] = des_decrypt(in[i], subkeys);
}





// CBC — Cipher Block Chaining
//
// Encrypt: ciphertext[i] = DES_enc(plaintext[i] XOR prev_cipher)
// prev_cipher starts as the IV, then becomes ciphertext[i-1].
// 
// Decrypt: plaintext[i] = DES_dec(ciphertext[i]) XOR prev_cipher
// Note: prev_cipher for decryption is ciphertext[i-1], saved BEFORE
// overwriting out[i], so in-place buffers (in == out) are safe.
//
void des_cbc_encrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t iv) {
    uint64_t subkeys[16];
    subkeyGen(key, subkeys);

    uint64_t prev = iv;
    for (size_t i = 0; i < num_blocks; i++) {
        out[i] = des_encrypt(in[i] ^ prev, subkeys);
        prev   = out[i];
    }
}

void des_cbc_decrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t iv) {
    uint64_t subkeys[16];
    subkeyGen(key, subkeys);

    uint64_t prev = iv;
    for (size_t i = 0; i < num_blocks; i++) {
        uint64_t tmp = in[i];          /* save before possible in-place overwrite */
        out[i] = des_decrypt(in[i], subkeys) ^ prev;
        prev   = tmp;
    }
}





// CTR — Counter Mode
// 
// Turns DES into a stream cipher:
// keystream[i] = DES_enc(nonce XOR i)
// ciphertext[i] = plaintext[i] XOR keystream[i]
// 
// Encryption and decryption are identical (XOR is its own inverse).
// No padding needed. Blocks can be processed in parallel.
//
static void des_ctr(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t nonce) {
    uint64_t subkeys[16];
    subkeyGen(key, subkeys);

    for (size_t i = 0; i < num_blocks; i++) {
        uint64_t counter_block = nonce ^ (uint64_t)i;
        uint64_t keystream     = des_encrypt(counter_block, subkeys);
        out[i] = in[i] ^ keystream;
    }
}

void des_ctr_encrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t nonce) {
    des_ctr(in, out, num_blocks, key, nonce);
}

void des_ctr_decrypt(const uint64_t *in, uint64_t *out, size_t num_blocks, uint64_t key, uint64_t nonce) {
    des_ctr(in, out, num_blocks, key, nonce);
}




