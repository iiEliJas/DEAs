#include "des_core.h"
#include "des_tables.h"



static uint64_t leftShift28(uint32_t num, int n){
    return ((num<<n) | (num>>(28-n))) & 0x0FFFFFFF; 
}





uint64_t permutate(uint64_t num, const int *table, int out_width, int in_width){
    uint64_t result = 0;

    for(int i=0; i<out_width; i++){
        uint64_t bit = (num >> (in_width-table[i])) & 1;
        result |= bit << (out_width-1-i);
    }
    return result;
}





void subkeyGen(uint64_t key, uint64_t subkeys[16]){
    uint64_t permuted = permutate(key, PC1, 56, 64);

    uint32_t C = permuted>>28 & 0x0FFFFFFF;    
    uint32_t D = permuted     & 0x0FFFFFFF;

    for(int i=0; i<16; i++){
        C = leftShift28(C, SHIFT_SCHEDULE[i]);
        D = leftShift28(D, SHIFT_SCHEDULE[i]);
        
        uint64_t CD = ((uint64_t)C<<28) | D;
        subkeys[i] = permutate(CD, PC2, 48, 56);
    }
}





uint32_t feistel(uint32_t R, uint64_t key){
    uint64_t R_e = permutate((uint64_t)R, E, 48, 32);     // expanded R with E-table  -> 48 bits

    uint64_t KR = R_e ^ key;    // R expanded XOR key -> 48 bits

    uint32_t S = 0;

    for(int s=0; s<8; s++){
        uint8_t B = (KR >> (42-s*6)) & 0x3F;
        
        uint8_t row = ((B & 0x20) >> 4) | (B & 1);
        uint8_t col = (B >> 1) & 0x0F;

        S = (S << 4) | SBOX[s][row][col];
    }
    
    return (uint32_t)permutate((uint64_t)S, P, 32, 32);
}





uint64_t des_encrypt(const uint64_t message, uint64_t subkeys[16]){
    uint64_t permutation = permutate(message, IP, 64, 64);

    uint32_t L = permutation>>32;
    uint32_t R = (uint32_t)permutation;

    for(int round=0; round<16; round++){
       uint32_t temp = R;
       R = L ^ feistel(R, subkeys[round]);
       L = temp;
    } 

    uint64_t final = ((uint64_t)R << 32) | (uint64_t)L;
    return permutate(final, FP, 64, 64);
}





uint64_t des_decrypt(const uint64_t cipher, uint64_t subkeys[16]){
    uint64_t permutation = permutate(cipher, IP, 64, 64);

    uint32_t L = permutation>>32;
    uint32_t R = (uint32_t)permutation;

    for(int round=0; round<16; round++){
       uint32_t temp = R;
       R = L ^ feistel(R, subkeys[15-round]);
       L = temp;
    } 

    uint64_t final = ((uint64_t)R << 32) | (uint64_t)L;
    return permutate(final, FP, 64, 64);
}




// ECB — Electronic Codebook
//
// Every block is encrypted independently with the same key
// subkeyGen is called once; the same subkeys are reused for every block
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
// prev_cipher starts as the IV, then becomes ciphertext[i-1]
// 
// Decrypt: plaintext[i] = DES_dec(ciphertext[i]) XOR prev_cipher
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
        uint64_t tmp = in[i];  
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
// Encryption and decryption are identical 
// No padding needed. Blocks can be processed in parallel
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



