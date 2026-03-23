#include "des.h"


////////////////////////////////////////////////////
///             DES TABLES

// First Permutation IP
const int IP[64] = {
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
};



// Final Permutation IP^-1
const int FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};


// PC-1: selects 56 bits from the 64-bit key
const int PC1[56] = {
        // Left half (C0) - 28 bits 
        57, 49, 41, 33, 25, 17,  9,
        1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,

        // Right half (D0) - 28 bits
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
};

// PC-2: selects 48 bits from the 56-bit combined CD
const int PC2[48] = {
        14, 17, 11, 24,  1,  5,
         3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
};


// Expansion table: expands R from 32 to 48 bits
const int E[48] = {
        32,  1,  2,  3,  4,  5,
         4,  5,  6,  7,  8,  9,
         8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
};

// P-permutation: shuffles the 32-bit S-Box output
const int P[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};

// All 8 S-Boxes
const int SBOX[8][4][16] = {
    { /* S1 */
        {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
        { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
        { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
        {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}
    },
    { /* S2 */
        {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
        { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
        { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
        {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    },
    { /* S3 */
        {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
        {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
        {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
        { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    },
    { /* S4 */
        { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
        {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
        {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    },
    { /* S5 */
        { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
        {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
        { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
        {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    },
    { /* S6 */
        {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
        {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
        { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
        { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    },
    { /* S7 */
        { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
        {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
        { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
        { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    },
    { /* S8 */
        {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
        { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
        { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
        { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    }
};



///////////////////////////////////////////////////////////////
///                 DES FUNCTIONS

// Left-Shift scheduling for key generation 
const int SHIFT_SCHEDULE[16] = {
        1, 1, 2, 2, 2, 2, 2, 2,
        1, 2, 2, 2, 2, 2, 2, 1
};


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



