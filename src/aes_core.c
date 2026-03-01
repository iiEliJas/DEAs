#include "aes_core.h"



uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

uint8_t rcon[11] = {
    0x00,   // not needed - rcon index starts at 1
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36
};




////////////////////////////////////////////////////////////////////////////
///                 AES functions

// turns a flat uint8_t key into the a 32 int array with words
//
void bytesToWords(const uint8_t *bytes, uint32_t *words, int Nk) {
    for (int i = 0; i < Nk; i++) {
        words[i] =  ((uint32_t)bytes[i*4+0] << 24) |
                    ((uint32_t)bytes[i*4+1] << 16) |
                    ((uint32_t)bytes[i*4+2] <<  8) |
                     (uint32_t)bytes[i*4+3];
    }
}




// XOR key and state 
//
static void AddRoundKey(uint8_t state[16], const uint32_t words[4]){
    for(int col=0; col<4; col++){
        for(int byte=0; byte<4; byte++){
            state[col*4+byte] ^= (words[col] >> (24-byte*8)) & 0xFF;
        }
    }
}


// SBOX substitution
//
static void SubBytes(uint8_t state[16]){
    for(int i=0; i<16; i++){
        state[i] = sbox[state[i]];
    }
}


// Cyclical left shift
// 1st row: no change
// 2nd row: 1 byte
// 3rd row: 2 bytes
// 4th row: 3 bytes
static void ShiftRows(uint8_t state[16]){
    for(int i=1; i<4; i++){
        uint8_t temp[4] = { state[i], state[i+4], state[i+8], state[i+12] };    // temporarly store the row

        for(int j=0; j<4; j++){
            int sub_i = i + ((4+j-i)%4)*4;  // new substitution index

            state[sub_i] = temp[j]; 
        }
    }
}



static void MixCol(uint8_t state[16]){
    for (int col = 0; col < 4; col++) {
        uint8_t s0 = state[col*4+0];
        uint8_t s1 = state[col*4+1];
        uint8_t s2 = state[col*4+2];
        uint8_t s3 = state[col*4+3];

        uint8_t x0 = (s0<<1) ^ ((s0>>7) ? 0x1b : 0x00);
        uint8_t x1 = (s1<<1) ^ ((s1>>7) ? 0x1b : 0x00);
        uint8_t x2 = (s2<<1) ^ ((s2>>7) ? 0x1b : 0x00);
        uint8_t x3 = (s3<<1) ^ ((s3>>7) ? 0x1b : 0x00);

        state[col*4+0] = x0 ^ (x1^s1) ^ s2 ^ s3;
        state[col*4+1] = s0 ^ x1 ^ (x2^s2) ^ s3;
        state[col*4+2] = s0 ^ s1 ^ x2 ^ (x3^s3);
        state[col*4+3] = (x0^s0) ^ s1 ^ s2 ^ x3;
        
    }
}





// Generates all words and puts them into the words array
// key ... the key containing all 128/192/256 bits (must be in seperate 32 bit integer values)
// words .... output array either words128[44], words192[52] or words256[60]
// Nk ... length of uint32_t key. So Nk=4 for 128bit, 6 for 192bit and 8 for 256bit
//
void aes_keyexpansion(const uint32_t *key, uint32_t *words, int Nk){
    int Nr = Nk+6;  // Number of rounds (10, 12, 14)
    
    for(int i=0; i<Nk; i++){
        words[i] = key[i];  // Key 0
    }

    for(int i=Nk; i<=4*Nr+3; i++){
        uint32_t temp = words[i-1];

        if(i%Nk == 0){
            temp = (temp << 8) | (temp >> 24);                      // RotWord
            temp =  ((uint32_t)sbox[(temp>>24) & 0xFF] << 24) |     // SubWord
                    ((uint32_t)sbox[(temp>>16) & 0xFF] << 16) |
                    ((uint32_t)sbox[(temp>> 8) & 0xFF] <<  8) |
                    ((uint32_t)sbox[ temp      & 0xFF]);
            temp ^= (uint32_t)rcon[i/Nk] << 24;                     // Rcon
        }
        else if(Nk>6 && i%Nk == 4){
            temp =  ((uint32_t)sbox[(temp>>24) & 0xFF] << 24) |     // SubWord
                    ((uint32_t)sbox[(temp>>16) & 0xFF] << 16) |
                    ((uint32_t)sbox[(temp>> 8) & 0xFF] <<  8) |
                    ((uint32_t)sbox[ temp      & 0xFF]);
        }

        words[i] = words[i-Nk] ^ temp;
    }
}



// Init function ... setup for aes_encrypt
// takes in  AES_Ctx pointer which will be passed into aes_encrypt
//
void aes_init(const uint8_t *key, AES_KEYSIZE keysize, AES_Ctx *ctx){
    int Nk = (int)keysize;
    ctx->nr = Nk+6;
    uint32_t keywords[8];
    bytesToWords(key, keywords, Nk);
    aes_keyexpansion(keywords, ctx->words, Nk);
}




// AES key encryption
// takes in a message (in) and outputs a cipher (out)
// AES_Ctx must be initialized beforehand
//
void aes_encrypt(const uint8_t in[16], uint8_t out[16], const AES_Ctx *ctx){
    memcpy(out, in, 16);

    AddRoundKey(out, &ctx->words[0]); // Before round 1

    for(int i=1; i<=ctx->nr; i++){
        SubBytes(out);
        ShiftRows(out);
        if(i!=ctx->nr) MixCol(out);   // not in round 10
        AddRoundKey(out, &ctx->words[i*4]);
    }
}


