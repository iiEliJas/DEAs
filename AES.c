#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

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

uint8_t rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36
};



/////////////////////////////////////////////////////////////////////////
///                 DEBUGGING TOOLS
///
void printKey(const char *title, const uint32_t num[4]){
    printf("%s: ", title);
    for(int i=0; i<4; i++){
        printf(" %08x ", num[i]);
    }
    printf("\n");
}


// Prints the state correctly (in rows not in columns)
//
void printState(const char *title, const uint8_t num[16]){
    printf("%s: \n", title);
    for(int i=0; i<4; i++){
        for(int j=0; j<4; j++){
            printf(" %02x ", num[i+j*4]);
        }
        printf("\n");
    }
    printf("\n");
}

// turns a flat uint8_t key into the a 32 int array with words
//
void bytesToWords(const uint8_t bytes[16], uint32_t words[4]) {
    for (int i = 0; i < 4; i++) {
        words[i] =  ((uint32_t)bytes[i*4+0] << 24) |
                    ((uint32_t)bytes[i*4+1] << 16) |
                    ((uint32_t)bytes[i*4+2] <<  8) |
                     (uint32_t)bytes[i*4+3];
    }
}



////////////////////////////////////////////////////////////////////////////
///                 AES functions


// generates all 43 words and puts them into the subkey array
void aes_subkeyGen(const uint32_t key[4], uint32_t subkeys[11][4]){
    
    memcpy(subkeys[0], key, sizeof(subkeys[0]));

    for(int round=1; round<11; round++){
        uint32_t g = subkeys[round-1][3];
        g = (g << 8) | (g >> 24);   // Left shift
        g = ((uint32_t)sbox[(g >> 24) & 0xFF]) << 24    |
            ((uint32_t)sbox[(g >> 16) & 0xFF]) << 16    |       // put each byte into the sbox
            ((uint32_t)sbox[(g >> 8) & 0xFF]) << 8      |
            (uint32_t)(sbox[g & 0xFF]);    
        g ^= (uint32_t)(rcon[round-1]) << 24;        

        for(int i=0; i<4; i++){
            subkeys[round][i] = subkeys[round-1][i] ^ g;
            g = subkeys[round][i];
        }
    }
}



// XOR key and state 
//
static void AddRoundKey(uint8_t state[16], const uint32_t subkey[4]){
    for(int col=0; col<4; col++){
        for(int byte=0; byte<4; byte++){
            state[col*4+byte] ^= (subkey[col] >> (24-byte*8)) & 0xFF;
        }
    }
}


// SBOX substitution
//
static void ByteSub(uint8_t state[16]){
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


// AES 128 bit key encryption
//
void aes_encrypt(const uint8_t in[16], uint8_t out[16], const uint32_t subkeys[11][4]){
    memcpy(out, in, 16);

    AddRoundKey(out, subkeys[0]); // Before round 1

    for(int i=0; i<10; i++){
        ByteSub(out);
        ShiftRows(out);
        if(i!=9) MixCol(out);   // not in round 10
        AddRoundKey(out, subkeys[i+1]);

        // Debugging
        printf("Round %d", i+1);
        printState("", out);
    }
}



int main(void){
    //////////////////////////////
    /// key and message
    uint8_t raw_key[16] = {
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t message[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t cipher[16];

    
    //////////////////////////////
    // Generate subkeys 
    //
    uint32_t key[4];
    bytesToWords(raw_key, key);

    printKey("KEY", key);

    uint32_t subkeys[11][4];
    aes_subkeyGen(key, subkeys);

      // Print all subkeys
    for(int i=0; i<11; i++){
        printf("\nSubkey %d", i);
        printKey(" ", subkeys[i]);
        
    }
   

    //////////////////////////////
    /// Encrypt
    /// 
    printState("Message", message);
    aes_encrypt(message, cipher, subkeys);
    printState("Cipher", cipher);

    return 0;
}



//////////// TEST ////////////////////////////
/*
    This is a test encryption. The solutions can be compared to the official FIPS 197 document [Appendix B]


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
