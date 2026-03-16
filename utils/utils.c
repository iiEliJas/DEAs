#include "utils.h"
#include <stdio.h>
#include <inttypes.h>




void printbin(uint64_t num) {
    for (int i = 63; i >= 0; i--) {
        printf("%c", (num & (1ULL << i)) ? '1' : '0');
        if (i % 8 == 0) printf(" ");
    }
    printf("\n");
}

void print_blocks(const char *title, const uint64_t *blocks, size_t num_blocks) {
    printf("%s:\n", title);
    for (size_t i = 0; i < num_blocks; i++)
        printf("  0x%016" PRIX64 "\n", (uint64_t)blocks[i]);
}



/////////////////////////////////////////////////////////////////////////
///                 AES TOOLS
///
void printAES_word(const uint32_t word){
    printf(" %08x ", word);
    printf("\n");
}


// Prints the state correctly (in rows not in columns)
//
void printAES_state(const char *title, const uint8_t *num, const size_t num_blocks){
    printf("%s: \n", title);
    for(size_t block=0; block<num_blocks; block++){
        for(int i=0; i<4; i++){
            for(int j=0; j<4; j++){
                printf(" %02x ", num[block*16+i+j*4]);
            }
            printf("\n");
        }
    }
}
