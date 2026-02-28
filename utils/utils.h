#ifndef UTILS
#define UTILS

#include <stdint.h>
#include <stddef.h>

// Print a 64-bit value as binary
void printbin(uint64_t num);

// Print a block array as hex
void print_blocks(const char *title, const uint64_t *blocks, size_t num_blocks);




///////////////////////////////////////////////////////
///             AES TOOLS

// Prints one AES keyword
//
void printAES_word(const uint32_t word);


// Prints the state correctly (in rows not in columns)
//
void printAES_state(const char *title, const uint8_t num[16]);

#endif
