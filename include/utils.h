#ifndef DES_UTILS
#define DES_UTILS

#include <stdint.h>
#include <stddef.h>

// Print a 64-bit value as binary
void printbin(uint64_t num);

// Print a block array as hex
void print_blocks(const char *title, const uint64_t *blocks, size_t num_blocks);

#endif
