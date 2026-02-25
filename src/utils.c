
#include "utils.h"
#include <stdio.h>

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
        printf("  [%zu] 0x%016llX\n", i, (unsigned long long)blocks[i]);
}
