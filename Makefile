CC      = gcc
CFLAGS  = -Wall -Wextra -O2

SRC_DIR = src
DEMO_DIR = Demos
UTIL_DIR = utils

# Shared utils object
UTILS_OBJ = $(UTIL_DIR)/utils.o

.PHONY: all aes des clean

all: aes des

# Compile utils once, reuse for both demos
$(UTILS_OBJ): $(UTIL_DIR)/utils.c $(UTIL_DIR)/utils.h
	$(CC) $(CFLAGS) -c $< -o $@

aes: $(DEMO_DIR)/aes_demo.c $(SRC_DIR)/aes_core.c $(UTILS_OBJ)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o aes_demo

des: $(DEMO_DIR)/des_demo.c $(SRC_DIR)/des_core.c $(UTILS_OBJ)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o des_demo

clean:
	rm -f aes_demo des_demo $(UTILS_OBJ)
