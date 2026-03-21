CC      = gcc
CFLAGS  = -Wall -Wextra -O2
NIFLAGS = -Wall -Wextra -O2 -maes -msse4.1
 
SRC_DIR  = src
DEMO_DIR = Demos
UTIL_DIR = utils
TEST_DIR = tests
 
# Shared utils object
UTILS_OBJ = $(UTIL_DIR)/utils.o
 
.PHONY: all aes des aesni test test-aes test-des test-aesni clean
 
all: aes aesni des
 
# Compile utils once, reuse for all demos
$(UTILS_OBJ): $(UTIL_DIR)/utils.c $(UTIL_DIR)/utils.h
	$(CC) $(CFLAGS) -c $< -o $@
 

# ---------------- DEMOS --------------------------

aes: $(DEMO_DIR)/aes_demo.c $(SRC_DIR)/aes_core.c $(UTILS_OBJ)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o aes_demo
 
aesni: $(DEMO_DIR)/aesni_demo.c $(SRC_DIR)/aesni_core.c $(UTILS_OBJ)
	$(CC) $(NIFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o aesni_demo
	
des: $(DEMO_DIR)/des_demo.c $(SRC_DIR)/des_core.c $(UTILS_OBJ)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o des_demo
 
	
# ---------------- TESTS --------------------------

test-aes: $(TEST_DIR)/aes_test.c $(SRC_DIR)/aes_core.c $(UTILS_OBJ)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o test_aes
	./test_aes
 
test-aesni: $(TEST_DIR)/aesni_test.c $(SRC_DIR)/aesni_core.c $(UTILS_OBJ)
	$(CC) $(NIFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o test_aesni
	./test_aesni

test-des: $(TEST_DIR)/des_test.c $(SRC_DIR)/des_core.c $(UTILS_OBJ)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o test_des
	./test_des
 
test: test-aes test-aesni test-des
 
clean:
	rm -f aes_demo des_demo test_aes test_des $(UTILS_OBJ)
 
