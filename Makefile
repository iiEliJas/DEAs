CC      = gcc
CFLAGS  = -Wall -Wextra -O2
NIFLAGS = -Wall -Wextra -O2 -maes -msse4.1
 
SRC_DIR  = src
DEMO_DIR = demos
UTIL_DIR = utils
TEST_DIR = tests
BIN_DIR  = bin
 
# Shared objects
UTILS_OBJ = $(UTIL_DIR)/utils.o
 
.PHONY: all aes des aesni aesgcm test test-aes test-des test-aesni test-aesgcm clean
 
all: aes aesni aesgcm des
 
# Compile once, use multiple times
$(UTILS_OBJ): $(UTIL_DIR)/utils.c $(UTIL_DIR)/utils.h
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN_DIR):
	mkdir -p $(BIN_DIR)
 

# ---------------- DEMOS --------------------------

aes: $(DEMO_DIR)/aes_demo.c $(SRC_DIR)/aes.c $(UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o $(BIN_DIR)/aes_demo
 
aesni: $(DEMO_DIR)/aesni_demo.c $(SRC_DIR)/aesni.c $(UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(NIFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o $(BIN_DIR)/aesni_demo

aesgcm: $(DEMO_DIR)/aes256gcm_demo.c $(SRC_DIR)/aes256gcm.c $(SRC_DIR)/aesni.c $(UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(NIFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o $(BIN_DIR)/aesgcm_demo
	
des: $(DEMO_DIR)/des_demo.c $(SRC_DIR)/des.c $(UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) $^ -o $(BIN_DIR)/des_demo
 
	
# ---------------- TESTS --------------------------

test-aes: $(TEST_DIR)/aes_test.c $(SRC_DIR)/aes.c $(UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) -I$(TEST_DIR) $^ -o $(BIN_DIR)/test_aes
	./$(BIN_DIR)/test_aes
 
test-aesni: $(TEST_DIR)/aesni_test.c $(SRC_DIR)/aesni.c $(UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(NIFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) -I$(TEST_DIR) $^ -o $(BIN_DIR)/test_aesni
	./$(BIN_DIR)/test_aesni

test-aesgcm: $(TEST_DIR)/aes256gcm_test.c $(SRC_DIR)/aes256gcm.c $(SRC_DIR)/aesni.c $(UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(NIFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) -I$(TEST_DIR) $^ -o $(BIN_DIR)/test_aesgcm
	./$(BIN_DIR)/test_aesgcm

test-des: $(TEST_DIR)/des_test.c $(SRC_DIR)/des.c $(UTILS_OBJ) | $(BIN_DIR)
	$(CC) $(CFLAGS) -I$(SRC_DIR) -I$(UTIL_DIR) -I$(TEST_DIR) $^ -o $(BIN_DIR)/test_des
	./$(BIN_DIR)/test_des
 
test: test-aes test-aesni test-aesgcm test-des
 
clean:
	rm -f aes_demo des_demo test_aes test_des $(UTILS_OBJ) $(TEST_OBJ) $(BIN_DIR)
 
