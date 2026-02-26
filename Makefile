CC      = gcc
CFLAGS  = -Wall -Wextra -Iinclude
SRC     = src/des_tables.c src/des_core.c src/utils.c DES.c
TARGET  = des

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
