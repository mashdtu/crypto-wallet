# Makefile

CC     := gcc
CFLAGS := -Wall -Wextra -std=c11 \
          $(shell pkg-config --cflags openssl libsecp256k1 libcurl)
LDFLAGS := $(shell pkg-config --libs openssl libsecp256k1 libcurl)

SRCS := src/main.c src/keygen.c src/wallet.c src/storage.c src/network.c src/tx.c src/bech32.c

.PHONY: all compile run test compile_commands clean install uninstall crack

all: wallet

compile: wallet

run: wallet
	./wallet

wallet: $(SRCS) src/keygen.h src/wallet.h src/storage.h src/network.h src/tx.h src/bech32.h
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS)

crack: tools/crack.c
	$(CC) -O2 -Wall -pthread $(shell pkg-config --cflags openssl) tools/crack.c -o tools/crack $(shell pkg-config --libs openssl)

test: tests/test_vector
	./tests/test_vector

tests/test_vector: tests/test_vector.c src/bech32.c src/bech32.h
	$(CC) $(CFLAGS) -Isrc tests/test_vector.c src/bech32.c -o tests/test_vector $(LDFLAGS)

compile_commands:
	bear -- $(MAKE) all test

clean:
	rm -f wallet keygen tests/test_vector tools/crack

INSTALL_DIR := /usr/local/bin

install: wallet
	@cp wallet $(INSTALL_DIR)/wallet
	@echo "Installed to $(INSTALL_DIR)/wallet"

uninstall:
	@rm -f $(INSTALL_DIR)/wallet
	@echo "Removed $(INSTALL_DIR)/wallet"

