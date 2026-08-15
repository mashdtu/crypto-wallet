# Makefile

CC     := gcc
CFLAGS := -Wall -Wextra -std=c11 \
          $(shell pkg-config --cflags openssl)
LDFLAGS := $(shell pkg-config --libs openssl)

.PHONY: all compile_commands clean

all: keygen

keygen: src/keygen.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

compile_commands:
	bear -- $(MAKE) all

clean:
	rm -f keygen
