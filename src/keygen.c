#define _DEFAULT_SOURCE
#include "keygen.h"
#include "wordlist.c"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

int keygen_mnemonic(char *mnemonic_out, unsigned int mnemonic_size)
{
    if (!mnemonic_out || mnemonic_size < 216u) return -1;

    unsigned char entropy[32];
    if (getentropy(entropy, sizeof(entropy)) != 0) return -1;

    unsigned char hash[32];
    SHA256(entropy, 32, hash);

    unsigned char combined[33];
    for (unsigned int i = 0; i < 32; i++) combined[i] = entropy[i];
    combined[32] = hash[0];

    unsigned int indices[24];
    for (unsigned int i = 0; i < 24; i++) {
        unsigned int start_bit = i * 11;
        unsigned int byte_pos  = start_bit / 8;
        unsigned int bit_pos   = start_bit % 8;
        if (bit_pos <= 5) {
            unsigned int w = ((unsigned int)combined[byte_pos] << 8) | combined[byte_pos + 1];
            indices[i] = (w >> (5 - bit_pos)) & 0x7FFu;
        } else {
            unsigned int w = ((unsigned int)combined[byte_pos] << 16)
                           | ((unsigned int)combined[byte_pos + 1] << 8)
                           | combined[byte_pos + 2];
            indices[i] = (w >> (13 - bit_pos)) & 0x7FFu;
        }
    }

    mnemonic_out[0] = '\0';
    for (unsigned int i = 0; i < 24; i++) {
        strcat(mnemonic_out, wordlist[indices[i]]);
        if (i < 23u) strcat(mnemonic_out, " ");
    }

    return 0;
}

int keygen_seed(const char *mnemonic, unsigned char *seed_out)
{
    if (!mnemonic || !seed_out) return -1;

    int rc = PKCS5_PBKDF2_HMAC(mnemonic, (int)strlen(mnemonic),
                                (const unsigned char *)"mnemonic", 8,
                                2048, EVP_sha512(), 64, seed_out);
    return rc == 1 ? 0 : -1;
}

int keygen_valid_word(const char *word)
{
    for (unsigned int i = 0; i < 2048u; i++) {
        if (strcmp(wordlist[i], word) == 0) return 1;
    }
    return 0;
}
