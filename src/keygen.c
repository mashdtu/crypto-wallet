/*
 * keygen.c - BIP-39 mnemonic generation and seed derivation
 *
 * This file handles everything from raw entropy to the 64-byte seed that
 * the rest of the wallet builds on.  The flow is:
 *
 *   1. getentropy() pulls 32 bytes of cryptographic randomness from the OS.
 *   2. We SHA-256 the entropy and take the first byte as a checksum.
 *   3. The 256 entropy bits + 8 checksum bits = 264 bits are split into
 *      24 groups of 11 bits each. Each 11-bit value is a word index.
 *   4. The 24 word indices map to English words from the BIP-39 wordlist.
 *   5. The mnemonic is then stretched into a 64-byte seed via PBKDF2 so
 *      that brute-forcing the seed from a partial mnemonic is expensive.
 *
 * The resulting seed is NOT stored anywhere, only the AES-256-GCM
 * encrypted version of it lives on the USB drive (see storage.c).
 */

#define _DEFAULT_SOURCE
#include "keygen.h"
#include "wordlist.c"    /* embeds the 2048-word BIP-39 English wordlist */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

int keygen_mnemonic(char *mnemonic_out, unsigned int mnemonic_size)
{
    if (!mnemonic_out || mnemonic_size < 216u) return -1;

    /* Step 1: Get 32 bytes of OS entropy.
     * getentropy() is a Linux syscall that reads from the kernel's CSPRNG.
     * It blocks until enough entropy is available, so this is safe even
     * right after boot. */
    unsigned char entropy[32];
    if (getentropy(entropy, sizeof(entropy)) != 0) return -1;

    /* Step 2: SHA-256 the entropy and use the first byte as a checksum.
     * BIP-39 specifies: for 256 bits of entropy, the checksum is 8 bits
     * (256 / 32 = 8). This gives us 264 bits total. */
    unsigned char hash[32];
    SHA256(entropy, 32, hash);

    /* Append the checksum byte to the entropy so we can treat it as a
     * single 33-byte (264-bit) block. */
    unsigned char combined[33];
    for (unsigned int i = 0; i < 32; i++) combined[i] = entropy[i];
    combined[32] = hash[0];

    /* Step 3: Slice 264 bits into 24 groups of 11 bits.
     * Each 11-bit value (0-2047) is an index into the 2048-word wordlist.
     * The bit math handles spanning across byte boundaries. */
    unsigned int indices[24];
    for (unsigned int i = 0; i < 24; i++) {
        unsigned int start_bit = i * 11;
        unsigned int byte_pos  = start_bit / 8;
        unsigned int bit_pos   = start_bit % 8;
        if (bit_pos <= 5) {
            /* The 11 bits fit entirely within two bytes */
            unsigned int w = ((unsigned int)combined[byte_pos] << 8) | combined[byte_pos + 1];
            indices[i] = (w >> (5 - bit_pos)) & 0x7FFu;
        } else {
            /* The 11 bits span across three bytes */
            unsigned int w = ((unsigned int)combined[byte_pos] << 16)
                           | ((unsigned int)combined[byte_pos + 1] << 8)
                           | combined[byte_pos + 2];
            indices[i] = (w >> (13 - bit_pos)) & 0x7FFu;
        }
    }

    /* Step 4: Map indices to words and join with spaces.
     * 24 words * up to 8 chars + 23 spaces + null = 215 chars max. */
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

    /* BIP-39 seed derivation: PBKDF2-HMAC-SHA512.
     *
     * The mnemonic is the "password", the salt is the literal string
     * "mnemonic" (optionally followed by a user passphrase).
     * 2048 iterations is the BIP-39 standard. The output is 64 bytes
     * which becomes the BIP-32 master seed.
     *
     * 2048 rounds is deliberately low by modern PBKDF2 standards.
     * The security comes from the large key space of the 24-word
     * mnemonic (128 bits of entropy + 8 bits checksum). */
    int rc = PKCS5_PBKDF2_HMAC(mnemonic, (int)strlen(mnemonic),
                                (const unsigned char *)"mnemonic", 8,
                                2048, EVP_sha512(), 64, seed_out);
    return rc == 1 ? 0 : -1;
}

int keygen_valid_word(const char *word)
{
    /* Linear scan through all 2048 BIP-39 English words.
     * Called once per word during restore, so O(n) is fine. */
    for (unsigned int i = 0; i < 2048u; i++) {
        if (strcmp(wordlist[i], word) == 0) return 1;
    }
    return 0;
}
