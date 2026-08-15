#ifndef KEYGEN_H
#define KEYGEN_H

/*
 * keygen.h - BIP-39 mnemonic and seed generation
 *
 * Generates a 24-word BIP-39 mnemonic from 32 bytes of entropy,
 * then stretches it into a 64-byte BIP-32 seed via PBKDF2-HMAC-SHA512.
 */

/*
 * keygen_mnemonic()
 *
 * Fills mnemonic_out with a null-terminated space-separated 24-word string.
 * mnemonic_out must be at least 216 bytes.
 * Returns 0 on success, -1 on failure.
 */
int keygen_mnemonic(char *mnemonic_out, unsigned int mnemonic_size);

/*
 * keygen_seed()
 *
 * Derives a 64-byte BIP-32 seed from a mnemonic (no passphrase).
 * seed_out must be exactly 64 bytes.
 * Returns 0 on success, -1 on failure.
 */
int keygen_seed(const char *mnemonic, unsigned char *seed_out);

/* Returns 1 if word is in the BIP-39 wordlist, 0 otherwise. */
int keygen_valid_word(const char *word);

#endif
