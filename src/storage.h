#ifndef STORAGE_H
#define STORAGE_H

/*
 * storage.h - AES-256-GCM encrypted seed storage
 *
 * File format (124 bytes total):
 *   [32B salt][12B IV][64B ciphertext][16B auth tag]
 *
 * Key derivation: PBKDF2-SHA512, 100000 iterations, 32-byte output
 */

/*
 * storage_encrypt()
 *
 * Encrypts a 64-byte seed with the given password and writes it to path.
 *
 * seed      [in] 64-byte seed to encrypt
 * password  [in] null-terminated password string
 * path      [in] output file path
 *
 * Returns 0 on success, -1 on failure.
 */
int storage_encrypt(const unsigned char *seed,
                    const char *password,
                    const char *path);

/*
 * storage_decrypt()
 *
 * Reads the encrypted file at path and decrypts it into seed_out.
 *
 * path      [in]  file path to read
 * password  [in]  null-terminated password string
 * seed_out  [out] 64-byte buffer to receive the decrypted seed
 *
 * Returns 0 on success, -1 on failure (wrong password, corrupt file, etc).
 */
int storage_decrypt(const char *path,
                    const char *password,
                    unsigned char *seed_out);

#endif /* STORAGE_H */
