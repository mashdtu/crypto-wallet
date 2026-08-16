/*
 * storage.c - AES-256-GCM encrypted seed storage on raw block devices
 *
 * This is the security-critical layer of the wallet. It takes the raw
 * 64-byte seed and writes an encrypted, authenticated blob directly to
 * a block device (the USB drive), with no filesystem in the way.
 *
 * On-disk format (124 bytes total, at offset 0 of the device):
 *
 *   [0  .. 31]  salt        (32 bytes, random)
 *   [32 .. 43]  IV / nonce  (12 bytes, random)
 *   [44 .. 107] ciphertext  (64 bytes, encrypted seed)
 *   [108.. 123] auth tag    (16 bytes, GCM integrity tag)
 *
 * Key derivation: PBKDF2-HMAC-SHA512(password, salt, 100000 rounds) -> 32 bytes.
 * 100k rounds means ca. 1 second on a fast machine, making password brute-force
 * expensive enough to matter even if someone steals the USB.
 *
 * The salt is random and stored alongside the ciphertext, so the same password
 * on two different USB drives produces different ciphertexts.
 */

#define _DEFAULT_SOURCE
#include "storage.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_LEN   32       /* salt for PBKDF2 */
#define IV_LEN     12       /* GCM nonce -- 96 bits is the recommended size */
#define SEED_LEN   64       /* BIP-32 seed */
#define TAG_LEN    16       /* GCM authentication tag */
#define KEY_LEN    32       /* AES-256 key */
#define ITER       100000   /* PBKDF2 iterations -- ~1 second on modern hardware */
#define FILE_SIZE  (SALT_LEN + IV_LEN + SEED_LEN + TAG_LEN)     /* 124 bytes */

/*
 * derive_key()
 *
 * Stretches a human-entered password into a 32-byte AES key.
 * The salt ensures that the same password produces different keys on
 * different USB drives (or after re-init), preventing precomputation attacks.
 *
 * SHA-512 is used as the HMAC primitive because it's faster than SHA-256
 * on 64-bit hardware and produces a larger internal state.
 */
static int derive_key(const char *password,
                      const unsigned char *salt,
                      unsigned char *key_out)
{
    int rc = PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                                salt, SALT_LEN,
                                ITER, EVP_sha512(),
                                KEY_LEN, key_out);
    return rc == 1 ? 0 : -1;
}

int storage_encrypt(const unsigned char *seed,
                    const char *password,
                    const char *path)
{
    unsigned char salt[SALT_LEN];
    unsigned char iv[IV_LEN];
    unsigned char key[KEY_LEN];
    unsigned char ciphertext[SEED_LEN];
    unsigned char tag[TAG_LEN];

    /* Generate fresh random salt and IV for this encryption.
     * Using a new random salt every time means we also get a new AES key
     * even if the password hasn't changed. */
    if (RAND_bytes(salt, SALT_LEN) != 1) return -1;
    if (RAND_bytes(iv,   IV_LEN)   != 1) return -1;

    if (derive_key(password, salt, key) != 0) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 1;
    int out_len = 0;

    /* Two-phase init: first set the cipher algorithm, then provide key+IV.
     * This is the OpenSSL way of setting GCM parameters. */
    ok &= EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    ok &= EVP_EncryptUpdate(ctx, ciphertext, &out_len, seed, SEED_LEN);
    ok &= EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &out_len);
    /* Extract the 16-byte GCM tag after finalising. Must be done after Final */
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);

    EVP_CIPHER_CTX_free(ctx);
    /* Wipe the key from the stack immediately after use */
    memset(key, 0, KEY_LEN);

    if (!ok) return -1;

    /* Write all four fields in order to the device/file.
     * fopen("wb") on a raw block device works fine on Linux. */
    FILE *f = fopen(path, "wb");
    if (!f) return -1;

    int wrote =
        (fwrite(salt,       1, SALT_LEN, f) == SALT_LEN) &&
        (fwrite(iv,         1, IV_LEN,   f) == IV_LEN)   &&
        (fwrite(ciphertext, 1, SEED_LEN, f) == SEED_LEN) &&
        (fwrite(tag,        1, TAG_LEN,  f) == TAG_LEN);

    fclose(f);
    return wrote ? 0 : -1;
}

int storage_decrypt(const char *path,
                    const char *password,
                    unsigned char *seed_out)
{
    unsigned char buf[FILE_SIZE];

    /* Read exactly 124 bytes from offset 0 */
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    int read_ok = (fread(buf, 1, FILE_SIZE, f) == FILE_SIZE);
    fclose(f);
    if (!read_ok) return -1;

    /* Split the buffer into its four fields */
    unsigned char *salt       = buf;
    unsigned char *iv         = buf + SALT_LEN;
    unsigned char *ciphertext = buf + SALT_LEN + IV_LEN;
    unsigned char *tag        = buf + SALT_LEN + IV_LEN + SEED_LEN;

    unsigned char key[KEY_LEN];
    if (derive_key(password, salt, key) != 0) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { memset(key, 0, KEY_LEN); return -1; }

    int ok = 1;
    int out_len = 0;

    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    ok &= EVP_DecryptUpdate(ctx, seed_out, &out_len, ciphertext, SEED_LEN);
    /* Set the expected tag BEFORE calling Final so GCM can verify it */
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
    /* Final returns <= 0 if the tag doesn't match (auth check) */
    ok &= (EVP_DecryptFinal_ex(ctx, seed_out + out_len, &out_len) > 0);

    EVP_CIPHER_CTX_free(ctx);
    memset(key, 0, KEY_LEN);

    if (!ok) {
        /* Authentication failed: wrong password or corrupted data.
         * Zero the output so we never hand back partial plaintext. */
        memset(seed_out, 0, SEED_LEN);
        return -1;
    }
    return 0;
}
