#define _DEFAULT_SOURCE
#include "storage.h"

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define SALT_LEN   32
#define IV_LEN     12
#define SEED_LEN   64
#define TAG_LEN    16
#define KEY_LEN    32
#define ITER       100000
#define FILE_SIZE  (SALT_LEN + IV_LEN + SEED_LEN + TAG_LEN)

/* Derive a 32-byte AES key from password + salt using PBKDF2-SHA512 */
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

    if (RAND_bytes(salt, SALT_LEN) != 1) return -1;
    if (RAND_bytes(iv,   IV_LEN)   != 1) return -1;

    if (derive_key(password, salt, key) != 0) return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = 1;
    int out_len = 0;

    ok &= EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);
    ok &= EVP_EncryptUpdate(ctx, ciphertext, &out_len, seed, SEED_LEN);
    ok &= EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &out_len);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);

    EVP_CIPHER_CTX_free(ctx);
    memset(key, 0, KEY_LEN);

    if (!ok) return -1;

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

    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    int read_ok = (fread(buf, 1, FILE_SIZE, f) == FILE_SIZE);
    fclose(f);
    if (!read_ok) return -1;

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
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
    ok &= (EVP_DecryptFinal_ex(ctx, seed_out + out_len, &out_len) > 0);

    EVP_CIPHER_CTX_free(ctx);
    memset(key, 0, KEY_LEN);

    if (!ok) {
        memset(seed_out, 0, SEED_LEN);
        return -1;
    }
    return 0;
}
