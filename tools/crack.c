/*
 * tools/crack.c - password auditing tool for seed.enc files
 *
 * Reads a wallet seed.enc file (the raw 124-byte encrypted blob) and tries
 * passwords from a wordlist file, one per line. Uses the exact same
 * PBKDF2-HMAC-SHA512 + AES-256-GCM algorithm as the wallet itself.
 *
 * Uses all available CPU cores in parallel to maximize speed.
 *
 * Usage:
 *   ./crack <seed.enc> <wordlist.txt>
 *   sudo dd if=/dev/sdX bs=124 count=1 of=/tmp/seed.enc
 *   ./crack /tmp/seed.enc wordlist.txt
 *
 * Build:
 *   gcc -O2 -pthread -o crack crack.c $(pkg-config --cflags --libs openssl)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>
#include <openssl/evp.h>

#define SALT_LEN   32
#define IV_LEN     12
#define SEED_LEN   64
#define TAG_LEN    16
#define KEY_LEN    32
#define ITER       100000
#define FILE_SIZE  (SALT_LEN + IV_LEN + SEED_LEN + TAG_LEN)     /* 124 bytes */
#define MAX_PASS   512

/* Shared state between all threads */
static unsigned char g_blob[FILE_SIZE];
static FILE         *g_wordlist;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static atomic_int    g_found   = 0;
static atomic_llong  g_count   = 0;
static char          g_found_password[MAX_PASS];

/*
 * next_password() - thread-safe: grab the next line from the wordlist.
 * Returns 1 on success, 0 on EOF or after password found.
 */
static int next_password(char *buf, size_t bufsz)
{
    if (atomic_load(&g_found)) return 0;

    pthread_mutex_lock(&g_mutex);
    char *r = fgets(buf, (int)bufsz, g_wordlist);
    pthread_mutex_unlock(&g_mutex);

    if (!r) return 0;

    /* Strip trailing newline/whitespace */
    size_t len = strlen(buf);
    while (len > 0 && (buf[len-1] == '\n' || buf[len-1] == '\r' || buf[len-1] == ' '))
        buf[--len] = '\0';

    if (len == 0) return next_password(buf, bufsz);     /* skip blank lines */
    return 1;
}

/*
 * try_password() - returns 1 if the password decrypts the blob (GCM tag matches).
 */
static int try_password(const char *password)
{
    const unsigned char *salt       = g_blob;
    const unsigned char *iv         = g_blob + SALT_LEN;
    const unsigned char *ciphertext = g_blob + SALT_LEN + IV_LEN;
    unsigned char tag[TAG_LEN];
    memcpy(tag, g_blob + SALT_LEN + IV_LEN + SEED_LEN, TAG_LEN);

    unsigned char key[KEY_LEN];
    int rc = PKCS5_PBKDF2_HMAC(password, (int)strlen(password),
                                salt, SALT_LEN,
                                ITER, EVP_sha512(),
                                KEY_LEN, key);
    if (rc != 1) return 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { memset(key, 0, KEY_LEN); return 0; }

    int ok = 1, out_len = 0;
    unsigned char plaintext[SEED_LEN];

    ok &= EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    ok &= EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    ok &= EVP_DecryptUpdate(ctx, plaintext, &out_len, ciphertext, SEED_LEN);
    ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
    ok &= (EVP_DecryptFinal_ex(ctx, plaintext + out_len, &out_len) > 0);

    EVP_CIPHER_CTX_free(ctx);
    memset(key, 0, KEY_LEN);
    memset(plaintext, 0, SEED_LEN);

    return ok;
}

static void *worker(void *arg)
{
    (void)arg;
    char pass[MAX_PASS];

    while (next_password(pass, sizeof(pass))) {
        long long n = atomic_fetch_add(&g_count, 1) + 1;

        if (n % 50 == 0) {
            fprintf(stderr, "\r  Tried %lld passwords...", n);
            fflush(stderr);
        }

        if (try_password(pass)) {
            /* First thread to find it wins */
            int expected = 0;
            if (atomic_compare_exchange_strong(&g_found, &expected, 1)) {
                strncpy(g_found_password, pass, MAX_PASS - 1);
                g_found_password[MAX_PASS - 1] = '\0';
            }
            return NULL;
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <seed.enc> <wordlist.txt>\n", argv[0]);
        fprintf(stderr, "\n");
        fprintf(stderr, "To extract from USB:\n");
        fprintf(stderr, "  sudo dd if=/dev/sdX bs=124 count=1 of=/tmp/seed.enc\n");
        return 1;
    }

    /* Read the 124-byte encrypted blob */
    FILE *ef = fopen(argv[1], "rb");
    if (!ef) { perror(argv[1]); return 1; }
    if (fread(g_blob, 1, FILE_SIZE, ef) != FILE_SIZE) {
        fprintf(stderr, "error: %s is not a valid seed.enc (expected %d bytes)\n",
                argv[1], FILE_SIZE);
        fclose(ef); return 1;
    }
    fclose(ef);

    /* Open wordlist */
    g_wordlist = fopen(argv[2], "r");
    if (!g_wordlist) { perror(argv[2]); return 1; }

    /* Determine thread count from CPU cores */
    int nthreads = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (nthreads < 1) nthreads = 1;

    fprintf(stderr, "Cracking %s using %d threads...\n", argv[1], nthreads);
    fprintf(stderr, "(PBKDF2-SHA512 x100000 per guess)\n\n");

    pthread_t *threads = malloc((size_t)nthreads * sizeof(pthread_t));
    for (int i = 0; i < nthreads; i++)
        pthread_create(&threads[i], NULL, worker, NULL);
    for (int i = 0; i < nthreads; i++)
        pthread_join(threads[i], NULL);
    free(threads);

    fclose(g_wordlist);

    long long total = atomic_load(&g_count);
    fprintf(stderr, "\n");

    if (atomic_load(&g_found)) {
        printf("Password found after %lld guesses:\n\n  %s\n\n", total, g_found_password);
        return 0;
    }

    fprintf(stderr, "Not found after %lld passwords.\n", total);
    return 1;
}
