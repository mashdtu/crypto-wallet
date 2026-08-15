#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "keygen.h"
#include "wallet.h"
#include "storage.h"

#define DEFAULT_SEED_PATH "seed.enc"

static int cmd_init(void)
{
    if (access(DEFAULT_SEED_PATH, F_OK) == 0) {
        fprintf(stderr, "WARNING: %s already exists. This will overwrite your existing wallet.\n", DEFAULT_SEED_PATH);
        fprintf(stderr, "Type YES to continue: ");
        char answer[8];
        if (!fgets(answer, sizeof(answer), stdin) || strcmp(answer, "YES\n") != 0) {
            fprintf(stderr, "Aborted.\n");
            return 1;
        }
    }

    printf("Generating wallet...\n");

    printf("Sourcing entropy [...]");
    fflush(stdout);

    char mnemonic[216];
    if (keygen_mnemonic(mnemonic, sizeof(mnemonic)) != 0) {
        fprintf(stderr, "\nFailed to generate mnemonic\n");
        return 1;
    }
    printf("\rSourcing entropy [COMPLETE]\n");

    printf("Deriving seed [...]");
    fflush(stdout);

    unsigned char seed[64];
    if (keygen_seed(mnemonic, seed) != 0) {
        fprintf(stderr, "\nFailed to derive seed\n");
        return 1;
    }
    printf("\rDeriving seed [COMPLETE]\n");

    printf("\nWARNING: Write down your mnemonic and store it securely.\n");
    printf("         It will NOT be shown again.\n\n");
    printf("Mnemonic:\n\n");
    /* Print numbered words, 4 per line */
    char mnemonic_copy[216];
    strncpy(mnemonic_copy, mnemonic, sizeof(mnemonic_copy) - 1);
    mnemonic_copy[sizeof(mnemonic_copy) - 1] = '\0';
    char *word = strtok(mnemonic_copy, " ");
    for (int i = 1; word != NULL; i++) {
        printf("  %2d. %-12s", i, word);
        if (i % 4 == 0) printf("\n");
        word = strtok(NULL, " ");
    }
    printf("\n\n");

    /* Wipe mnemonic from stack */
    memset(mnemonic, 0, sizeof(mnemonic));

    /* Show first address */
    char address[73];
    if (wallet_derive_address(seed, 0, address) != 0) {
        fprintf(stderr, "Failed to derive address\n");
        memset(seed, 0, sizeof(seed));
        return 1;
    }

    printf("First receive address (index 0):\n  %s\n", address);

    /* Encrypt and save seed */
    char *pw_buf = getpass("\nSet wallet password: ");
    if (!pw_buf) {
        memset(seed, 0, sizeof(seed));
        return 1;
    }
    char password[256];
    strncpy(password, pw_buf, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    char *confirm = getpass("Confirm password: ");
    if (!confirm || strcmp(password, confirm) != 0) {
        fprintf(stderr, "Passwords do not match\n");
        memset(password, 0, sizeof(password));
        memset(seed, 0, sizeof(seed));
        return 1;
    }

    printf("Encrypting seed [...]");
    fflush(stdout);

    if (storage_encrypt(seed, password, DEFAULT_SEED_PATH) != 0) {
        fprintf(stderr, "\nFailed to write %s\n", DEFAULT_SEED_PATH);
        memset(seed, 0, sizeof(seed));
        return 1;
    }
    printf("\rEncrypting seed [COMPLETE]\n");
    printf("Saved to: %s\n", DEFAULT_SEED_PATH);

    memset(password, 0, sizeof(password));
    memset(seed, 0, sizeof(seed));
    return 0;
}

static int cmd_address(const char *index_str)
{
    unsigned long index = strtoul(index_str, NULL, 10);

    if (access(DEFAULT_SEED_PATH, F_OK) != 0) {
        fprintf(stderr, "error: %s not found -- run 'wallet init' first\n", DEFAULT_SEED_PATH);
        return 1;
    }

    char *password = getpass("Wallet password: ");
    if (!password) return 1;

    unsigned char seed[64];
    if (storage_decrypt(DEFAULT_SEED_PATH, password, seed) != 0) {
        fprintf(stderr, "error: decryption failed (wrong password or corrupt file)\n");
        return 1;
    }

    char address[73];
    if (wallet_derive_address(seed, (uint32_t)index, address) != 0) {
        fprintf(stderr, "error: failed to derive address\n");
        memset(seed, 0, sizeof(seed));
        return 1;
    }

    memset(seed, 0, sizeof(seed));
    printf("%s\n", address);
    return 0;
}

static int cmd_restore(void)
{
    if (access(DEFAULT_SEED_PATH, F_OK) == 0) {
        fprintf(stderr, "WARNING: %s already exists. This will overwrite your existing wallet.\n", DEFAULT_SEED_PATH);
        fprintf(stderr, "Type YES to continue: ");
        char answer[8];
        if (!fgets(answer, sizeof(answer), stdin) || strcmp(answer, "YES\n") != 0) {
            fprintf(stderr, "Aborted.\n");
            return 1;
        }
    }

    printf("Enter your 24 mnemonic words one per line:\n");
    fflush(stdout);

    char mnemonic[216];
    mnemonic[0] = '\0';
    for (int i = 0; i < 24; i++) {
        printf("  Word %2d: ", i + 1);
        fflush(stdout);
        char word[32];
        if (!fgets(word, sizeof(word), stdin)) {
            fprintf(stderr, "Failed to read word %d\n", i + 1);
            memset(mnemonic, 0, sizeof(mnemonic));
            return 1;
        }
        /* Strip newline and whitespace */
        size_t wlen = strlen(word);
        while (wlen > 0 && (word[wlen-1] == '\n' || word[wlen-1] == '\r' || word[wlen-1] == ' '))
            word[--wlen] = '\0';
        if (wlen == 0) {
            fprintf(stderr, "Empty word -- aborted\n");
            memset(mnemonic, 0, sizeof(mnemonic));
            return 1;
        }
        if (!keygen_valid_word(word)) {
            fprintf(stderr, "  '%s' is not in the BIP-39 wordlist -- try again\n", word);
            i--;
            continue;
        }
        if (i > 0) strcat(mnemonic, " ");
        strcat(mnemonic, word);
    }

    printf("Deriving seed [...]");
    fflush(stdout);

    unsigned char seed[64];
    if (keygen_seed(mnemonic, seed) != 0) {
        fprintf(stderr, "\nFailed to derive seed\n");
        memset(mnemonic, 0, sizeof(mnemonic));
        return 1;
    }
    printf("\rDeriving seed [COMPLETE]\n");
    memset(mnemonic, 0, sizeof(mnemonic));

    /* Show first address so the user can verify */
    char address[73];
    if (wallet_derive_address(seed, 0, address) != 0) {
        fprintf(stderr, "Failed to derive address\n");
        memset(seed, 0, sizeof(seed));
        return 1;
    }
    printf("First receive address (index 0):\n  %s\n", address);

    char *pw_buf = getpass("\nSet wallet password: ");
    if (!pw_buf) {
        memset(seed, 0, sizeof(seed));
        return 1;
    }
    char password[256];
    strncpy(password, pw_buf, sizeof(password) - 1);
    password[sizeof(password) - 1] = '\0';

    char *confirm = getpass("Confirm password: ");
    if (!confirm || strcmp(password, confirm) != 0) {
        fprintf(stderr, "Passwords do not match\n");
        memset(password, 0, sizeof(password));
        memset(seed, 0, sizeof(seed));
        return 1;
    }

    printf("Encrypting seed [...]");
    fflush(stdout);

    if (storage_encrypt(seed, password, DEFAULT_SEED_PATH) != 0) {
        fprintf(stderr, "\nFailed to write %s\n", DEFAULT_SEED_PATH);
        memset(password, 0, sizeof(password));
        memset(seed, 0, sizeof(seed));
        return 1;
    }
    printf("\rEncrypting seed [COMPLETE]\n");
    printf("Saved to: %s\n", DEFAULT_SEED_PATH);

    memset(password, 0, sizeof(password));
    memset(seed, 0, sizeof(seed));
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s init             generate a new wallet\n"
            "  %s restore          restore a wallet from a mnemonic\n"
            "  %s address <index>  show receive address at index\n",
            prog, prog, prog);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "init") == 0) {
        return cmd_init();
    }

    if (strcmp(argv[1], "restore") == 0) {
        return cmd_restore();
    }

    if (strcmp(argv[1], "address") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s address <index>\n", argv[0]);
            return 1;
        }
        return cmd_address(argv[2]);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    usage(argv[0]);
    return 1;
}
