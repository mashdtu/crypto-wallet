#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>

#include "keygen.h"
#include "wallet.h"
#include "storage.h"

static char seed_path[512];

/* Scan /sys/block for removable block devices.
 * Writes the first found device path (e.g. /dev/sda) into dev_out.
 * Returns 1 if found, 0 otherwise. */
static int find_usb_device(char *dev_out, size_t dev_size)
{
    DIR *bd = opendir("/sys/block");
    if (!bd) return 0;

    struct dirent *be;
    while ((be = readdir(bd)) != NULL) {
        if (strncmp(be->d_name, "sd", 2) != 0) continue;

        char rem[128];
        snprintf(rem, sizeof(rem), "/sys/block/%s/removable", be->d_name);
        FILE *f = fopen(rem, "r");
        if (!f) continue;
        char val[4] = {0};
        if (!fgets(val, sizeof(val), f)) { fclose(f); continue; }
        fclose(f);
        if (val[0] != '1') continue;

        snprintf(dev_out, dev_size, "/dev/%s", be->d_name);
        closedir(bd);
        return 1;
    }
    closedir(bd);
    return 0;
}

static void init_seed_path(void)
{
    char dev[64];
    if (!find_usb_device(dev, sizeof(dev))) {
        fprintf(stderr, "error: no USB drive found -- insert your wallet USB and try again\n");
        exit(1);
    }
    snprintf(seed_path, sizeof(seed_path), "%s", dev);
}

#define DEFAULT_SEED_PATH seed_path

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
            "  %s [--file <path>] init             generate a new wallet\n"
            "  %s [--file <path>] restore          restore a wallet from a mnemonic\n"
            "  %s [--file <path>] address <index>  show receive address at index\n"
            "  %s usb-format                       wipe a USB drive for use as a wallet key\n"
            "  %s eject                            safely eject the wallet USB\n"
            "\n"
            "  --file <path>  use a specific raw device or file instead of auto-detected USB\n",
            prog, prog, prog, prog, prog);
}

static int cmd_eject(void)
{
    char dev[64];
    if (!find_usb_device(dev, sizeof(dev))) {
        fprintf(stderr, "error: no USB drive found\n");
        return 1;
    }

    printf("Flushing writes [...]");
    fflush(stdout);
    sync();
    printf("\rFlushing writes [COMPLETE]\n");

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "udisksctl power-off -b %s", dev);
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "Power-off failed -- you may need to install udisks2\n");
        return 1;
    }
    printf("Safe to remove USB.\n");
    return 0;
}

static int cmd_usb_format(void)
{
    /* Scan /sys/block for removable block devices */
    char devs[8][64];
    char sizes[8][32];
    int count = 0;

    DIR *bd = opendir("/sys/block");
    if (!bd) {
        fprintf(stderr, "Cannot scan /sys/block\n");
        return 1;
    }
    struct dirent *be;
    while ((be = readdir(bd)) != NULL && count < 8) {
        if (strncmp(be->d_name, "sd", 2) != 0) continue;

        char rem[128];
        snprintf(rem, sizeof(rem), "/sys/block/%s/removable", be->d_name);
        FILE *f = fopen(rem, "r");
        if (!f) continue;
        char val[4] = {0};
        if (!fgets(val, sizeof(val), f)) { fclose(f); continue; }
        fclose(f);
        if (val[0] != '1') continue;

        char szpath[128];
        snprintf(szpath, sizeof(szpath), "/sys/block/%s/size", be->d_name);
        FILE *sf = fopen(szpath, "r");
        unsigned long long sectors = 0;
        if (sf) { fscanf(sf, "%llu", &sectors); fclose(sf); }
        unsigned long long mb = (sectors * 512ULL) / (1024ULL * 1024ULL);

        snprintf(devs[count],  sizeof(devs[count]),  "/dev/%s", be->d_name);
        snprintf(sizes[count], sizeof(sizes[count]), "%llu MB", mb);
        count++;
    }
    closedir(bd);

    if (count == 0) {
        fprintf(stderr, "No removable USB devices found\n");
        return 1;
    }

    printf("Removable devices:\n");
    for (int i = 0; i < count; i++)
        printf("  %d. %s  (%s)\n", i + 1, devs[i], sizes[i]);

    printf("\nSelect device to format (1-%d): ", count);
    fflush(stdout);
    char pick[8];
    if (!fgets(pick, sizeof(pick), stdin)) return 1;
    int sel = atoi(pick);
    if (sel < 1 || sel > count) {
        fprintf(stderr, "Invalid selection\n");
        return 1;
    }

    const char *dev   = devs[sel - 1];
    const char *dsize = sizes[sel - 1];

    fprintf(stderr,
            "\nWARNING: ALL DATA on %s (%s) will be permanently erased.\n"
            "         The raw device will be used to store the encrypted seed.\n"
            "Type YES to continue: ", dev, dsize);
    fflush(stderr);

    char answer[8];
    if (!fgets(answer, sizeof(answer), stdin) || strcmp(answer, "YES\n") != 0) {
        fprintf(stderr, "Aborted.\n");
        return 1;
    }

    /* Unmount any mounted partitions */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "umount %s?* %s 2>/dev/null; true", dev, dev);
    system(cmd);

    /* Wipe all signatures and partition tables */
    printf("Wiping %s [...]", dev);
    fflush(stdout);
    snprintf(cmd, sizeof(cmd), "wipefs -a %s", dev);
    int rc = system(cmd);
    if (rc != 0) {
        fprintf(stderr, "\nWipe failed -- try running as root (sudo)\n");
        return 1;
    }
    printf("\rWiping %s [COMPLETE]\n", dev);
    printf("USB is ready. Run 'sudo wallet init' to write your wallet to it.\n");
    return 0;
}

int main(int argc, char *argv[])
{
    /* Parse optional --file override before the command */
    int argi = 1;
    int path_set = 0;
    if (argc > 2 && strcmp(argv[1], "--file") == 0) {
        snprintf(seed_path, sizeof(seed_path), "%s", argv[2]);
        fprintf(stderr, "Using seed file: %s\n", seed_path);
        argi = 3;
        path_set = 1;
    }

    if (argc <= argi) {
        usage(argv[0]);
        return 1;
    }

    /* usb-format operates on unmounted block devices -- no seed path needed */
    if (strcmp(argv[argi], "usb-format") == 0) {
        return cmd_usb_format();
    }

    if (strcmp(argv[argi], "eject") == 0) {
        return cmd_eject();
    }

    if (!path_set) init_seed_path();

    if (strcmp(argv[argi], "init") == 0) {
        return cmd_init();
    }

    if (strcmp(argv[argi], "restore") == 0) {
        return cmd_restore();
    }

    if (strcmp(argv[argi], "address") == 0) {
        if (argc <= argi + 1) {
            fprintf(stderr, "Usage: %s address <index>\n", argv[0]);
            return 1;
        }
        return cmd_address(argv[argi + 1]);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[argi]);
    usage(argv[0]);
    return 1;
}
