#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>

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

        char rem[512];
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
    char dev[512];
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

#include "network.h"
#include "tx.h"
#include "bech32.h"

#define GAP_LIMIT 20
#define DUST_LIMIT 546

/* Format a uint64_t with comma separators into buf. Returns buf. */
static char *fmt_sat(uint64_t v, char *buf, size_t bufsz)
{
    char tmp[32];
    int len = snprintf(tmp, sizeof(tmp), "%llu", (unsigned long long)v);
    int out = 0;
    for (int i = 0; i < len && out < (int)bufsz - 1; i++) {
        if (i > 0 && (len - i) % 3 == 0)
            buf[out++] = ',';
        buf[out++] = tmp[i];
    }
    buf[out] = '\0';
    return buf;
}

/* Format a fiat amount with commas and 2 decimal places, e.g. "USD 1,234.56" */
static char *fmt_fiat(double amount, const char *currency, char *buf, size_t bufsz)
{
    long long cents = (long long)(amount * 100.0 + 0.5);
    long long whole = cents / 100;
    int frac = (int)(cents % 100);
    char w[32];
    fmt_sat((uint64_t)(whole < 0 ? 0 : whole), w, sizeof(w));
    snprintf(buf, bufsz, "%s %s.%02d", currency, w, frac);
    return buf;
}

/* Settings: store currency preference in ~/.config/btc-wallet/currency */
static const char *settings_path(void)
{
    static char path[512];
    /* Under sudo, HOME is /root — use the real user's home instead */
    const char *home = getenv("SUDO_USER") ? NULL : getenv("HOME");
    if (!home) {
        const char *sudo_user = getenv("SUDO_USER");
        if (sudo_user) {
            char pw_buf[256];
            snprintf(pw_buf, sizeof(pw_buf), "/home/%s", sudo_user);
            home = pw_buf;
            snprintf(path, sizeof(path), "%s/.config/btc-wallet/currency", pw_buf);
            return path;
        }
        home = "/tmp";
    }
    snprintf(path, sizeof(path), "%s/.config/btc-wallet/currency", home);
    return path;
}

static void settings_get_currency(char *out, size_t outsz)
{
    FILE *f = fopen(settings_path(), "r");
    if (!f) { strncpy(out, "NONE", outsz); return; }
    if (!fgets(out, (int)outsz, f)) strncpy(out, "NONE", outsz);
    fclose(f);
    out[strcspn(out, "\r\n")] = '\0';
}

static int cmd_settings(void)
{
    static const char *currencies[] = {
        "USD", "EUR", "GBP", "CAD", "CHF", "AUD", "JPY"
    };
    static const int ncurrencies = 7;

    char cur[16];
    settings_get_currency(cur, sizeof(cur));
    printf("Current currency display: %s\n\n", cur);
    printf("Select display currency:\n");
    for (int i = 0; i < ncurrencies; i++)
        printf("  %d. %s\n", i + 1, currencies[i]);
    printf("  %d. None\n", ncurrencies + 1);
    printf("Choice (1-%d): ", ncurrencies + 1);
    fflush(stdout);

    char ans[8];
    if (!fgets(ans, sizeof(ans), stdin)) return 1;
    int choice = (int)strtol(ans, NULL, 10);

    const char *selected;
    if (choice >= 1 && choice <= ncurrencies)
        selected = currencies[choice - 1];
    else
        selected = "NONE";

    /* Ensure ~/.config/btc-wallet/ exists */
    const char *home = getenv("HOME");
    if (home) {
        char dir[512];
        snprintf(dir, sizeof(dir), "%s/.config", home);
        mkdir(dir, 0700);
        snprintf(dir, sizeof(dir), "%s/.config/btc-wallet", home);
        mkdir(dir, 0700);
    }

    FILE *f = fopen(settings_path(), "w");
    if (!f) { fprintf(stderr, "error: could not save settings\n"); return 1; }
    fprintf(f, "%s\n", selected);
    fclose(f);
    printf("Currency display set to %s.\n", selected);
    return 0;
}

/* Returns the index if address belongs to this seed, -1 otherwise. */
static int address_index_in_wallet(const unsigned char *seed,
                                   const char *target,
                                   uint32_t max_index)
{
    for (uint32_t i = 0; i < max_index; i++) {
        char address[73];
        if (wallet_derive_address(seed, i, address) != 0) return -1;
        if (strcmp(address, target) == 0) return (int)i;
    }
    return -1;
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

static int cmd_balance(uint32_t gap_limit)
{
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

    int64_t total = 0;
    int gap = 0;
    uint32_t index = 0;
    int on_dot_line = 0;

    printf("Scanning addresses\n");
    fflush(stdout);

    for (;;) {
        char address[73];
        if (wallet_derive_address(seed, index, address) != 0) {
            fprintf(stderr, "\nerror: failed to derive address at index %u\n", index);
            memset(seed, 0, sizeof(seed));
            return 1;
        }

        int64_t bal = network_get_balance(address);
        if (bal < 0) {
            fprintf(stderr, "\nerror: network request failed for index %u\n", index);
            memset(seed, 0, sizeof(seed));
            return 1;
        }

        if (bal > 0) {
            if (on_dot_line) { printf("\n"); on_dot_line = 0; }
            printf("  [%u] %s  %lld sat\n", index, address, (long long)bal);
            fflush(stdout);
            total += bal;
            gap = 0;
        } else {
            printf(".");
            fflush(stdout);
            on_dot_line = 1;
            gap++;
            if (gap >= gap_limit) break;
        }
        index++;
    }

    memset(seed, 0, sizeof(seed));

    char currency[16];
    settings_get_currency(currency, sizeof(currency));
    double btc_price = 0.0;
    int have_price = (strcmp(currency, "NONE") != 0)
                     && (network_get_btc_price(currency, &btc_price) == 0);

    char s_total[32];
    fmt_sat((uint64_t)(total < 0 ? 0 : total), s_total, sizeof(s_total));
    printf("\nTotal balance: %s sat", s_total);
    if (total > 0) {
        printf(" (%.8f tBTC)", (double)total / 100000000.0);
        if (have_price) {
            char f_total[32];
            fmt_fiat((double)total / 1e8 * btc_price, currency, f_total, sizeof(f_total));
            printf(" (~%s)", f_total);
        }
    }
    printf("\n");
    return 0;
}

static int cmd_send(const char *dest_addr, const char *amount_str, const char *fee_str)
{
    uint64_t amount_sat = (uint64_t)strtoull(amount_str, NULL, 10);
    uint64_t fee_sat    = fee_str ? (uint64_t)strtoull(fee_str, NULL, 10) : 1000u;

    if (amount_sat == 0) {
        fprintf(stderr, "error: invalid amount\n");
        return 1;
    }

    /* Decode destination address */
    char dest_hrp[16];
    unsigned char dest_prog[40];
    size_t dest_prog_len = 0;
    int dest_witver = segwit_addr_decode(dest_addr, dest_hrp, dest_prog, &dest_prog_len);
    if (dest_witver < 0
        || (dest_prog_len != 20 && dest_prog_len != 32)
        || (dest_witver == 0 && dest_prog_len != 20)
        || (dest_witver == 1 && dest_prog_len != 32)) {
        fprintf(stderr, "error: invalid destination address\n");
        return 1;
    }
    (void)dest_witver;

    if (access(DEFAULT_SEED_PATH, F_OK) != 0) {
        fprintf(stderr, "error: %s not found -- run 'wallet init' first\n", DEFAULT_SEED_PATH);
        return 1;
    }

    char *password = getpass("Wallet password: ");
    if (!password) return 1;
    printf("\n");

    unsigned char seed[64];
    if (storage_decrypt(DEFAULT_SEED_PATH, password, seed) != 0) {
        fprintf(stderr, "error: decryption failed\n");
        return 1;
    }

    /* Derive key at index 0 */
    unsigned char privkey[32], pubkey[33], our_hash160[20];
    if (wallet_derive_key(seed, 0, privkey, pubkey, our_hash160) != 0) {
        fprintf(stderr, "error: key derivation failed\n");
        memset(seed, 0, sizeof(seed));
        return 1;
    }

    /* Encode our address from hash160 */
    char our_address[73];
    if (segwit_addr_encode(our_address, "bc", 0, our_hash160, 20) != 1) {
        fprintf(stderr, "error: address encoding failed\n");
        memset(seed, 0, sizeof(seed));
        memset(privkey, 0, 32);
        return 1;
    }

    /* Fetch UTXOs */
    tx_utxo_t utxos[64];
    int n_utxos = network_get_utxos(our_address, (utxo_t *)utxos, 64);
    if (n_utxos < 0) {
        fprintf(stderr, "error: failed to fetch UTXOs\n");
        memset(seed, 0, sizeof(seed));
        memset(privkey, 0, 32);
        return 1;
    }
    if (n_utxos == 0) {
        fprintf(stderr, "error: no UTXOs found\n");
        memset(seed, 0, sizeof(seed));
        memset(privkey, 0, 32);
        return 1;
    }

    /* Sum inputs */
    uint64_t total_in = 0;
    for (int i = 0; i < n_utxos; i++) total_in += utxos[i].value;

    if (total_in < amount_sat + fee_sat) {
        fprintf(stderr, "error: insufficient funds (%llu sat available, need %llu + %llu fee)\n",
                (unsigned long long)total_in,
                (unsigned long long)amount_sat,
                (unsigned long long)fee_sat);
        memset(seed, 0, sizeof(seed));
        memset(privkey, 0, 32);
        return 1;
    }

    uint64_t change_sat = total_in - amount_sat - fee_sat;
    if (change_sat < DUST_LIMIT) {
        fee_sat += change_sat;
        change_sat = 0;
    }

    /* Check address ownership while seed is still live */
    int dest_idx = address_index_in_wallet(seed, dest_addr, 1000);
    memset(seed, 0, sizeof(seed));

    /* Fetch dest balance for display */
    int64_t to_bal_before = network_get_balance(dest_addr);
    if (to_bal_before < 0) to_bal_before = 0;

    uint64_t from_bal_before = total_in;
    uint64_t from_bal_after  = change_sat;
    uint64_t to_bal_after    = (uint64_t)to_bal_before + amount_sat;

    char s_send[32], s_fee[32], s_fromb[32], s_froma[32], s_tob[32], s_toa[32];
    fmt_sat(amount_sat,      s_send,  sizeof(s_send));
    fmt_sat(fee_sat,         s_fee,   sizeof(s_fee));
    fmt_sat(from_bal_before, s_fromb, sizeof(s_fromb));
    fmt_sat(from_bal_after,  s_froma, sizeof(s_froma));
    fmt_sat((uint64_t)to_bal_before, s_tob, sizeof(s_tob));
    fmt_sat(to_bal_after,    s_toa,   sizeof(s_toa));

    /* Fetch fiat price if configured */
    char currency[16];
    settings_get_currency(currency, sizeof(currency));
    double btc_price = 0.0;
    int have_price = (strcmp(currency, "NONE") != 0)
                     && (network_get_btc_price(currency, &btc_price) == 0);

    #define TO_FIAT(sat) ((double)(sat) / 1e8 * btc_price)

    char f_send[32]  = "", f_fee[32]  = "";
    char f_fromb[32] = "", f_froma[32] = "";
    char f_tob[32]   = "", f_toa[32]   = "";
    if (have_price) {
        fmt_fiat(TO_FIAT(amount_sat),          currency, f_send,  sizeof(f_send));
        fmt_fiat(TO_FIAT(fee_sat),             currency, f_fee,   sizeof(f_fee));
        fmt_fiat(TO_FIAT(from_bal_before),     currency, f_fromb, sizeof(f_fromb));
        fmt_fiat(TO_FIAT(from_bal_after),      currency, f_froma, sizeof(f_froma));
        fmt_fiat(TO_FIAT((uint64_t)to_bal_before), currency, f_tob, sizeof(f_tob));
        fmt_fiat(TO_FIAT(to_bal_after),        currency, f_toa,   sizeof(f_toa));
    }
    #undef TO_FIAT

    /* build fiat suffix strings for reuse */
    char suf_send[64]  = "";
    char suf_fee[64]   = "";
    char suf_fromb[64] = "";
    char suf_froma[64] = "";
    char suf_tob[64]   = "";
    char suf_toa[64]   = "";
    if (have_price) {
        snprintf(suf_send,  sizeof(suf_send),  " (~%s)", f_send);
        snprintf(suf_fee,   sizeof(suf_fee),   " (~%s)", f_fee);
        snprintf(suf_fromb, sizeof(suf_fromb), " (~%s)", f_fromb);
        snprintf(suf_froma, sizeof(suf_froma), " (~%s)", f_froma);
        snprintf(suf_tob,   sizeof(suf_tob),   " (~%s)", f_tob);
        snprintf(suf_toa,   sizeof(suf_toa),   " (~%s)", f_toa);
    }

    printf("Sending:  %s sat%s\n", s_send, suf_send);
    printf("Fee:      %s sat%s\n\n", s_fee, suf_fee);
    printf("From:     %s  (yours, index 0)\n          %s sat%s -> %s sat%s\n\n",
           our_address, s_fromb, suf_fromb, s_froma, suf_froma);
    if (dest_idx >= 0)
        printf("To:       %s  (yours, index %d)\n          %s sat%s -> %s sat%s\n",
               dest_addr, dest_idx, s_tob, suf_tob, s_toa, suf_toa);
    else
        printf("To:       %s  (external)\n          %s sat%s -> %s sat%s\n",
               dest_addr, s_tob, suf_tob, s_toa, suf_toa);
    printf("\nConfirm? (yes/no): ");
    fflush(stdout);

    char ans[8];
    if (!fgets(ans, sizeof(ans), stdin) || (ans[0] != 'y' && ans[0] != 'Y')) {
        printf("Aborted.\n");
        memset(privkey, 0, 32);
        return 1;
    }

    /* Build and sign */
    char tx_hex[8192];
    if (tx_build_sign(utxos, n_utxos,
                      dest_prog, dest_prog_len, amount_sat,
                      change_sat > 0 ? our_hash160 : NULL, change_sat,
                      privkey, pubkey,
                      tx_hex, sizeof(tx_hex)) != 0) {
        fprintf(stderr, "error: transaction build/sign failed\n");
        memset(privkey, 0, 32);
        return 1;
    }
    memset(privkey, 0, 32);

    printf("Broadcasting [...]");
    fflush(stdout);

    char txid[65] = {0};
    if (network_broadcast(tx_hex, txid) != 0) {
        fprintf(stderr, "\nerror: broadcast failed\n");
        return 1;
    }
    printf("\rBroadcasting [COMPLETE]\n");
    printf("txid: %s\n", txid);
    printf("https://mempool.space/tx/%s\n", txid);
    return 0;
}

/* Returns the index if address belongs to this seed, -1 otherwise.
 * Scans up to max_index addresses. */

static int cmd_check(const char *target)
{
    if (access(DEFAULT_SEED_PATH, F_OK) != 0) {
        fprintf(stderr, "error: %s not found -- run 'wallet init' first\n", DEFAULT_SEED_PATH);
        return 1;
    }

    char *password = getpass("Wallet password: ");
    if (!password) return 1;

    unsigned char seed[64];
    if (storage_decrypt(DEFAULT_SEED_PATH, password, seed) != 0) {
        fprintf(stderr, "error: decryption failed\n");
        return 1;
    }

    printf("Scanning...");
    fflush(stdout);

    for (uint32_t i = 0; i < 10000u; i++) {
        char address[73];
        if (wallet_derive_address(seed, i, address) != 0) {
            fprintf(stderr, "\nerror: derivation failed at index %u\n", i);
            memset(seed, 0, sizeof(seed));
            return 1;
        }
        if (strcmp(address, target) == 0) {
            memset(seed, 0, sizeof(seed));
            printf("\rAddress belongs to this wallet (index %u).\n", i);
            return 0;
        }
    }

    memset(seed, 0, sizeof(seed));
    printf("\rAddress does NOT belong to this wallet (checked 10000 indices).\n");
    return 1;
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

#define SEED_ENC_SIZE 124  /* 32 salt + 12 IV + 64 ciphertext + 16 tag */

static int cmd_clone(void)
{
    char src_dev[512];
    if (!find_usb_device(src_dev, sizeof(src_dev))) {
        fprintf(stderr, "error: no USB drive found\n");
        return 1;
    }

    /* Read encrypted seed from source USB */
    unsigned char enc[SEED_ENC_SIZE];
    FILE *f = fopen(src_dev, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open %s: %s\n", src_dev, strerror(errno));
        return 1;
    }
    if (fread(enc, 1, SEED_ENC_SIZE, f) != SEED_ENC_SIZE) {
        fprintf(stderr, "error: read failed from %s\n", src_dev);
        fclose(f);
        return 1;
    }
    fclose(f);
    printf("Read encrypted seed from %s\n", src_dev);

    /* Step 1: wait for the source USB to be removed */
    printf("Remove the USB drive now...\n");
    fflush(stdout);
    for (;;) {
        sleep(1);
        char tmp[512];
        int present = find_usb_device(tmp, sizeof(tmp)) && strcmp(tmp, src_dev) == 0;
        if (!present)
            break;
    }
    printf("USB removed.\n");

    /* Step 2: wait for the target USB to be inserted */
    printf("Insert the target USB now...\n");
    fflush(stdout);
    char dst_dev[512];
    int found = 0;
    for (int attempts = 0; attempts < 60; attempts++) {
        sleep(1);
        if (find_usb_device(dst_dev, sizeof(dst_dev))) {
            found = 1;
            break;
        }
    }
    if (!found) {
        fprintf(stderr, "error: no USB drive detected after 60 seconds\n");
        return 1;
    }
    printf("Detected target USB: %s\n", dst_dev);

    printf("WARNING: this will overwrite the first %d bytes of %s.\n", SEED_ENC_SIZE, dst_dev);
    printf("Type YES to continue: ");
    fflush(stdout);
    char ans[8];
    if (!fgets(ans, sizeof(ans), stdin) || strcmp(ans, "YES\n") != 0) {
        printf("Aborted.\n");
        return 1;
    }

    FILE *g = fopen(dst_dev, "wb");
    if (!g) {
        fprintf(stderr, "error: cannot open %s: %s\n", dst_dev, strerror(errno));
        return 1;
    }
    if (fwrite(enc, 1, SEED_ENC_SIZE, g) != SEED_ENC_SIZE) {
        fprintf(stderr, "error: write failed to %s\n", dst_dev);
        fclose(g);
        return 1;
    }
    fflush(g);
    fclose(g);
    sync();

    printf("Written to %s. Clone complete.\n", dst_dev);
    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s [--file <path>] init                          generate a new wallet\n"
            "  %s [--file <path>] restore                       restore a wallet from a mnemonic\n"
            "  %s [--file <path>] address <index>               show receive address at index\n"
            "  %s [--file <path>] balance [gap]                 show total balance (scans addresses)\n"
            "  %s [--file <path>] history [gap]                 show transaction history\n"
            "  %s [--file <path>] send <addr> <sat> [fee_sat]   send funds\n"
            "  %s [--file <path>] check <address>               check if address is yours\n"
            "  %s usb-clone                                     clone encrypted seed to a second USB\n"
            "  %s usb-format                                    wipe a USB drive for use as a wallet key\n"
            "  %s eject                                         safely eject the wallet USB\n"
            "  %s settings                                      configure display currency\n"
            "\n"
            "  --file <path>  use a specific raw device or file instead of auto-detected USB\n",
            prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

#define MAX_HISTORY_TXS 512

static int compare_tx_time(const void *a, const void *b)
{
    const addr_tx_t *ta = (const addr_tx_t *)a;
    const addr_tx_t *tb = (const addr_tx_t *)b;
    /* Unconfirmed (block_time==0) sorts first (treated as most recent) */
    uint32_t ka = (ta->confirmed && ta->block_time) ? ta->block_time : UINT32_MAX;
    uint32_t kb = (tb->confirmed && tb->block_time) ? tb->block_time : UINT32_MAX;
    if (ka > kb) return -1;
    if (ka < kb) return  1;
    return 0;
}

static int cmd_history(uint32_t gap_limit)
{
    if (access(DEFAULT_SEED_PATH, F_OK) != 0) {
        fprintf(stderr, "error: %s not found -- run 'wallet init' first\n", DEFAULT_SEED_PATH);
        return 1;
    }
    char *password = getpass("Wallet password: ");
    if (!password) return 1;
    printf("\n");

    unsigned char seed[64];
    if (storage_decrypt(DEFAULT_SEED_PATH, password, seed) != 0) {
        fprintf(stderr, "error: decryption failed\n");
        return 1;
    }

    addr_tx_t *all = malloc(MAX_HISTORY_TXS * sizeof(addr_tx_t));
    if (!all) { memset(seed, 0, sizeof(seed)); return 1; }
    int total = 0;

    uint32_t gap = 0, index = 0;
    printf("Scanning addresses...\n");
    fflush(stdout);

    int64_t cur_bal = 0;
    while (gap < gap_limit) {
        char address[73];
        if (wallet_derive_address(seed, index, address) != 0) break;

        addr_tx_t page[50];
        int n = network_get_address_txs(address, page, 50);
        if (n < 0) {
            fprintf(stderr, "error: network request failed for index %u\n", index);
            break;
        }
        if (n == 0) { gap++; index++; continue; }
        gap = 0;

        /* Add this address's balance to total */
        int64_t ab = network_get_balance(address);
        if (ab > 0) cur_bal += ab;

        for (int i = 0; i < n && total < MAX_HISTORY_TXS; i++) {
            int found = 0;
            for (int j = 0; j < total; j++) {
                if (strcmp(all[j].txid, page[i].txid) == 0) {
                    all[j].net_value += page[i].net_value;
                    found = 1;
                    break;
                }
            }
            if (!found) {
                all[total] = page[i];
                total++;
            }
        }
        index++;
    }
    memset(seed, 0, sizeof(seed));

    /* Sort most recent first */
    qsort(all, (size_t)total, sizeof(addr_tx_t), compare_tx_time);

    /* Fetch fiat price if configured */
    char currency[16];
    settings_get_currency(currency, sizeof(currency));
    double btc_price = 0.0;
    int have_price = (strcmp(currency, "NONE") != 0)
                     && (network_get_btc_price(currency, &btc_price) == 0);

    if (total == 0) {
        printf("No transactions found.\n");
        free(all);
        return 0;
    }

    /* Compute balance after each tx (sorted newest first, so oldest is last).
     * Walk oldest→newest (reverse), starting from current balance. */
    int64_t *bal_after = malloc((size_t)total * sizeof(int64_t));
    if (!bal_after) { free(all); return 1; }

    int64_t running = cur_bal;
    int running_valid = 1; /* becomes 0 once we go negative (missing history) */
    for (int i = 0; i < total; i++) {
        bal_after[i] = running_valid ? running : INT64_MIN;
        running -= all[i].net_value;
        if (running < 0) running_valid = 0;
    }

    printf("\n");
    if (have_price) {
        printf("  %-16s  %-19s  %-46s  %-46s\n",
               "date", "txid", "amount", "balance");
        printf("  %-16s  %-19s  %-46s  %-46s\n",
               "----------------", "-------------------",
               "----------------------------------------------",
               "----------------------------------------------");
    } else {
        printf("  %-16s  %-19s  %-20s  %-20s\n",
               "date", "txid", "amount", "balance");
        printf("  %-16s  %-19s  %-20s  %-20s\n",
               "----------------", "-------------------",
               "--------------------", "--------------------");
    }
    for (int i = 0; i < total; i++) {
        addr_tx_t *tx = &all[i];

        /* Format date */
        char date_str[24];
        if (tx->confirmed && tx->block_time > 0) {
            time_t t = (time_t)tx->block_time;
            struct tm *tm_p = gmtime(&t);
            strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M", tm_p);
        } else {
            snprintf(date_str, sizeof(date_str), "unconfirmed  ");
        }

        /* Short txid: first8...last8 */
        char short_txid[20];
        snprintf(short_txid, sizeof(short_txid), "%.8s..%.8s",
                 tx->txid, tx->txid + 56);

        /* Amount */
        char sign = tx->net_value >= 0 ? '+' : '-';
        uint64_t abs_val = tx->net_value >= 0
                           ? (uint64_t)tx->net_value
                           : (uint64_t)(-tx->net_value);
        char s_val[32], s_bal[32];
        fmt_sat(abs_val, s_val, sizeof(s_val));
        int bal_known = (bal_after[i] != INT64_MIN);
        if (bal_known)
            fmt_sat((uint64_t)bal_after[i], s_bal, sizeof(s_bal));
        else
            snprintf(s_bal, sizeof(s_bal), "---");

        /* Optional fiat */
        char fiat_val[48] = "", fiat_bal[48] = "";
        if (have_price) {
            char f_v[32];
            fmt_fiat((double)abs_val / 1e8 * btc_price, currency, f_v, sizeof(f_v));
            snprintf(fiat_val, sizeof(fiat_val), "  (~%s)", f_v);
            if (bal_known) {
                char f_b[32];
                fmt_fiat((double)bal_after[i] / 1e8 * btc_price, currency, f_b, sizeof(f_b));
                snprintf(fiat_bal, sizeof(fiat_bal), "  (~%s)", f_b);
            }
        }

        /* Build combined amount and balance columns with aligned fiat */
        char amt_col[72], bal_col[72];
        char amt_sat[32], bal_sat[32];
        snprintf(amt_sat, sizeof(amt_sat), "%c%s sat", sign, s_val);
        snprintf(bal_sat, sizeof(bal_sat), "%s sat", s_bal);
        snprintf(amt_col, sizeof(amt_col), " %-16s%s", amt_sat, fiat_val);
        snprintf(bal_col, sizeof(bal_col), " %-16s%s", bal_sat, fiat_bal);

        printf("  %s  %s  %-46s  %s\n",
               date_str, short_txid, amt_col, bal_col);
    }
    printf("\n%d transaction%s\n", total, total == 1 ? "" : "s");

    free(bal_after);
    free(all);
    return 0;
}

static int cmd_eject(void)
{
    char dev[512];
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
    char devs[8][512];
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

        char rem[512];
        snprintf(rem, sizeof(rem), "/sys/block/%s/removable", be->d_name);
        FILE *f = fopen(rem, "r");
        if (!f) continue;
        char val[4] = {0};
        if (!fgets(val, sizeof(val), f)) { fclose(f); continue; }
        fclose(f);
        if (val[0] != '1') continue;

        char szpath[512];
        snprintf(szpath, sizeof(szpath), "/sys/block/%s/size", be->d_name);
        FILE *sf = fopen(szpath, "r");
        unsigned long long sectors = 0;
        if (sf) {
            char szbuf[32] = {0};
            if (fgets(szbuf, sizeof(szbuf), sf))
                sectors = strtoull(szbuf, NULL, 10);
            fclose(sf);
        }
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
    if (system(cmd) != 0) { /* best-effort, ignore failure */ }

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

    /* usb-format and usb-clone operate on raw block devices -- no seed path needed */
    if (strcmp(argv[argi], "usb-format") == 0) {
        return cmd_usb_format();
    }

    if (strcmp(argv[argi], "usb-clone") == 0) {
        return cmd_clone();
    }

    if (strcmp(argv[argi], "eject") == 0) {
        return cmd_eject();
    }

    if (strcmp(argv[argi], "settings") == 0) {
        return cmd_settings();
    }

    if (!path_set) init_seed_path();

    if (strcmp(argv[argi], "init") == 0) {
        return cmd_init();
    }

    if (strcmp(argv[argi], "restore") == 0) {
        return cmd_restore();
    }

    if (strcmp(argv[argi], "balance") == 0) {
        uint32_t gap = GAP_LIMIT;
        if (argc > argi + 1) gap = (uint32_t)strtoul(argv[argi + 1], NULL, 10);
        if (gap == 0) gap = GAP_LIMIT;
        return cmd_balance(gap);
    }

    if (strcmp(argv[argi], "history") == 0) {
        uint32_t gap = GAP_LIMIT;
        if (argc > argi + 1) gap = (uint32_t)strtoul(argv[argi + 1], NULL, 10);
        if (gap == 0) gap = GAP_LIMIT;
        return cmd_history(gap);
    }

    if (strcmp(argv[argi], "send") == 0) {
        if (argc <= argi + 2) {
            fprintf(stderr, "Usage: %s send <address> <satoshis> [fee_sat]\n", argv[0]);
            return 1;
        }
        return cmd_send(argv[argi + 1], argv[argi + 2],
                        argc > argi + 3 ? argv[argi + 3] : NULL);
    }

    if (strcmp(argv[argi], "check") == 0) {
        if (argc <= argi + 1) {
            fprintf(stderr, "Usage: %s check <address>\n", argv[0]);
            return 1;
        }
        return cmd_check(argv[argi + 1]);
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
