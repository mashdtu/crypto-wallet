/*
 * tests/test_vector.c
 *
 * Verifies key derivation against the canonical BIP-39 all-zero test vector.
 *
 * Entropy: 32 zero bytes
 * Expected mnemonic: "abandon" x23 + "art"
 * Path: m/84'/1'/0'/0/0 (testnet P2WPKH)
 *
 * Compare output against:
 *   https://iancoleman.io/bip39
 *   Mnemonic: abandon abandon ... art
 *   Coin: BTC testnet, BIP84
 *
 * WARNING: This mnemonic has no security value. Test use only.
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>
#include "../src/bech32.h"
#include "../src/wordlist.c"

/* BIP-39 wordlist (same as keygen.c) */

static const char *EXPECTED_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon abandon abandon art";

/* helpers */

static int derive_hardened_child(
    const unsigned char *parent_key, const unsigned char *parent_cc,
    uint32_t index,
    unsigned char *child_key, unsigned char *child_cc)
{
    unsigned char data[37];
    data[0] = 0x00;
    memcpy(data + 1, parent_key, 32);
    data[33] = (unsigned char)((index >> 24) & 0xFFu);
    data[34] = (unsigned char)((index >> 16) & 0xFFu);
    data[35] = (unsigned char)((index >>  8) & 0xFFu);
    data[36] = (unsigned char)((index      ) & 0xFFu);

    unsigned char out[64]; unsigned int out_len;
    if (HMAC(EVP_sha512(), parent_cc, 32, data, 37, out, &out_len) == NULL) return -1;

    unsigned char IL[32];
    memcpy(IL, out, 32);
    memcpy(child_cc, out + 32, 32);
    memcpy(child_key, parent_key, 32);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    int ok = secp256k1_ec_seckey_tweak_add(ctx, child_key, IL);
    secp256k1_context_destroy(ctx);
    return ok == 1 ? 0 : -1;
}

static int derive_normal_child(
    const unsigned char *parent_key, const unsigned char *parent_cc,
    uint32_t index,
    unsigned char *child_key, unsigned char *child_cc)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, parent_key);
    unsigned char pub[33]; size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);

    unsigned char data[37];
    memcpy(data, pub, 33);
    data[33] = (unsigned char)((index >> 24) & 0xFFu);
    data[34] = (unsigned char)((index >> 16) & 0xFFu);
    data[35] = (unsigned char)((index >>  8) & 0xFFu);
    data[36] = (unsigned char)((index      ) & 0xFFu);

    unsigned char out[64]; unsigned int out_len;
    if (HMAC(EVP_sha512(), parent_cc, 32, data, 37, out, &out_len) == NULL) {
        secp256k1_context_destroy(ctx); return -1;
    }

    unsigned char IL[32];
    memcpy(IL, out, 32);
    memcpy(child_cc, out + 32, 32);
    memcpy(child_key, parent_key, 32);
    int ok = secp256k1_ec_seckey_tweak_add(ctx, child_key, IL);
    secp256k1_context_destroy(ctx);
    return ok == 1 ? 0 : -1;
}

/* test */

int main(void)
{
    int pass = 1;

    /* Step 1: mnemonic from 32 zero bytes */
    static const unsigned char zero_entropy[32] = { 0 };

    unsigned char hash[32];
    SHA256(zero_entropy, 32, hash);

    unsigned char combined[33] = { 0 };
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

    char mnemonic[216] = {0};
    for (unsigned int i = 0; i < 24; i++) {
        strcat(mnemonic, wordlist[indices[i]]);
        if (i < 23u) strcat(mnemonic, " ");
    }

    if (strcmp(mnemonic, EXPECTED_MNEMONIC) == 0) {
        printf("PASS  mnemonic\n");
    } else {
        printf("FAIL  mnemonic\n  got: %s\n", mnemonic);
        pass = 0;
    }

    /* Step 2: PBKDF2 seed */
    unsigned char seed[64];
    PKCS5_PBKDF2_HMAC(mnemonic, (int)strlen(mnemonic),
                      (const unsigned char *)"mnemonic", 8,
                      2048, EVP_sha512(), 64, seed);

    /* Step 3: master key */
    unsigned char out[64]; unsigned int out_len;
    HMAC(EVP_sha512(), (const unsigned char *)"Bitcoin seed", 12,
         seed, 64, out, &out_len);
    unsigned char mk[32], cc[32];
    memcpy(mk, out, 32);
    memcpy(cc, out + 32, 32);

    /* Step 4: derive m/84'/1'/0'/0/0 */
    unsigned char k[32], c[32];
    if (derive_hardened_child(mk, cc, 84u | 0x80000000u, k, c) != 0) { printf("FAIL  84'\n"); return 1; }
    if (derive_hardened_child(k,  c,   1u | 0x80000000u, k, c) != 0) { printf("FAIL  1'\n");  return 1; }
    if (derive_hardened_child(k,  c,   0u | 0x80000000u, k, c) != 0) { printf("FAIL  0'\n");  return 1; }
    if (derive_normal_child(k, c, 0u, k, c) != 0) { printf("FAIL  0\n"); return 1; }
    if (derive_normal_child(k, c, 0u, k, c) != 0) { printf("FAIL  0\n"); return 1; }

    /* Step 5: public key → hash160 → address */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    secp256k1_ec_pubkey_create(ctx, &pubkey, k);
    unsigned char pub[33]; size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);

    unsigned char sha_out[32];
    SHA256(pub, 33, sha_out);
    unsigned char h160[20];
    RIPEMD160(sha_out, 32, h160);

    char address[73];
    segwit_addr_encode(address, "tb", 0, h160, 20);

    printf("Address: %s\n", address);
    printf("\nVerify at https://iancoleman.io/bip39\n");
    printf("  Mnemonic: abandon (x23) art\n");
    printf("  Coin: BTC testnet  Path: m/84'/1'/0'/0/0\n");

    return pass ? 0 : 1;
}
