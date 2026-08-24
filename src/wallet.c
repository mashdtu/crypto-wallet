/*
 * wallet.c - BIP-32/84 hierarchical deterministic key derivation
 *
 * Takes the 64-byte master seed from keygen.c and derives individual
 * private keys and Bitcoin addresses from it.
 *
 * Derivation path: m/84'/0'/0'/0/<index>
 *
 *   84'  - purpose, hardened. 84 = BIP-84 (native SegWit / bech32).
 *   0'   - coin type, hardened. 0 = Bitcoin mainnet (BIP-44).
 *   0'   - account 0, hardened.
 *   0    - external chain (receiving addresses). 1 would be change.
 *   idx  - address index, normal (unhardened).
 *
 * Hardened derivation (') means the child key cannot be computed from
 * the parent public key alone - the parent private key is required.
 * This prevents an attacker who steals one child private key from
 * climbing back up the tree to other addresses.
 *
 * Normal (unhardened) derivation for the last two levels is fine
 * because index 0 is where we always sign from, and the wallet
 * currently only uses index 0 for spending.
 *
 * The actual address type produced is P2WPKH (pay-to-witness-public-key-hash),
 * which gives bech32 addresses starting with "bc1q" on mainnet.
 */

#define _DEFAULT_SOURCE
#include "wallet.h"
#include "bech32.h"

#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>

/*
 * derive_hardened_child()
 *
 * BIP-32 hardened child derivation. The child key is derived from:
 *   HMAC-SHA512(key=parent_chain_code, data=0x00 || parent_privkey || index_BE)
 *
 * The 0x00 prefix distinguishes hardened from normal derivation.
 * The index must have bit 31 set (index | 0x80000000).
 *
 * The left 32 bytes of the HMAC output are added (mod curve order) to
 * the parent private key to get the child private key.
 * The right 32 bytes become the child chain code.
 */
static int derive_hardened_child(
    const unsigned char *parent_key,
    const unsigned char *parent_cc,
    uint32_t index,
    unsigned char *child_key,
    unsigned char *child_cc)
{
    /* Build the HMAC input: 0x00 || parent_privkey || index (big-endian 4 bytes) */
    unsigned char data[37];
    data[0] = 0x00;
    memcpy(data + 1, parent_key, 32);
    data[33] = (unsigned char)((index >> 24) & 0xFFu);
    data[34] = (unsigned char)((index >> 16) & 0xFFu);
    data[35] = (unsigned char)((index >> 8) & 0xFFu);
    data[36] = (unsigned char)((index) & 0xFFu);

    unsigned char out[64];
    unsigned int out_len;
    if (HMAC(EVP_sha512(), parent_cc, 32, data, 37, out, &out_len) == NULL)
        return -1;

    unsigned char IL[32];
    memcpy(IL, out, 32);            /* left half: tweak to add to parent key */
    memcpy(child_cc, out + 32, 32); /* right half: new chain code */

    /* child_key = parent_key + IL (mod curve order), done in-place by secp256k1 */
    memcpy(child_key, parent_key, 32);
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    int ok = secp256k1_ec_seckey_tweak_add(ctx, child_key, IL);
    secp256k1_context_destroy(ctx);
    return ok == 1 ? 0 : -1;
}

/*
 * derive_normal_child()
 *
 * BIP-32 normal (unhardened) child derivation. Unlike hardened, this uses
 * the parent PUBLIC key in the HMAC, so the child public key can be derived
 * without knowing the private key.
 *
 * HMAC-SHA512(key=parent_chain_code, data=parent_pubkey || index_BE)
 *
 * Normal derivation is fine for the last two path components (chain=0, index=n)
 * because we don't expose child private keys externally.
 */
static int derive_normal_child(
    const unsigned char *parent_key,
    const unsigned char *parent_cc,
    uint32_t index,
    unsigned char *child_key,
    unsigned char *child_cc)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    /* Compute the parent compressed public key (33 bytes) */
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, parent_key) != 1)
    {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    unsigned char pub[33];
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);

    /* HMAC input: parent_pubkey (33 bytes) || index (big-endian 4 bytes) */
    unsigned char data[37];
    memcpy(data, pub, 33);
    data[33] = (unsigned char)((index >> 24) & 0xFFu);
    data[34] = (unsigned char)((index >> 16) & 0xFFu);
    data[35] = (unsigned char)((index >> 8) & 0xFFu);
    data[36] = (unsigned char)((index) & 0xFFu);

    unsigned char out[64];
    unsigned int out_len;
    if (HMAC(EVP_sha512(), parent_cc, 32, data, 37, out, &out_len) == NULL)
    {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    unsigned char IL[32];
    memcpy(IL, out, 32);
    memcpy(child_cc, out + 32, 32);

    /* child_key = parent_key + IL (mod curve order) */
    memcpy(child_key, parent_key, 32);
    int ok = secp256k1_ec_seckey_tweak_add(ctx, child_key, IL);
    secp256k1_context_destroy(ctx);
    return ok == 1 ? 0 : -1;
}

int wallet_derive_address(const unsigned char *seed,
                          uint32_t index,
                          char *address_out)
{
    /* Start with the BIP-32 master key.
     * The master key is derived from the seed by:
     *   HMAC-SHA512(key="Bitcoin seed", data=seed)
     * The left 32 bytes are the master private key,
     * the right 32 bytes are the master chain code.
     * "Bitcoin seed" is the exact magic string defined in BIP-32. */
    unsigned char out[64];
    unsigned int out_len;
    if (HMAC(EVP_sha512(),
             (const unsigned char *)"Bitcoin seed", 12,
             seed, 64, out, &out_len) == NULL)
        return -1;

    unsigned char k[32], cc[32];
    memcpy(k, out, 32);
    memcpy(cc, out + 32, 32);

    /* Walk the derivation path m/84'/0'/0'/0/<index>.
     * Each call overwrites k and cc with the child key and chain code.
     * The 0x80000000 bit marks a step as hardened. */
    if (derive_hardened_child(k, cc, 84u | 0x80000000u, k, cc) != 0)
        return -1; /* purpose */
    if (derive_hardened_child(k, cc, 0u | 0x80000000u, k, cc) != 0)
        return -1; /* coin: BTC mainnet */
    if (derive_hardened_child(k, cc, 0u | 0x80000000u, k, cc) != 0)
        return -1; /* account 0 */
    if (derive_normal_child(k, cc, 0u, k, cc) != 0)
        return -1; /* external chain */
    if (derive_normal_child(k, cc, index, k, cc) != 0)
        return -1; /* address index */

    /* Compute the compressed public key from the derived private key */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, k) != 1)
    {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    unsigned char pub[33];
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);

    /* P2WPKH witness program = HASH160(pubkey) = RIPEMD160(SHA256(pubkey)).
     * This 20-byte hash is what gets embedded in the scriptPubKey on-chain
     * and encoded as the bech32 address. */
    unsigned char sha_out[32];
    SHA256(pub, 33, sha_out);
    unsigned char h160[20];
    RIPEMD160(sha_out, 32, h160);

    /* Encode as bech32: "bc" HRP, witness version 0, 20-byte program.
     * Produces a "bc1q..." address. */
    if (segwit_addr_encode(address_out, "bc", 0, h160, 20) != 1)
        return -1;

    return 0;
}

int wallet_derive_key(const unsigned char *seed,
                      uint32_t index,
                      unsigned char *privkey_out,
                      unsigned char *pubkey_out,
                      unsigned char *hash160_out)
{
    /* Same derivation as wallet_derive_address(), but returns the
     * private key and public key so the caller can sign transactions. */
    unsigned char out[64];
    unsigned int out_len;
    if (HMAC(EVP_sha512(),
             (const unsigned char *)"Bitcoin seed", 12,
             seed, 64, out, &out_len) == NULL)
        return -1;

    unsigned char k[32], cc[32];
    memcpy(k, out, 32);
    memcpy(cc, out + 32, 32);

    if (derive_hardened_child(k, cc, 84u | 0x80000000u, k, cc) != 0)
        return -1;
    if (derive_hardened_child(k, cc, 0u | 0x80000000u, k, cc) != 0)
        return -1;
    if (derive_hardened_child(k, cc, 0u | 0x80000000u, k, cc) != 0)
        return -1;
    if (derive_normal_child(k, cc, 0u, k, cc) != 0)
        return -1;
    if (derive_normal_child(k, cc, index, k, cc) != 0)
        return -1;

    memcpy(privkey_out, k, 32);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, k) != 1)
    {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_out, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);

    /* Also give the caller the hash160, they need it to build the
     * BIP-143 scriptCode when signing P2WPKH inputs. */
    unsigned char sha_out[32];
    SHA256(pubkey_out, 33, sha_out);
    RIPEMD160(sha_out, 32, hash160_out);

    return 0;
}
