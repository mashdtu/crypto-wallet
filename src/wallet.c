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

static int derive_hardened_child(
    const unsigned char *parent_key,
    const unsigned char *parent_cc,
    uint32_t index,
    unsigned char *child_key,
    unsigned char *child_cc)
{
    unsigned char data[37];
    data[0] = 0x00;
    memcpy(data + 1, parent_key, 32);
    data[33] = (unsigned char)((index >> 24) & 0xFFu);
    data[34] = (unsigned char)((index >> 16) & 0xFFu);
    data[35] = (unsigned char)((index >>  8) & 0xFFu);
    data[36] = (unsigned char)((index      ) & 0xFFu);

    unsigned char out[64];
    unsigned int out_len;
    if (HMAC(EVP_sha512(), parent_cc, 32, data, 37, out, &out_len) == NULL)
        return -1;

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
    const unsigned char *parent_key,
    const unsigned char *parent_cc,
    uint32_t index,
    unsigned char *child_key,
    unsigned char *child_cc)
{
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, parent_key) != 1) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    unsigned char pub[33];
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);

    unsigned char data[37];
    memcpy(data, pub, 33);
    data[33] = (unsigned char)((index >> 24) & 0xFFu);
    data[34] = (unsigned char)((index >> 16) & 0xFFu);
    data[35] = (unsigned char)((index >>  8) & 0xFFu);
    data[36] = (unsigned char)((index      ) & 0xFFu);

    unsigned char out[64];
    unsigned int out_len;
    if (HMAC(EVP_sha512(), parent_cc, 32, data, 37, out, &out_len) == NULL) {
        secp256k1_context_destroy(ctx);
        return -1;
    }

    unsigned char IL[32];
    memcpy(IL, out, 32);
    memcpy(child_cc, out + 32, 32);
    memcpy(child_key, parent_key, 32);
    int ok = secp256k1_ec_seckey_tweak_add(ctx, child_key, IL);
    secp256k1_context_destroy(ctx);
    return ok == 1 ? 0 : -1;
}

int wallet_derive_address(const unsigned char *seed,
                          uint32_t index,
                          char *address_out)
{
    /* Master key from seed */
    unsigned char out[64];
    unsigned int out_len;
    if (HMAC(EVP_sha512(),
             (const unsigned char *)"Bitcoin seed", 12,
             seed, 64, out, &out_len) == NULL)
        return -1;

    unsigned char k[32], cc[32];
    memcpy(k,  out,      32);
    memcpy(cc, out + 32, 32);

    /* Derive m/84'/0'/0'/0/<index> */
    if (derive_hardened_child(k, cc, 84u | 0x80000000u, k, cc) != 0) return -1;
    if (derive_hardened_child(k, cc,  0u | 0x80000000u, k, cc) != 0) return -1;
    if (derive_hardened_child(k, cc,  0u | 0x80000000u, k, cc) != 0) return -1;
    if (derive_normal_child(k, cc, 0u,    k, cc) != 0) return -1;
    if (derive_normal_child(k, cc, index, k, cc) != 0) return -1;

    /* Public key */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, k) != 1) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    unsigned char pub[33];
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pub, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);

    /* Hash160 */
    unsigned char sha_out[32];
    SHA256(pub, 33, sha_out);
    unsigned char h160[20];
    RIPEMD160(sha_out, 32, h160);

    /* Bech32 */
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
    unsigned char out[64];
    unsigned int out_len;
    if (HMAC(EVP_sha512(),
             (const unsigned char *)"Bitcoin seed", 12,
             seed, 64, out, &out_len) == NULL)
        return -1;

    unsigned char k[32], cc[32];
    memcpy(k,  out,      32);
    memcpy(cc, out + 32, 32);

    if (derive_hardened_child(k, cc, 84u | 0x80000000u, k, cc) != 0) return -1;
    if (derive_hardened_child(k, cc,  0u | 0x80000000u, k, cc) != 0) return -1;
    if (derive_hardened_child(k, cc,  0u | 0x80000000u, k, cc) != 0) return -1;
    if (derive_normal_child(k, cc, 0u,    k, cc) != 0) return -1;
    if (derive_normal_child(k, cc, index, k, cc) != 0) return -1;

    memcpy(privkey_out, k, 32);

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(ctx, &pubkey, k) != 1) {
        secp256k1_context_destroy(ctx);
        return -1;
    }
    size_t pub_len = 33;
    secp256k1_ec_pubkey_serialize(ctx, pubkey_out, &pub_len, &pubkey, SECP256K1_EC_COMPRESSED);
    secp256k1_context_destroy(ctx);

    unsigned char sha_out[32];
    SHA256(pubkey_out, 33, sha_out);
    RIPEMD160(sha_out, 32, hash160_out);

    return 0;
}
