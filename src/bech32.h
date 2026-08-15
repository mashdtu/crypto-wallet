/*
 * src/bech32.h — bech32 encoding for native SegWit addresses (BIP-173)
 */

#ifndef BECH32_H
#define BECH32_H

#include <stddef.h>

/*
 * segwit_addr_encode()
 *
 * Encodes a native SegWit address in bech32 format.
 *
 * output      — caller-provided buffer, at least 73 bytes
 * hrp         — human-readable part: "tb" for testnet, "bc" for mainnet
 * witver      — witness version (0 for P2WPKH / P2WSH)
 * witprog     — witness program bytes (20 bytes for P2WPKH)
 * witprog_len — length of witprog
 *
 * Returns 1 on success, 0 on failure.
 */
int segwit_addr_encode(char *output, const char *hrp, int witver,
                       const unsigned char *witprog, size_t witprog_len);

#endif /* BECH32_H */
