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

/*
 * segwit_addr_decode()
 *
 * Decodes a bech32 segwit address into its witness program.
 *
 * addr        [in]  null-terminated bech32 address
 * hrp_out     [out] caller buffer >= 84 bytes, receives the HRP
 * prog_out    [out] caller buffer >= 40 bytes, receives the witness program
 * prog_len    [out] length of the witness program in bytes
 *
 * Returns witness version (0-16) on success, -1 on failure.
 */
int segwit_addr_decode(const char *addr,
                       char *hrp_out,
                       unsigned char *prog_out,
                       size_t *prog_len);

#endif /* BECH32_H */
