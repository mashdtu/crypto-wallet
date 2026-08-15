/*
 * src/bech32.c — bech32 encoding for native SegWit addresses (BIP-173)
 *
 * Based on the reference implementation in BIP-173.
 * https://github.com/bitcoin/bips/blob/master/bip-0173/ref/c/segwit_addr.c
 */

#include "bech32.h"

#include <string.h>
#include <stdint.h>

/* The 32-character bech32 alphabet */
static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/* checksum */

/*
 * Compute the bech32 checksum polynomial over an array of 5-bit values.
 * The generator constants come directly from BIP-173.
 */
static uint32_t bech32_polymod(const uint8_t *values, size_t len)
{
    static const uint32_t GEN[] = {
        0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u
    };
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = (uint8_t)(chk >> 25);
        chk = ((chk & 0x1ffffffu) << 5) ^ values[i];
        for (int j = 0; j < 5; j++) {
            if ((b >> j) & 1u) chk ^= GEN[j];
        }
    }
    return chk;
}

/*
 * Expand the human-readable part into a sequence of 5-bit values for the
 * checksum calculation.  For HRP "tb" this produces: [3, 2, 0, 20, 2].
 *
 *   High bits of each char (>>5), then a zero separator, then low bits (&31).
 */
static size_t bech32_hrp_expand(const char *hrp, uint8_t *out)
{
    size_t len = strlen(hrp);
    for (size_t i = 0; i < len; i++) out[i]         = (uint8_t)((unsigned char)hrp[i] >> 5);
    out[len] = 0;
    for (size_t i = 0; i < len; i++) out[len + 1 + i] = (uint8_t)((unsigned char)hrp[i] & 31u);
    return len * 2 + 1;
}

/* base conversion */

/*
 * Convert between power-of-2 bit-group sizes.
 * Used to repack 8-bit bytes into 5-bit groups for bech32.
 *
 * frombits / tobits: source and target group sizes (e.g. 8 and 5)
 * pad: if 1, pad the last group; if 0, require no leftover bits
 *
 * Returns 1 on success, 0 on failure.
 */
static int convertbits(uint8_t *out, size_t *outlen,
                       const uint8_t *in, size_t inlen,
                       int frombits, int tobits, int pad)
{
    int acc   = 0;
    int bits  = 0;
    size_t o  = 0;
    int maxv  = (1 << tobits) - 1;

    for (size_t i = 0; i < inlen; i++) {
        acc   = (acc << frombits) | in[i];
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out[o++] = (uint8_t)((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits) out[o++] = (uint8_t)((acc << (tobits - bits)) & maxv);
    } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
        return 0; /* leftover bits that shouldn't be there */
    }
    *outlen = o;
    return 1;
}

/* public API */

int segwit_addr_encode(char *output, const char *hrp, int witver,
                       const unsigned char *witprog, size_t witprog_len)
{
    /* Convert witness program from 8-bit to 5-bit groups */
    uint8_t converted[65];
    size_t  converted_len = 0;
    if (!convertbits(converted, &converted_len,
                     witprog, witprog_len, 8, 5, 1))
        return 0;

    /* data = [witness_version] + [5-bit converted program] */
    uint8_t data[66];
    data[0] = (uint8_t)witver;
    memcpy(data + 1, converted, converted_len);
    size_t data_len = 1 + converted_len;

    /* Build input for polymod: hrp_expand + data + 6 zero padding */
    uint8_t polymod_input[200];
    size_t  hrp_len = bech32_hrp_expand(hrp, polymod_input);
    memcpy(polymod_input + hrp_len, data, data_len);
    memset(polymod_input + hrp_len + data_len, 0, 6);

    uint32_t chk = bech32_polymod(polymod_input, hrp_len + data_len + 6) ^ 1u;

    /* Compute 6 checksum characters */
    uint8_t checksum[6];
    for (int i = 0; i < 6; i++)
        checksum[i] = (uint8_t)((chk >> (5 * (5 - i))) & 31u);

    /* Write output: hrp + '1' + encoded data + encoded checksum */
    size_t h = strlen(hrp);
    memcpy(output, hrp, h);
    output[h] = '1';
    for (size_t i = 0; i < data_len; i++)
        output[h + 1 + i] = CHARSET[data[i]];
    for (int i = 0; i < 6; i++)
        output[h + 1 + data_len + i] = CHARSET[checksum[i]];
    output[h + 1 + data_len + 6] = '\0';

    return 1;
}
