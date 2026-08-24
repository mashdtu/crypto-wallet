/*
 * bech32.c - bech32 and bech32m address encoding/decoding (BIP-173 / BIP-350)
 *
 * Bech32 is the encoding format used for native SegWit Bitcoin addresses.
 * Addresses look like: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
 *
 * Format: <hrp> "1" <data> <checksum>
 *   hrp        - human-readable part ("bc" for mainnet, "tb" for testnet)
 *   "1"        - separator (always the character '1')
 *   data       - witness version (1 char) + witness program (5-bit encoded)
 *   checksum   - 6 characters providing error detection
 *
 * Two variants:
 *   bech32  (BIP-173): used for witness version 0 (P2WPKH bc1q..., P2WSH)
 *   bech32m (BIP-350): used for witness version 1+ (P2TR bc1p... taproot)
 *
 * The only difference between bech32 and bech32m is the checksum constant:
 *   bech32  checksum XOR constant = 1
 *   bech32m checksum XOR constant = 0x2bc830a3
 *
 * Using the wrong constant on an address from the other type causes
 * checksum verification to fail, preventing accidentally sending to
 * a taproot address using a P2WPKH-format checksum (or vice versa).
 */

#include "bech32.h"

#include <string.h>
#include <stdint.h>

/* The 32-character alphabet used for bech32 encoding.
 * Chosen to avoid visually confusing characters (0/O, 1/I/l). */
static const char CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/*
 * bech32_polymod()
 *
 * Computes the BCH polynomial checksum over an array of 5-bit values.
 * This is a BCH (Bose-Chaudhuri-Hocquenghem) error-detecting code that
 * can detect up to 4 errors in an address string.
 *
 * The five generator constants come directly from BIP-173.
 * If the checksum of a valid bech32 string equals 1 (or 0x2bc830a3 for
 * bech32m), the data is valid.
 */
static uint32_t bech32_polymod(const uint8_t *values, size_t len)
{
    static const uint32_t GEN[] = {
        0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u};
    uint32_t chk = 1;
    for (size_t i = 0; i < len; i++)
    {
        uint8_t b = (uint8_t)(chk >> 25);
        chk = ((chk & 0x1ffffffu) << 5) ^ values[i];
        for (int j = 0; j < 5; j++)
        {
            if ((b >> j) & 1u)
                chk ^= GEN[j];
        }
    }
    return chk;
}

/*
 * bech32_hrp_expand()
 *
 * Expands the human-readable part into 5-bit values for use in the checksum.
 * The expansion is: high bits of each char (>>5), a zero separator, then
 * low bits (&31). This ensures different HRPs produce different checksums.
 *
 * For "bc": [3, 2, 0, 2, 3]
 * For "tb": [3, 2, 0, 20, 2]
 */
static size_t bech32_hrp_expand(const char *hrp, uint8_t *out)
{
    size_t len = strlen(hrp);
    for (size_t i = 0; i < len; i++)
        out[i] = (uint8_t)((unsigned char)hrp[i] >> 5);
    out[len] = 0; /* zero separator */
    for (size_t i = 0; i < len; i++)
        out[len + 1 + i] = (uint8_t)((unsigned char)hrp[i] & 31u);
    return len * 2 + 1;
}

/*
 * convertbits()
 *
 * Converts an array of values from one bit-width to another.
 * Used to repack 8-bit bytes into 5-bit groups for bech32 encoding,
 * and to convert 5-bit groups back to 8-bit bytes for decoding.
 *
 * frombits:    source group size (e.g. 8 for bytes)
 * tobits:      target group size (e.g. 5 for bech32)
 * pad:         1 = pad with zeros at the end; 0 = require no leftover bits
 */
static int convertbits(uint8_t *out, size_t *outlen,
                       const uint8_t *in, size_t inlen,
                       int frombits, int tobits, int pad)
{
    int acc = 0;
    int bits = 0;
    size_t o = 0;
    int maxv = (1 << tobits) - 1;

    for (size_t i = 0; i < inlen; i++)
    {
        acc = (acc << frombits) | in[i];
        bits += frombits;
        while (bits >= tobits)
        {
            bits -= tobits;
            out[o++] = (uint8_t)((acc >> bits) & maxv);
        }
    }
    if (pad)
    {
        if (bits)
            out[o++] = (uint8_t)((acc << (tobits - bits)) & maxv);
    }
    else if (bits >= frombits || ((acc << (tobits - bits)) & maxv))
    {
        return 0; /* leftover bits that shouldn't be there (reject) */
    }
    *outlen = o;
    return 1;
}

int segwit_addr_encode(char *output, const char *hrp, int witver,
                       const unsigned char *witprog, size_t witprog_len)
{
    /* Step 1: convert the witness program from 8-bit bytes to 5-bit groups */
    uint8_t converted[65];
    size_t converted_len = 0;
    if (!convertbits(converted, &converted_len,
                     witprog, witprog_len, 8, 5, 1))
        return 0;

    /* Step 2: prepend the witness version as the first 5-bit value */
    uint8_t data[66];
    data[0] = (uint8_t)witver;
    memcpy(data + 1, converted, converted_len);
    size_t data_len = 1 + converted_len;

    /* Step 3: compute the checksum over hrp_expand + data + 6 zeros */
    uint8_t polymod_input[200];
    size_t hrp_len = bech32_hrp_expand(hrp, polymod_input);
    memcpy(polymod_input + hrp_len, data, data_len);
    memset(polymod_input + hrp_len + data_len, 0, 6); /* placeholder for checksum */

    /* Use bech32 constant (1) for v0, bech32m constant (0x2bc830a3) for v1+ */
    uint32_t const_val = (witver == 0) ? 1u : 0x2bc830a3u;
    uint32_t chk = bech32_polymod(polymod_input, hrp_len + data_len + 6) ^ const_val;

    /* Step 4: encode the 6 checksum characters */
    uint8_t checksum[6];
    for (int i = 0; i < 6; i++)
        checksum[i] = (uint8_t)((chk >> (5 * (5 - i))) & 31u);

    /* Step 5: assemble the final string: hrp + "1" + encoded_data + checksum */
    size_t h = strlen(hrp);
    memcpy(output, hrp, h);
    output[h] = '1'; /* separator */
    for (size_t i = 0; i < data_len; i++)
        output[h + 1 + i] = CHARSET[data[i]];
    for (int i = 0; i < 6; i++)
        output[h + 1 + data_len + i] = CHARSET[checksum[i]];
    output[h + 1 + data_len + 6] = '\0';

    return 1;
}

int segwit_addr_decode(const char *addr,
                       char *hrp_out,
                       unsigned char *prog_out,
                       size_t *prog_len)
{
    /* Find the last '1'. Everything before it is the HRP */
    size_t addr_len = strlen(addr);
    int sep = -1;
    for (int i = (int)addr_len - 1; i >= 0; i--)
    {
        if (addr[i] == '1')
        {
            sep = i;
            break;
        }
    }
    /* Require at least 1 HRP char and 6 checksum chars after the separator */
    if (sep < 1 || sep + 7 > (int)addr_len)
        return -1;

    /* Extract the HRP */
    memcpy(hrp_out, addr, (size_t)sep);
    hrp_out[sep] = '\0';

    /* Decode data portion from the charset */
    size_t data_len = addr_len - sep - 1;
    uint8_t data[128];
    if (data_len > 128)
        return -1;
    for (size_t i = 0; i < data_len; i++)
    {
        const char *pos = strchr(CHARSET, addr[sep + 1 + i]);
        if (!pos)
            return -1;
        data[i] = (uint8_t)(pos - CHARSET);
    }

    /* Peek the witness version (first 5-bit value) BEFORE verifying the checksum,
     * so we know which constant to use for verification. */
    int witver = data[0];
    if (witver > 16)
        return -1;

    /* Verify the checksum (different constant for bech32 vs bech32m) */
    uint8_t polymod_input[256];
    size_t hrp_expand_len = bech32_hrp_expand(hrp_out, polymod_input);
    memcpy(polymod_input + hrp_expand_len, data, data_len);
    uint32_t chk = bech32_polymod(polymod_input, hrp_expand_len + data_len);
    if (witver == 0 && chk != 1u)
        return -1; /* bech32 */
    if (witver != 0 && chk != 0x2bc830a3u)
        return -1; /* bech32m */

    /* Convert remaining 5-bit groups (minus the 1 version byte and 6 checksum chars)
     * back to 8-bit bytes. pad=0 means we reject any trailing leftover bits. */
    size_t conv_len = 0;
    if (!convertbits(prog_out, &conv_len,
                     data + 1, data_len - 7, 5, 8, 0))
        return -1;

    *prog_len = conv_len;
    return witver;
}
