/*
 * tx.c - Bitcoin transaction construction and signing
 *
 * This file builds and signs a raw segwit (BIP-141/143) transaction entirely
 * in memory, then returns it as a hex string ready to broadcast.
 *
 * It handles two output types:
 *   - P2WPKH   (20-byte witness program): bc1q... addresses
 *   - P2TR     (32-byte witness program): bc1p... taproot addresses
 *
 * All inputs are P2WPKH from a single keypair (the wallet only signs with
 * index 0 currently). Change output is always P2WPKH back to us.
 *
 * The signing follows BIP-143 (SegWit v0 sighash algorithm), which prevents
 * the quadratic sighash bug from legacy transactions and commits to the value
 * of each input being spent.
 *
 * Segwit transaction serialization format:
 *   version(4) | 0x00 0x01 (marker+flag) | inputs | outputs | witness | locktime
 *
 * The 0x00 0x01 marker signals to nodes that this is a segwit transaction
 * and that witness data follows the outputs.
 */

#include "tx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>

/* Serialization helpers */

/* Bitcoin wire format uses little-endian integers throughout */
static void write_u32le(unsigned char *buf, uint32_t v)
{
    buf[0] = (unsigned char)(v);
    buf[1] = (unsigned char)(v >> 8);
    buf[2] = (unsigned char)(v >> 16);
    buf[3] = (unsigned char)(v >> 24);
}

static void write_u64le(unsigned char *buf, uint64_t v)
{
    buf[0] = (unsigned char)(v);
    buf[1] = (unsigned char)(v >> 8);
    buf[2] = (unsigned char)(v >> 16);
    buf[3] = (unsigned char)(v >> 24);
    buf[4] = (unsigned char)(v >> 32);
    buf[5] = (unsigned char)(v >> 40);
    buf[6] = (unsigned char)(v >> 48);
    buf[7] = (unsigned char)(v >> 56);
}

/*
 * write_varint()
 *
 * Bitcoin's variable-length integer encoding. Small values (< 0xfd) are
 * a single byte. Larger values use a 1-byte prefix followed by 2, 4, or 8
 * bytes. Used to encode lengths of arrays (input count, output count, etc).
 */
static int write_varint(unsigned char *buf, uint64_t v)
{
    if (v < 0xfd)
    {
        buf[0] = (unsigned char)v;
        return 1;
    }
    else if (v <= 0xffff)
    {
        buf[0] = 0xfd;
        buf[1] = (unsigned char)(v);
        buf[2] = (unsigned char)(v >> 8);
        return 3;
    }
    else if (v <= 0xffffffff)
    {
        buf[0] = 0xfe;
        write_u32le(buf + 1, (uint32_t)v);
        return 5;
    }
    else
    {
        buf[0] = 0xff;
        write_u64le(buf + 1, v);
        return 9;
    }
}

/* Parse a big-endian hex txid into 32 bytes (reversed to little-endian).
 *
 * Block explorers and APIs display txids in big-endian (most significant byte
 * first). Bitcoin's wire format stores them little-endian. We reverse here
 * so the on-wire bytes match what nodes expect. */
static int parse_txid(const char *hex, unsigned char *out)
{
    if (strlen(hex) != 64)
        return -1;
    for (int i = 0; i < 32; i++)
    {
        unsigned int byte;
        if (sscanf(hex + (62 - i * 2), "%02x", &byte) != 1)
            return -1;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

/* Double-SHA256: SHA256(SHA256(data)).
 * Used for transaction hashing and the BIP-143 hashPrevouts/hashOutputs. */
static void dsha256(const unsigned char *data, size_t len, unsigned char *out)
{
    unsigned char tmp[32];
    SHA256(data, len, tmp);
    SHA256(tmp, 32, out);
}

static void bytes_to_hex(const unsigned char *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++)
        sprintf(out + i * 2, "%02x", in[i]);
    out[len * 2] = '\0';
}

/* BIP-143 sighash */

/*
 * bip143_sighash()
 *
 * Computes the BIP-143 signature hash for a single P2WPKH input.
 * This is what we actually sign with the private key.
 *
 * The preimage for SIGHASH_ALL is:
 *
 *   dSHA256(
 *     nVersion(4LE)        - transaction version
 *     hashPrevouts(32)     - dSHA256 of all outpoints (commit to which UTXOs)
 *     hashSequence(32)     - dSHA256 of all nSequence values
 *     outpoint(36)         - this input's txid + vout
 *     scriptCode(26)       - the P2PKH scriptCode for P2WPKH inputs
 *     value(8LE)           - satoshi value of this input
 *     nSequence(4LE)       - this input's sequence number
 *     hashOutputs(32)      - dSHA256 of all outputs (commit to where money goes)
 *     nLocktime(4LE)
 *     sighash_type(4LE)    - 0x01 = SIGHASH_ALL
 *   )
 *
 * We call this once per input, varying only input_idx.
 * hashPrevouts and hashOutputs are the same for all inputs in the same tx.
 */
static void bip143_sighash(
    const tx_utxo_t *utxos, int n_utxos,
    int input_idx,
    const unsigned char *hash160, /* 20-byte HASH160(pubkey) */
    const unsigned char *dest_spk, size_t dest_spk_len,
    const unsigned char *change_spk, size_t change_spk_len,
    uint64_t dest_value,
    uint64_t change_value,
    unsigned char *sighash_out)
{
    unsigned char buf[4096];
    size_t pos = 0;

    /* nVersion = 2 */
    write_u32le(buf + pos, 2);
    pos += 4;

    /* hashPrevouts: commit to all inputs we're spending.
     * An attacker can't redirect this tx to spend different UTXOs. */
    {
        unsigned char all_outpoints[36 * 16]; /* max 16 inputs */
        size_t op = 0;
        for (int i = 0; i < n_utxos; i++)
        {
            parse_txid(utxos[i].txid_hex, all_outpoints + op);
            op += 32;
            write_u32le(all_outpoints + op, utxos[i].vout);
            op += 4;
        }
        dsha256(all_outpoints, op, buf + pos);
        pos += 32;
    }

    /* hashSequence: commit to all nSequence values.
     * We use 0xffffffff (final/no RBF) for all inputs. */
    {
        unsigned char all_seq[4 * 16];
        for (int i = 0; i < n_utxos; i++)
            write_u32le(all_seq + i * 4, 0xffffffffu);
        dsha256(all_seq, (size_t)n_utxos * 4, buf + pos);
        pos += 32;
    }

    /* The specific input we're signing: its outpoint (txid + vout) */
    parse_txid(utxos[input_idx].txid_hex, buf + pos);
    pos += 32;
    write_u32le(buf + pos, utxos[input_idx].vout);
    pos += 4;

    /* scriptCode for P2WPKH (defined in BIP-143):
     * This is the equivalent of the P2PKH scriptPubKey that the witness
     * program "unwraps" to. It's 26 bytes:
     *   0x19 = length of what follows (25 bytes)
     *   OP_DUP OP_HASH160 OP_PUSH20 {hash160} OP_EQUALVERIFY OP_CHECKSIG */
    buf[pos++] = 0x19;
    buf[pos++] = 0x76; /* OP_DUP */
    buf[pos++] = 0xa9; /* OP_HASH160 */
    buf[pos++] = 0x14; /* push 20 bytes */
    memcpy(buf + pos, hash160, 20);
    pos += 20;
    buf[pos++] = 0x88; /* OP_EQUALVERIFY */
    buf[pos++] = 0xac; /* OP_CHECKSIG */

    /* satoshi value of input being signed to sighash preimage */
    write_u64le(buf + pos, utxos[input_idx].value);
    pos += 8;

    /* nSequence for this specific input */
    write_u32le(buf + pos, 0xffffffffu);
    pos += 4;

    /* hashOutputs: commit to all outputs.
     * Changing any output (amount or destination) invalidates all signatures. */
    {
        unsigned char all_outputs[256];
        size_t op = 0;
        /* destination output */
        write_u64le(all_outputs + op, dest_value);
        op += 8;
        op += (size_t)write_varint(all_outputs + op, dest_spk_len);
        memcpy(all_outputs + op, dest_spk, dest_spk_len);
        op += dest_spk_len;
        /* change output (if present) */
        if (change_spk && change_value > 0)
        {
            write_u64le(all_outputs + op, change_value);
            op += 8;
            op += (size_t)write_varint(all_outputs + op, change_spk_len);
            memcpy(all_outputs + op, change_spk, change_spk_len);
            op += change_spk_len;
        }
        dsha256(all_outputs, op, buf + pos);
        pos += 32;
    }

    /* nLocktime = 0 */
    write_u32le(buf + pos, 0);
    pos += 4;

    /* sighash type = SIGHASH_ALL = 1 */
    write_u32le(buf + pos, 1);
    pos += 4;

    dsha256(buf, pos, sighash_out);
}

/* Transaction builder */

int tx_build_sign(const tx_utxo_t *utxos, int n_utxos,
                  const unsigned char *dest_prog, size_t dest_prog_len,
                  uint64_t dest_value,
                  const unsigned char *change_prog,
                  uint64_t change_value,
                  const unsigned char *privkey,
                  const unsigned char *pubkey,
                  char *tx_hex_out,
                  size_t tx_hex_size)
{
    /* Build the destination scriptPubKey based on the witness program length.
     *
     * P2WPKH (20-byte program, bc1q...):
     *   OP_0 OP_PUSH20 {20-byte hash160}       -> 0x00 0x14 {hash160}  (22 bytes)
     *
     * P2TR (32-byte program, bc1p...):
     *   OP_1 OP_PUSH32 {32-byte x-only pubkey} -> 0x51 0x20 {key}      (34 bytes)
     *
     * OP_0 = 0x00 signals witness version 0.
     * OP_1 = 0x51 signals witness version 1 (taproot).
     * These are not the same as OP_PUSH1, they use different opcodes
     * because witness versions are encoded specially in scriptPubKey. */
    unsigned char dest_spk[34];
    size_t dest_spk_len;
    if (dest_prog_len == 32)
    {
        dest_spk[0] = 0x51; /* OP_1 taproot */
        dest_spk[1] = 0x20; /* push 32 bytes */
        memcpy(dest_spk + 2, dest_prog, 32);
        dest_spk_len = 34;
    }
    else
    {
        dest_spk[0] = 0x00; /* OP_0 P2WPKH */
        dest_spk[1] = 0x14; /* push 20 bytes */
        memcpy(dest_spk + 2, dest_prog, 20);
        dest_spk_len = 22;
    }

    /* Change always goes back to our own P2WPKH address (index 0).
     * We don't need a new address for change, the wallet derives all
     * addresses from the same seed, so any index works for receiving. */
    unsigned char change_spk[22];
    change_spk[0] = 0x00;
    change_spk[1] = 0x14;
    if (change_prog)
        memcpy(change_spk + 2, change_prog, 20);

    int n_outputs = (change_value > 0) ? 2 : 1;

    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    /* Pre-compute signatures for all inputs.
     * Each input gets its own sighash (differs only in input_idx)
     * and its own ECDSA signature. */
    unsigned char sigs[16][73]; /* DER signature (max 72 bytes) + SIGHASH_ALL byte */
    size_t sig_lens[16];

    /* HASH160(pubkey) = RIPEMD160(SHA256(pubkey)). Needed for the scriptCode */
    unsigned char sha_tmp[32];
    unsigned char hash160[20];
    SHA256(pubkey, 33, sha_tmp);
    RIPEMD160(sha_tmp, 32, hash160);

    for (int i = 0; i < n_utxos; i++)
    {
        unsigned char sighash[32];
        bip143_sighash(utxos, n_utxos, i,
                       hash160,
                       dest_spk, dest_spk_len,
                       (change_value > 0) ? change_spk : NULL, 22,
                       dest_value, change_value,
                       sighash);

        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ecdsa_sign(ctx, &sig, sighash, privkey, NULL, NULL))
        {
            secp256k1_context_destroy(ctx);
            return -1;
        }
        /* Normalize to low-S form (BIP-62 / BIP-146).
         * ECDSA signatures have two valid (r, s) forms. Nodes reject
         * the high-S form as non-standard. This normalizes to low-S. */
        secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

        unsigned char der[72];
        size_t der_len = 72;
        secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig);

        memcpy(sigs[i], der, der_len);
        sigs[i][der_len] = 0x01; /* SIGHASH_ALL byte appended to the DER signature */
        sig_lens[i] = der_len + 1;
    }
    secp256k1_context_destroy(ctx);

    /* Serialize the complete segwit transaction into raw bytes.
     *
     * Segwit format (BIP-141):
     *   [version 4B][0x00 0x01][inputs][outputs][witness per input][locktime 4B]
     *
     * The 0x00 marker byte + 0x01 flag tell nodes this is a segwit tx.
     * Old nodes that don't understand segwit see the 0x00 input count and
     * treat it as an empty transaction (backwards compatibility). */
    unsigned char raw[4096];
    size_t pos = 0;

    write_u32le(raw + pos, 2);
    pos += 4; /* nVersion = 2 */

    /* Segwit marker and flag (required for segwit serialization) */
    raw[pos++] = 0x00; /* marker */
    raw[pos++] = 0x01; /* flag */

    pos += (size_t)write_varint(raw + pos, (uint64_t)n_utxos);

    /* Inputs: each input is outpoint(36) + scriptSig(1 byte = empty) + nSequence(4) */
    for (int i = 0; i < n_utxos; i++)
    {
        parse_txid(utxos[i].txid_hex, raw + pos);
        pos += 32;
        write_u32le(raw + pos, utxos[i].vout);
        pos += 4;
        raw[pos++] = 0x00; /* empty scriptSig. Segwit moves the script to the witness */
        write_u32le(raw + pos, 0xffffffffu);
        pos += 4; /* nSequence = final */
    }

    pos += (size_t)write_varint(raw + pos, (uint64_t)n_outputs);

    /* Destination output: value(8) + scriptPubKey length varint + scriptPubKey */
    write_u64le(raw + pos, dest_value);
    pos += 8;
    pos += (size_t)write_varint(raw + pos, dest_spk_len);
    memcpy(raw + pos, dest_spk, dest_spk_len);
    pos += dest_spk_len;

    /* Change output (omitted if change_value == 0 to avoid dust) */
    if (change_value > 0)
    {
        write_u64le(raw + pos, change_value);
        pos += 8;
        pos += (size_t)write_varint(raw + pos, 22); /* P2WPKH scriptPubKey is always 22 bytes */
        memcpy(raw + pos, change_spk, 22);
        pos += 22;
    }

    /* Witness data: one witness stack per input, in the same order as inputs.
     * For P2WPKH each witness stack has exactly 2 items: <sig> <pubkey>.
     * The 0x02 prefix is the stack item count. */
    for (int i = 0; i < n_utxos; i++)
    {
        raw[pos++] = 0x02; /* 2 witness stack items */
        /* Item 1: DER signature + sighash type byte */
        pos += (size_t)write_varint(raw + pos, sig_lens[i]);
        memcpy(raw + pos, sigs[i], sig_lens[i]);
        pos += sig_lens[i];
        /* Item 2: compressed public key (33 bytes) */
        raw[pos++] = 0x21; /* push 33 bytes */
        memcpy(raw + pos, pubkey, 33);
        pos += 33;
    }

    /* nLocktime = 0 (no time lock) */
    write_u32le(raw + pos, 0);
    pos += 4;

    if (pos * 2 + 1 > tx_hex_size)
        return -1;
    bytes_to_hex(raw, pos, tx_hex_out);
    return 0;
}
