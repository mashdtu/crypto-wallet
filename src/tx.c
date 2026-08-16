#include "tx.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <secp256k1.h>

/* ------------------------------------------------------------------ */
/* Serialization helpers                                                */
/* ------------------------------------------------------------------ */

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

/* Write a compact-size (varint) integer, return bytes written */
static int write_varint(unsigned char *buf, uint64_t v)
{
    if (v < 0xfd) {
        buf[0] = (unsigned char)v;
        return 1;
    } else if (v <= 0xffff) {
        buf[0] = 0xfd;
        buf[1] = (unsigned char)(v);
        buf[2] = (unsigned char)(v >> 8);
        return 3;
    } else if (v <= 0xffffffff) {
        buf[0] = 0xfe;
        write_u32le(buf + 1, (uint32_t)v);
        return 5;
    } else {
        buf[0] = 0xff;
        write_u64le(buf + 1, v);
        return 9;
    }
}

/* Parse a big-endian hex txid into 32 bytes (reversed to little-endian) */
static int parse_txid(const char *hex, unsigned char *out)
{
    if (strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned int byte;
        if (sscanf(hex + (62 - i * 2), "%02x", &byte) != 1) return -1;
        out[i] = (unsigned char)byte;
    }
    return 0;
}

/* Double-SHA256 */
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

/* ------------------------------------------------------------------ */
/* BIP-143 sighash                                                      */
/* ------------------------------------------------------------------ */

/*
 * Compute the BIP-143 sighash for a single P2WPKH input.
 *
 * SIGHASH_ALL (0x01)
 *
 * hash = dSHA256(
 *   version(4LE) ||
 *   hashPrevouts(32) || hashSequence(32) ||
 *   outpoint(36) || scriptCode(26) || value(8LE) || sequence(4LE) ||
 *   hashOutputs(32) ||
 *   locktime(4LE) || sighash_type(4LE)
 * )
 */
static void bip143_sighash(
    const tx_utxo_t *utxos, int n_utxos,
    int input_idx,
    const unsigned char *hash160,  /* 20-byte hash160 of pubkey */
    const unsigned char *dest_spk, size_t dest_spk_len,    /* dest scriptPubKey */
    const unsigned char *change_spk, size_t change_spk_len, /* change scriptPubKey (or NULL) */
    uint64_t dest_value,
    uint64_t change_value,
    unsigned char *sighash_out)
{
    unsigned char buf[4096];
    size_t pos = 0;

    /* nVersion = 2 */
    write_u32le(buf + pos, 2); pos += 4;

    /* hashPrevouts = dSHA256(all outpoints) */
    {
        unsigned char all_outpoints[36 * 16]; /* max 16 inputs */
        size_t op = 0;
        for (int i = 0; i < n_utxos; i++) {
            parse_txid(utxos[i].txid_hex, all_outpoints + op); op += 32;
            write_u32le(all_outpoints + op, utxos[i].vout);    op += 4;
        }
        dsha256(all_outpoints, op, buf + pos);
        pos += 32;
    }

    /* hashSequence = dSHA256(all sequences = 0xffffffff each) */
    {
        unsigned char all_seq[4 * 16];
        for (int i = 0; i < n_utxos; i++)
            write_u32le(all_seq + i * 4, 0xffffffffu);
        dsha256(all_seq, (size_t)n_utxos * 4, buf + pos);
        pos += 32;
    }

    /* outpoint of THIS input */
    parse_txid(utxos[input_idx].txid_hex, buf + pos); pos += 32;
    write_u32le(buf + pos, utxos[input_idx].vout);    pos += 4;

    /* scriptCode for P2WPKH:
     * 0x19 76 a9 14 {20-byte hash160} 88 ac
     * (the 0x19 is the length prefix of the scriptCode itself) */
    buf[pos++] = 0x19;
    buf[pos++] = 0x76; /* OP_DUP */
    buf[pos++] = 0xa9; /* OP_HASH160 */
    buf[pos++] = 0x14; /* push 20 bytes */
    memcpy(buf + pos, hash160, 20); pos += 20;
    buf[pos++] = 0x88; /* OP_EQUALVERIFY */
    buf[pos++] = 0xac; /* OP_CHECKSIG */

    /* value of this input (8LE) */
    write_u64le(buf + pos, utxos[input_idx].value); pos += 8;

    /* nSequence */
    write_u32le(buf + pos, 0xffffffffu); pos += 4;

    /* hashOutputs = dSHA256(all outputs serialized) */
    {
        unsigned char all_outputs[256];
        size_t op = 0;
        /* destination output */
        write_u64le(all_outputs + op, dest_value); op += 8;
        op += (size_t)write_varint(all_outputs + op, dest_spk_len);
        memcpy(all_outputs + op, dest_spk, dest_spk_len); op += dest_spk_len;
        /* change output (if present) */
        if (change_spk && change_value > 0) {
            write_u64le(all_outputs + op, change_value); op += 8;
            op += (size_t)write_varint(all_outputs + op, change_spk_len);
            memcpy(all_outputs + op, change_spk, change_spk_len); op += change_spk_len;
        }
        dsha256(all_outputs, op, buf + pos);
        pos += 32;
    }

    /* nLocktime = 0 */
    write_u32le(buf + pos, 0); pos += 4;

    /* sighash type = SIGHASH_ALL = 1 */
    write_u32le(buf + pos, 1); pos += 4;

    dsha256(buf, pos, sighash_out);
}

/* ------------------------------------------------------------------ */
/* Transaction builder                                                  */
/* ------------------------------------------------------------------ */

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
    /* Build dest scriptPubKey:
     * P2WPKH (20 bytes): OP_0 OP_PUSH20 {prog}  = 0x0014{prog}
     * P2TR   (32 bytes): OP_1 OP_PUSH32 {prog}  = 0x5120{prog} */
    unsigned char dest_spk[34];
    size_t dest_spk_len;
    if (dest_prog_len == 32) {
        dest_spk[0] = 0x51; /* OP_1 */
        dest_spk[1] = 0x20; /* push 32 bytes */
        memcpy(dest_spk + 2, dest_prog, 32);
        dest_spk_len = 34;
    } else {
        dest_spk[0] = 0x00; dest_spk[1] = 0x14;
        memcpy(dest_spk + 2, dest_prog, 20);
        dest_spk_len = 22;
    }

    /* Change is always P2WPKH (our own address) */
    unsigned char change_spk[22];
    change_spk[0] = 0x00; change_spk[1] = 0x14;
    if (change_prog) memcpy(change_spk + 2, change_prog, 20);

    int n_outputs = (change_value > 0) ? 2 : 1;

    /* secp256k1 context */
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

    /* Sign each input */
    unsigned char sigs[16][73]; /* DER sig + sighash byte */
    size_t sig_lens[16];

    /* Compute hash160 of pubkey for the scriptCode */
    unsigned char sha_tmp[32];
    unsigned char hash160[20];
    SHA256(pubkey, 33, sha_tmp);
    RIPEMD160(sha_tmp, 32, hash160);

    for (int i = 0; i < n_utxos; i++) {
        unsigned char sighash[32];
        bip143_sighash(utxos, n_utxos, i,
                       hash160,
                       dest_spk, dest_spk_len,
                       (change_value > 0) ? change_spk : NULL, 22,
                       dest_value, change_value,
                       sighash);

        secp256k1_ecdsa_signature sig;
        if (!secp256k1_ecdsa_sign(ctx, &sig, sighash, privkey, NULL, NULL)) {
            secp256k1_context_destroy(ctx);
            return -1;
        }
        /* Normalize to low-S */
        secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

        unsigned char der[72];
        size_t der_len = 72;
        secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig);

        memcpy(sigs[i], der, der_len);
        sigs[i][der_len] = 0x01; /* SIGHASH_ALL */
        sig_lens[i] = der_len + 1;
    }
    secp256k1_context_destroy(ctx);

    /* Serialize the transaction */
    unsigned char raw[4096];
    size_t pos = 0;

    /* version (2) */
    write_u32le(raw + pos, 2); pos += 4;

    /* segwit marker + flag */
    raw[pos++] = 0x00;
    raw[pos++] = 0x01;

    /* input count */
    pos += (size_t)write_varint(raw + pos, (uint64_t)n_utxos);

    /* inputs */
    for (int i = 0; i < n_utxos; i++) {
        parse_txid(utxos[i].txid_hex, raw + pos); pos += 32;
        write_u32le(raw + pos, utxos[i].vout);    pos += 4;
        raw[pos++] = 0x00; /* empty scriptSig (segwit) */
        write_u32le(raw + pos, 0xffffffffu);       pos += 4;
    }

    /* output count */
    pos += (size_t)write_varint(raw + pos, (uint64_t)n_outputs);

    /* destination output */
    write_u64le(raw + pos, dest_value); pos += 8;
    pos += (size_t)write_varint(raw + pos, dest_spk_len);
    memcpy(raw + pos, dest_spk, dest_spk_len); pos += dest_spk_len;

    /* change output */
    if (change_value > 0) {
        write_u64le(raw + pos, change_value); pos += 8;
        pos += (size_t)write_varint(raw + pos, 22);
        memcpy(raw + pos, change_spk, 22); pos += 22;
    }

    /* witness data for each input */
    for (int i = 0; i < n_utxos; i++) {
        raw[pos++] = 0x02; /* 2 witness items */
        /* signature */
        pos += (size_t)write_varint(raw + pos, sig_lens[i]);
        memcpy(raw + pos, sigs[i], sig_lens[i]); pos += sig_lens[i];
        /* pubkey */
        raw[pos++] = 0x21; /* 33 bytes */
        memcpy(raw + pos, pubkey, 33); pos += 33;
    }

    /* locktime */
    write_u32le(raw + pos, 0); pos += 4;

    if (pos * 2 + 1 > tx_hex_size) return -1;
    bytes_to_hex(raw, pos, tx_hex_out);
    return 0;
}
