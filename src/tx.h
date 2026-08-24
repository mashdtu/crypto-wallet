#ifndef TX_H
#define TX_H

#include <stdint.h>
#include <stddef.h>

typedef struct
{
    char txid_hex[65]; /* hex string, as returned by mempool.space */
    uint32_t vout;
    uint64_t value; /* satoshis */
} tx_utxo_t;

/*
 * tx_build_sign()
 *
 * Builds and signs a P2WPKH transaction.
 *
 * Inputs are all from the same keypair (privkey/pubkey/hash160).
 * Produces at most 2 outputs: destination + optional change.
 * If change_value == 0 the change output is omitted.
 *
 * utxos         [in]  array of UTXOs to spend
 * n_utxos       [in]  number of UTXOs
 * dest_prog     [in]  20-byte witness program of destination address
 * dest_value    [in]  satoshis to send
 * change_prog   [in]  20-byte witness program of our change address
 * change_value  [in]  satoshis to return as change (0 = no change output)
 * privkey       [in]  32-byte private key
 * pubkey        [in]  33-byte compressed public key
 * tx_hex_out    [out] caller buffer to receive hex-encoded signed tx
 * tx_hex_size   [in]  size of tx_hex_out (must be >= 4096)
 *
 * Returns 0 on success, -1 on failure.
 */
int tx_build_sign(const tx_utxo_t *utxos, int n_utxos,
                  const unsigned char *dest_prog, size_t dest_prog_len,
                  uint64_t dest_value,
                  const unsigned char *change_prog,
                  uint64_t change_value,
                  const unsigned char *privkey,
                  const unsigned char *pubkey,
                  char *tx_hex_out,
                  size_t tx_hex_size);

#endif /* TX_H */
