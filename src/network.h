#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>

/*
 * network.h - mempool.space testnet API queries
 *
 * All functions take public address strings only.
 * No key material ever enters this module.
 */

typedef struct
{
    char txid[65];
    uint32_t vout;
    uint64_t value; /* satoshis */
} utxo_t;

/*
 * network_get_utxos()
 *
 * Fetches unspent outputs for a P2WPKH address from mempool.space testnet.
 *
 * address   [in]  bech32 address string
 * utxos     [out] caller-allocated array to fill
 * max_utxos [in]  capacity of utxos array
 *
 * Returns number of UTXOs found (>= 0), or -1 on error.
 */
int network_get_utxos(const char *address, utxo_t *utxos, int max_utxos);

/*
 * network_get_balance()
 *
 * Returns confirmed + unconfirmed balance in satoshis for address,
 * or -1 on error.
 */
int64_t network_get_balance(const char *address);

/*
 * network_broadcast()
 *
 * POST a signed raw transaction (hex) to mempool.space testnet.
 * On success, writes the txid into txid_out (65-byte buffer).
 *
 * Returns 0 on success, -1 on failure.
 */
int network_broadcast(const char *tx_hex, char *txid_out);

/*
 * network_get_btc_price()
 *
 * Fetches current BTC price in the given currency ("USD" or "EUR")
 * from mempool.space mainnet price API.
 * Writes the price (USD or EUR per BTC) into price_out.
 *
 * Returns 0 on success, -1 on failure.
 */
int network_get_btc_price(const char *currency, double *price_out);

/*
 * network_get_address_txs()
 *
 * Fetches the transaction history for a single address.
 * net_value is positive for received, negative for spent (relative to address).
 * block_time is 0 for unconfirmed transactions.
 *
 * Returns number of transactions found (>= 0), or -1 on error.
 */
typedef struct
{
    char txid[65];
    int64_t net_value;
    uint32_t block_time;
    int confirmed;
} addr_tx_t;

int network_get_address_txs(const char *address, addr_tx_t *txs, int max_txs);

/*
 * network_get_fee_rate()
 *
 * Fetches the recommended fee rate (sat/vbyte) from mempool.space.
 * Writes the half-hour confirmation target rate into rate_out.
 *
 * Returns 0 on success, -1 on failure.
 */
int network_get_fee_rate(uint64_t *rate_out);

#endif /* NETWORK_H */
