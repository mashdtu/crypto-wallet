/*
 * network.c - mempool.space API client
 *
 * This module handles all outbound network traffic. It talks exclusively
 * to https://mempool.space/api (Bitcoin mainnet). No private key material
 * ever enters this file, everything is addressed by public address strings.
 *
 * The JSON parsing here is deliberately hand-rolled rather than using a
 * library.  The mempool.space response format is stable and well-defined,
 * and pulling in a JSON library would add a heavyweight dependency for
 * something that only needs to extract a handful of fields.
 *
 * All HTTP requests are made with libcurl with TLS verification enabled.
 * A 10-second timeout prevents the wallet from hanging on network failures.
 */

#define _DEFAULT_SOURCE
#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define API_BASE     "https://mempool.space/api"
#define TIMEOUT_SECS 10L

/* HTTP helpers */

/* A growable buffer that curl writes response data into.
 * We realloc on every chunk which is slightly inefficient but fine
 * for the small responses we are dealing with (a few KB at most). */
typedef struct {
    char  *data;
    size_t len;
} buf_t;

/* curl CURLOPT_WRITEFUNCTION callback.
 * Called for each chunk of response data as it arrives. */
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t bytes = size * nmemb;
    buf_t *b = (buf_t *)userdata;
    char *tmp = realloc(b->data, b->len + bytes + 1);
    if (!tmp) return 0;         /* returning 0 tells curl to abort */
    b->data = tmp;
    memcpy(b->data + b->len, ptr, bytes);
    b->len += bytes;
    b->data[b->len] = '\0';     /* keep it null-terminated for strstr/etc */
    return bytes;
}

/*
 * http_get()
 *
 * Performs a TLS-verified HTTP GET and stores the response body in out.
 * Caller must free(out->data) on success.
 * Returns 0 on success (HTTP 200), -1 on any error.
 */
static int http_get(const char *url, buf_t *out)
{
    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    out->data = malloc(1);
    out->len  = 0;
    if (!out->data) { curl_easy_cleanup(curl); return -1; }
    out->data[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, out);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT_SECS);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "bitcoin-wallet/1.0");
    /* Always verify the server's TLS certificate.
     * Without this, a MITM could feed us fake UTXOs or intercept broadcasts. */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code != 200) {
        free(out->data);
        out->data = NULL;
        return -1;
    }
    return 0;
}

/* Minimal JSON parsing */

/*
 * json_get_int()
 *
 * Finds the first "key": <integer> in a JSON string and returns the value.
 * This is intentionally simple, it doesn't handle nested objects or arrays
 * with the same key name, but that's fine for mempool.space's predictable
 * response format.
 *
 * Returns -1 if the key is not found (which is also a valid value in some
 * contexts, but all values we look for are non-negative in practice).
 */
static int64_t json_get_int(const char *json, const char *key)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ') p++;
    return (int64_t)strtoll(p, NULL, 10);
}

/* Public API functions */

/*
 * network_get_utxos()
 *
 * Fetches the unspent output set for an address.
 * mempool.space returns an array of objects like:
 *   [{"txid":"...","vout":N,"value":N,"status":{...}}, ...]
 *
 * We parse this with basic string searching rather than a JSON parser.
 * The pattern is: find "txid", then scan forward for "vout" and "value".
 * Each iteration of the while loop processes one UTXO entry.
 */
int network_get_utxos(const char *address, utxo_t *utxos, int max_utxos)
{
    char url[256];
    snprintf(url, sizeof(url), "%s/address/%s/utxo", API_BASE, address);

    buf_t resp = {0};
    if (http_get(url, &resp) != 0) return -1;

    int count = 0;
    const char *p = resp.data;
    while (count < max_utxos && (p = strstr(p, "\"txid\"")) != NULL) {
        /* Extract the 64-character hex txid string */
        const char *q = strchr(p, ':');
        if (!q) break;
        q++;
        while (*q == ' ' || *q == '"') q++;
        int i = 0;
        while (*q && *q != '"' && i < 64)
            utxos[count].txid[i++] = *q++;
        utxos[count].txid[i] = '\0';

        /* Extract vout (output index within the funding transaction) */
        const char *vout_p = strstr(p, "\"vout\"");
        if (!vout_p) break;
        vout_p = strchr(vout_p, ':');
        if (!vout_p) break;
        utxos[count].vout = (uint32_t)strtoul(vout_p + 1, NULL, 10);

        /* Extract value in satoshis */
        const char *val_p = strstr(p, "\"value\"");
        if (!val_p) break;
        val_p = strchr(val_p, ':');
        if (!val_p) break;
        utxos[count].value = (uint64_t)strtoull(val_p + 1, NULL, 10);

        count++;
        p++;
    }

    free(resp.data);
    return count;
}

/*
 * network_get_balance()
 *
 * GET /address/{addr} returns a JSON object with confirmed and unconfirmed
 * stats. We sum both so the balance reflects pending incoming transactions
 * (e.g. right after you receive a payment and it's still in the mempool).
 *
 * The "funded_txo_sum" field is the total sats ever received,
 * "spent_txo_sum" is the total sats ever spent. The difference is the
 * current confirmed balance. We then add in the unconfirmed delta from
 * "mempool_stats" for the pending balance.
 */
int64_t network_get_balance(const char *address)
{
    char url[256];
    snprintf(url, sizeof(url), "%s/address/%s", API_BASE, address);

    buf_t resp = {0};
    if (http_get(url, &resp) != 0) return -1;

    int64_t funded   = json_get_int(resp.data, "funded_txo_sum");
    int64_t spent    = json_get_int(resp.data, "spent_txo_sum");
    int64_t unc_in   = json_get_int(resp.data, "unconfirmed_tx_count");
    (void)unc_in;       /* not used directly, but tells us there's a mempool section */

    /* The mempool_stats block has its own funded/spent sums for unconfirmed txs */
    const char *mp = strstr(resp.data, "mempool_stats");
    int64_t mp_funded = 0, mp_spent = 0;
    if (mp) {
        mp_funded = json_get_int(mp, "funded_txo_sum");
        mp_spent  = json_get_int(mp, "spent_txo_sum");
    }

    free(resp.data);

    if (funded < 0 || spent < 0) return -1;
    return (funded - spent) + (mp_funded - mp_spent);
}

/*
 * network_broadcast()
 *
 * POSTs a raw signed transaction (as a hex string) to /tx.
 * On success, mempool.space responds with just the txid as plain text.
 * On failure, it responds with a descriptive error message.
 */
int network_broadcast(const char *tx_hex, char *txid_out)
{
    char url[128];
    snprintf(url, sizeof(url), "%s/tx", API_BASE);

    CURL *curl = curl_easy_init();
    if (!curl) return -1;

    buf_t resp = {0};
    resp.data = malloc(1);
    if (!resp.data) { curl_easy_cleanup(curl); return -1; }
    resp.data[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, tx_hex);     /* POST body = raw tx hex */
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, TIMEOUT_SECS);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "bitcoin-wallet/1.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK || http_code != 200) {
        fprintf(stderr, "broadcast error (HTTP %ld): %s\n",
                http_code, resp.data ? resp.data : "");
        free(resp.data);
        return -1;
    }

    /* Response body is the 64-character txid */
    if (txid_out && resp.data)
        strncpy(txid_out, resp.data, 64);
    if (txid_out) txid_out[64] = '\0';

    free(resp.data);
    return 0;
}

/*
 * network_get_btc_price()
 *
 * Fetches the current BTC price from mempool.space's price endpoint.
 * The response looks like: {"USD":65000,"EUR":60000,"GBP":52000,...}
 */
int network_get_btc_price(const char *currency, double *price_out)
{
    buf_t resp = {0};
    if (http_get("https://mempool.space/api/v1/prices", &resp) != 0) return -1;
    int64_t val = json_get_int(resp.data, currency);
    free(resp.data);
    if (val <= 0) return -1;
    *price_out = (double)val;
    return 0;
}

/* Transaction history */

/*
 * tx_net_for_addr()
 *
 * Scans a JSON range [json, end) for all references to addr and computes
 * the net satoshi change for that address in this transaction.
 *
 * Outputs  (vout.scriptpubkey_address == addr)         add to net.
 * Inputs   (vin.prevout.scriptpubkey_address == addr)  subtract from net.
 *
 * If the scriptpubkey block we found is inside a "prevout": object,
 * then it's an input being spent. We detect this by scanning back to
 * the nearest '{' and checking if it's preceded by "prevout":
 */
static int64_t tx_net_for_addr(const char *json, const char *end, const char *addr)
{
    int64_t net = 0;
    char pat[128];
    snprintf(pat, sizeof(pat), "\"scriptpubkey_address\":\"%s\"", addr);
    size_t plen = strlen(pat);
    const char *p = json;
    while ((p = strstr(p, pat)) != NULL && p < end) {
        /* Walk back to the opening { of the enclosing object */
        const char *brace = p;
        while (brace > json && *brace != '{') brace--;

        /* Check if that { is preceded by "prevout": (with optional whitespace).
         * If it is, this address appears in a vin.prevout, i.e. it's being spent. */
        const char *pre = brace > json ? brace - 1 : json;
        while (pre > json && (*pre == ' ' || *pre == '\t' || *pre == '\n' || *pre == '\r')) pre--;
        int in_prevout = (*pre == ':' && pre >= json + 9 &&
                          strncmp(pre - 9, "\"prevout\"", 9) == 0);

        /* Find the "value": field that belongs to this same object */
        const char *vp = strstr(p + plen, "\"value\":");
        if (vp && vp < end) {
            const char *vs = vp + 8;
            while (*vs == ' ') vs++;
            int64_t val = (int64_t)strtoll(vs, NULL, 10);
            if (in_prevout) net -= val;     /* being spent      (outflow) */
            else            net += val;     /* being received   (inflow) */
        }
        p += plen;
    }
    return net;
}

/*
 * network_get_address_txs()
 *
 * Fetches transaction history for a single address.
 * mempool.space returns an array of full transaction objects.
 *
 * Finding top-level transaction objects is tricky in raw JSON because txs
 * contain nested objects (vin, vout, status, etc.) that also have "txid" fields
 * in their prevout sections. We identify top-level tx objects by checking that
 * "txid":"<64hex>" is immediately followed by ,"version":.
 *
 * Once we have the tx boundaries, we hand it off to tx_net_for_addr()
 * to compute the net value change for our address.
 */
int network_get_address_txs(const char *address, addr_tx_t *txs, int max_txs)
{
    char url[256];
    snprintf(url, sizeof(url), "%s/address/%s/txs", API_BASE, address);
    buf_t resp = {0};
    if (http_get(url, &resp) != 0) return -1;
    if (!resp.data || resp.len == 0) { free(resp.data); return 0; }

    int count = 0;
    const char *p = resp.data;

    while (count < max_txs) {
        /* Look for the next "txid":"<64-char hex>" */
        const char *txid_key = strstr(p, "\"txid\":\"");
        if (!txid_key) break;

        const char *txid_val = txid_key + 8;

        /* Extract the 64-character txid */
        char txid[65] = {0};
        int i = 0;
        while (txid_val[i] && txid_val[i] != '"' && i < 64) {
            txid[i] = txid_val[i];
            i++;
        }
        if (i != 64) { p = txid_key + 1; continue; }

        /* Confirm this is a top-level tx: immediately after closing " must be ,"version": */
        const char *after = txid_val + 64 + 1;
        if (*after != ',' || strncmp(after + 1, "\"version\":", 10) != 0) {
            p = txid_key + 1;
            continue;
        }

        /* Find the opening brace of this tx object */
        const char *tx_start = txid_key;
        while (tx_start > resp.data && *tx_start != '{') tx_start--;

        /* Find "status":{ and walk its depth to find where the tx ends.
         * "status" is always the last field, so its closing } is also the
         * closing } of the entire tx object. */
        const char *status_p = strstr(txid_key, "\"status\":{");
        if (!status_p) { p = txid_key + 1; continue; }

        const char *sp = status_p + 9; /* points to opening { */
        int depth = 1;
        while (*sp && depth > 0) {
            if      (*sp == '{') depth++;
            else if (*sp == '}') depth--;
            sp++;
        }
        /* sp is now one past the closing } of status, which closes the tx object */
        const char *tx_end = sp;
        if (!tx_end || tx_end <= tx_start) { p = txid_key + 1; continue; }

        /* Parse confirmed flag and block_time from the status block */
        int confirmed = 0;
        uint32_t block_time = 0;
        const char *conf_p = strstr(status_p, "\"confirmed\":");
        if (conf_p && conf_p < tx_end) {
            const char *cv = conf_p + 12;
            while (*cv == ' ') cv++;
            confirmed = (strncmp(cv, "true", 4) == 0);
        }
        if (confirmed) {
            int64_t bt = json_get_int(status_p, "block_time");
            if (bt > 0) block_time = (uint32_t)bt;
        }

        txs[count].net_value  = tx_net_for_addr(tx_start, tx_end, address);
        txs[count].block_time = block_time;
        txs[count].confirmed  = confirmed;
        strncpy(txs[count].txid, txid, 64);
        txs[count].txid[64] = '\0';
        count++;

        p = tx_end;
    }

    free(resp.data);
    return count;
}
