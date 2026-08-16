#define _DEFAULT_SOURCE
#include "network.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define API_BASE "https://mempool.space/testnet4/api"
#define TIMEOUT_SECS 10L

/* Growing buffer for curl response */
typedef struct {
    char  *data;
    size_t len;
} buf_t;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t bytes = size * nmemb;
    buf_t *b = (buf_t *)userdata;
    char *tmp = realloc(b->data, b->len + bytes + 1);
    if (!tmp) return 0;
    b->data = tmp;
    memcpy(b->data + b->len, ptr, bytes);
    b->len += bytes;
    b->data[b->len] = '\0';
    return bytes;
}

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
    /* Verify TLS certificates */
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

/*
 * Minimal JSON integer extraction.
 * Finds the first occurrence of "key": <number> and returns the number.
 * Returns -1 if not found.
 */
static int64_t json_get_int(const char *json, const char *key)
{
    /* Build search pattern: "key": */
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ') p++;
    return (int64_t)strtoll(p, NULL, 10);
}

/*
 * Parse a UTXO array from mempool.space JSON:
 * [{"txid":"...","vout":N,"value":N,"status":{...}}, ...]
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
        /* txid */
        const char *q = strchr(p, ':');
        if (!q) break;
        q++;
        while (*q == ' ' || *q == '"') q++;
        int i = 0;
        while (*q && *q != '"' && i < 64)
            utxos[count].txid[i++] = *q++;
        utxos[count].txid[i] = '\0';

        /* vout */
        const char *vout_p = strstr(p, "\"vout\"");
        if (!vout_p) break;
        vout_p = strchr(vout_p, ':');
        if (!vout_p) break;
        utxos[count].vout = (uint32_t)strtoul(vout_p + 1, NULL, 10);

        /* value */
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

int64_t network_get_balance(const char *address)
{
    char url[256];
    snprintf(url, sizeof(url), "%s/address/%s", API_BASE, address);

    buf_t resp = {0};
    if (http_get(url, &resp) != 0) return -1;

    /* Sum funded_txo_sum - spent_txo_sum for confirmed,
     * plus unconfirmed deltas */
    int64_t funded   = json_get_int(resp.data, "funded_txo_sum");
    int64_t spent    = json_get_int(resp.data, "spent_txo_sum");
    int64_t unc_in   = json_get_int(resp.data, "unconfirmed_tx_count");

    /* mempool.space also provides mempool_stats for unconfirmed balance */
    const char *mp = strstr(resp.data, "mempool_stats");
    int64_t mp_funded = 0, mp_spent = 0;
    if (mp) {
        mp_funded = json_get_int(mp, "funded_txo_sum");
        mp_spent  = json_get_int(mp, "spent_txo_sum");
    }
    (void)unc_in;

    free(resp.data);

    if (funded < 0 || spent < 0) return -1;
    return (funded - spent) + (mp_funded - mp_spent);
}

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
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, tx_hex);
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

    /* Response body is the txid */
    if (txid_out && resp.data)
        strncpy(txid_out, resp.data, 64);
    if (txid_out) txid_out[64] = '\0';

    free(resp.data);
    return 0;
}

int network_get_btc_price(const char *currency, double *price_out)
{
    buf_t resp = {0};
    /* Use mainnet price endpoint — testnet BTC has no market price */
    if (http_get("https://mempool.space/api/v1/prices", &resp) != 0) return -1;
    int64_t val = json_get_int(resp.data, currency);
    free(resp.data);
    if (val <= 0) return -1;
    *price_out = (double)val;
    return 0;
}
