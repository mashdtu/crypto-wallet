#ifndef WALLET_H
#define WALLET_H

#include <stdint.h>

/*
 * wallet.h - BIP-32/84 key derivation and address generation
 *
 * All functions derive keys from a 64-byte seed.
 * Path: m/84'/1'/0'/0/<index> (testnet P2WPKH)
 */

/*
 * wallet_derive_address()
 *
 * Derives the P2WPKH testnet address at m/84'/1'/0'/0/<index>.
 *
 * seed         [in]  64-byte BIP-32 seed
 * index        [in]  address index (0, 1, 2, ...)
 * address_out  [out] caller buffer, at least 73 bytes
 *
 * Returns 0 on success, -1 on failure.
 */
int wallet_derive_address(const unsigned char *seed,
                          uint32_t index,
                          char *address_out);

/*
 * wallet_derive_key()
 *
 * Derives private key and compressed public key at m/84'/1'/0'/0/<index>.
 *
 * seed        [in]  64-byte BIP-32 seed
 * index       [in]  address index
 * privkey_out [out] 32-byte private key
 * pubkey_out  [out] 33-byte compressed public key
 * hash160_out [out] 20-byte HASH160(pubkey) -- the witness program
 *
 * Returns 0 on success, -1 on failure.
 */
int wallet_derive_key(const unsigned char *seed,
                      uint32_t index,
                      unsigned char *privkey_out,
                      unsigned char *pubkey_out,
                      unsigned char *hash160_out);

#endif
