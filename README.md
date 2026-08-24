# Bitcoin Wallet

DISCLAIMER: THIS PROJECT IS NOT GUARANTEED SAFE AND IS THEREFORE NOT APPLICABLE FOR COMMERCIAL OR PERSONAL FINANCIAL USE.

A self-custody Bitcoin mainnet wallet written in C. The private key never touches your hard drive, it lives encrypted on a USB drive and is decrypted in memory only while a command is running, then wiped immediately.

This code can be ran on a personal device, however for maximum security it is intended to be altered to run on an offline device, which is only to be used only for the purpose of signing transactions. As the code is currently, it is not fit to run on such a device, though feel free to fork this repository and adapt it yourself.

## What it does

- Generates a 24-word BIP-39 mnemonic and derives a Bitcoin mainnet wallet from it.
- Encrypts the 64-byte master seed with AES-256-GCM and stores it directly on a USB drive.
- Derives P2WPKH (`bc1q...`) addresses following BIP-84 (`m/84'/0'/0'/0/<index>`).
- Sends to any mainnet segwit address: P2WPKH (`bc1q`) or P2TR taproot (`bc1p`).
- Shows balance, transaction history, and fiat equivalent via mempool.space.
- Clones the encrypted seed to a second USB as a backup.

## Security model

| What is stored on USB        | What stays in memory only |
| ---------------------------- | ------------------------- |
| 124-byte encrypted blob      | 64-byte seed              |
| Random salt + IV             | 32-byte private key       |
| AES-256-GCM ciphertext + tag | Derived addresses         |

The encryption key is never written anywhere, it's derived fresh every time from your password + the random salt via PBKDF2-HMAC-SHA512 (100,000 rounds).

If someone steals your USB, they have an encrypted blob. Without your password they cannot decrypt it. If they brute-force common passwords, 100k PBKDF2 rounds means about 1 second per guess on fast hardware.

**Back up your mnemonic offline. If you lose both the USB and the mnemonic, your funds are gone permanently.**

## Requirements

- Linux (`/sys/block`, `getentropy()`, `udisksctl`)
- gcc
- OpenSSL 3
- libsecp256k1
- libcurl

## Building

First install the dependencies for your distro:

**Debian / Ubuntu:**

```bash
sudo apt install gcc libssl-dev libsecp256k1-dev libcurl4-openssl-dev pkg-config udisks2 util-linux
```

**Fedora / RHEL:**

```bash
sudo dnf install gcc openssl-devel libsecp256k1-devel libcurl-devel pkg-config udisks2 util-linux
```

**Arch:**

```bash
sudo pacman -S gcc openssl libsecp256k1 curl pkg-config udisks2 util-linux
```

Then build and install:

```bash
make
make install
```

`make install` copies the binary to `~/.local/bin/wallet`. Add that to your PATH if it isn't already:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

## Setup

### 1. Format a USB drive

Wipes the drive and prepares it for use as a wallet key:

```bash
sudo wallet usb-format
```

This runs `wipefs -a` to remove any existing partition tables and filesystems.
The encrypted seed will be written directly to the raw device (offset 0),
with no filesystem or partition table.

### 2. Create a wallet

```bash
sudo wallet init
```

- Generates 32 bytes of entropy via `getentropy()`
- Derives a 24-word BIP-39 mnemonic
- Shows the mnemonic.
- Asks for a password to encrypt the seed
- Writes the encrypted seed to the USB

### 3. Restore an existing wallet

```bash
sudo wallet restore
```

Enter your 24 words one at a time. Each word is validated against the BIP-39
wordlist as you type. Shows the first address at the end so you can verify
the wallet was restored correctly before setting a password.

## Commands

All commands that access the seed require `sudo` (raw block device access).

```
wallet [--file <path>] init                          generate a new wallet
wallet [--file <path>] restore                       restore from mnemonic
wallet [--file <path>] address <index>               show receive address at index
wallet [--file <path>] balance [gap]                 show total balance
wallet [--file <path>] history [gap]                 show transaction history
wallet [--file <path>] send <addr> <sat> [fee_sat]   send funds
wallet [--file <path>] check <address>               check if address is yours
wallet usb-clone                                     clone encrypted seed to a second USB
wallet usb-format                                    wipe a USB drive for use as wallet key
wallet eject                                         safely eject the USB
wallet settings                                      configure display currency (USD, EUR, etc.)
```

### `--file` override

If you want to test with a file instead of a USB:

```bash
wallet --file /tmp/seed.bin init
wallet --file /tmp/seed.bin balance
```

### Sending

```bash
sudo wallet send bc1q... 50000
sudo wallet send bc1p... 50000 2000     # custom fee
```

- Amount and fee are in satoshis
- Default fee is 1000 sat if not specified
- Destination can be P2WPKH (`bc1q`) or P2TR taproot (`bc1p`)
- Shows a confirmation screen before broadcasting
- If the destination is one of your own addresses, it's labelled "(yours, index N)"

### Balance scanning

```bash
sudo wallet balance     # uses default gap limit of 20
sudo wallet balance 50  # scan until 50 consecutive empty addresses
```

### Cloning your USB

To make a backup USB:

```bash
sudo wallet usb-clone
```

1. Reads the encrypted seed from the current USB
2. Prompts you to remove the USB
3. Waits until it's gone
4. Prompts you to insert the target USB
5. Waits until a USB is detected
6. Asks for confirmation before writing
7. Writes the same 124-byte encrypted blob to the new USB

The clone contains the exact same encrypted data. Both USB drives use the
same password to decrypt.

### Ejecting

```bash
sudo wallet eject
```

Flushes write buffers and powers off the USB via `udisksctl`.
Safe to physically unplug after this.

## Display currency

```bash
wallet settings
```

Supported: USD, EUR, GBP, CAD, CHF, AUD, JPY. Set to "None" to disable fiat display.

The currency preference is saved to `~/.config/btc-wallet/currency`.

## Dependencies

- **OpenSSL 3**: SHA-256, RIPEMD-160, HMAC-SHA512, PBKDF2, AES-256-GCM, RAND_bytes
- **libsecp256k1**: EC key generation, ECDSA signing
- **libcurl**: HTTPS requests to mempool.space
- **udisks2**: safe USB ejection (optional, for `eject` command)
- **util-linux**: `wipefs` for `usb-format`
