# Bitcoin Testnet HD Wallet Address Generator
![Bitcoin Testnet HD Wallet Address Generator](https://github.com/Trusttobitcoin/Bitcoin-Testnet-HD-Wallet-Address-Generator/blob/main/Capture2.JPG?raw=true)
A Python tool for creating and managing hierarchical deterministic (HD) wallets and generating various types of Bitcoin testnet addresses. This project implements BIP32, BIP39, and BIP44 standards for a comprehensive testnet wallet experience.

## Features

- Create new HD wallets or load existing ones
- Generate multiple address types for Bitcoin testnet:
  - P2PKH (Legacy)
  - P2SH (Nested SegWit)
  - Bech32 (Native SegWit)
- Secure wallet encryption using Fernet
- Derive addresses using BIP32, BIP39, and BIP44 standards
- Display comprehensive wallet information including seed, addresses, private keys, and WIF

## Project Structure

- `main.py`: The entry point of the application. It handles user interaction and calls functions from hdwithsteps.py.
- `hdwithsteps.py`: Contains the `BitcoinTestnetHDWallet` class implementation. This is the core of the wallet functionality.
- `ripemd160.py`: A custom implementation of the RIPEMD160 hashing algorithm, ensuring compatibility across different systems.
- `bip39_wordlist.txt`: Word list for mnemonic generation.

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/Trusttobitcoin/Bitcoin-Testnet-HD-Wallet-Address-Generator.git
   cd Bitcoin-Testnet-HD-Wallet-Address-Generator
   ```

2. Install the required dependencies:
   ```
   pip install ecdsa base58 cryptography bech32
   ```

## Usage

Run the main script to create a new wallet or load an existing one:

```
python main.py
```

Follow the prompts to:
- Enter a password for a new wallet or to decrypt an existing one
- Choose the type of address to generate
- View generated addresses and wallet information

## Dependencies

- ecdsa
- base58
- cryptography
- bech32

## Security Note

This address generator is intended for educational purposes and use on Bitcoin's testnet only. Do not use it to manage real funds on the Bitcoin mainnet without proper security audits and enhancements.



## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the Bitcoin community for the BIP standards that make this project possible.
- The custom RIPEMD160 implementation is based on the test-only implementation from Bitcoin Core.
