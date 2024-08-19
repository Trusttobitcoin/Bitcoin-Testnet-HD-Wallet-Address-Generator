# File: main.py
from hdwithsteps import BitcoinTestnetHDWallet

def prompt_address_type():
    while True:
        print("\nSelect the type of testnet address to generate:")
        print("1. P2PKH (Legacy)")
        print("2. P2SH (Nested SegWit)")
        print("3. Bech32 (Native SegWit)")
        choice = input("Enter your choice (1-3): ")
        if choice in ['1', '2', '3']:
            return int(choice)
        print("Invalid choice. Please try again.")

def main():
    # Create a wallet instance (it will use 'wallet.enc' by default)
    wallet = BitcoinTestnetHDWallet()
    
    try:
        # Try to load an existing wallet
        password = input("Enter wallet password: ")
        wallet.load_existing_wallet(password)
        print("Existing wallet loaded successfully.")
    except FileNotFoundError:
        # If wallet doesn't exist, create a new one
        print("No existing wallet found. Creating a new wallet.")
        mnemonic = wallet.create_new_wallet()
        print("New wallet created. Please save your mnemonic phrase:")
        print(mnemonic)
        password = input("Enter a password to encrypt your wallet: ")
        wallet.save_wallet(password)
    except ValueError as e:
        print(f"Error loading wallet: {e}")
        return

    # Prompt for address type
    address_type = prompt_address_type()

    # Generate 5 addresses of the chosen type
    addresses = wallet.generate_addresses(5, address_type)

    # Display wallet info
    wallet_info = wallet.get_wallet_info()
    print("\nWallet Information:")
    print(f"Seed (hex): {wallet_info['seed']}")
    print("\nDerived Addresses:")
    for addr in wallet_info['addresses']:
        print(f"Path: {addr['path']}")
        print(f"Address Type: {addr['address_type']}")
        print(f"Address: {addr['address']}")
        print(f"Private Key: {addr['private_key']}")
        print(f"Public Key: {addr['public_key']}")
        print(f"WIF: {addr['wif']}")
        print()

if __name__ == "__main__":
    main()
