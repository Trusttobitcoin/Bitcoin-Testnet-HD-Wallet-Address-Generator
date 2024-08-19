# File: hdwithsteps.py

import os
import hashlib
import hmac
import ecdsa
import base58
import base64
from ripemd160 import ripemd160  
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import bech32

class BitcoinTestnetHDWallet:
    def __init__(self, wallet_file='wallet.enc'):
        self.wallet_file = wallet_file
        self.mnemonic = None
        self.seed = None
        self.master_key = None
        self.addresses = []

    def create_new_wallet(self):
        self.mnemonic = self.generate_mnemonic()
        self.seed = self.mnemonic_to_seed(self.mnemonic)
        self.master_key = self.generate_master_key()
        return self.mnemonic

    def load_existing_wallet(self, password):
        if not os.path.exists(self.wallet_file):
            raise FileNotFoundError("Wallet file not found.")
        self.mnemonic = self.load_wallet(password)
        self.seed = self.mnemonic_to_seed(self.mnemonic)
        self.master_key = self.generate_master_key()

    def generate_mnemonic(self):
        entropy = os.urandom(32)  # 256 bits of entropy
        return self.entropy_to_mnemonic(entropy)

    def entropy_to_mnemonic(self, entropy):
        word_list = self.load_word_list()
        checksum = hashlib.sha256(entropy).digest()[0]
        bits = bin(int.from_bytes(entropy, 'big'))[2:].zfill(256) + bin(checksum)[2:].zfill(8)[:8]
        return ' '.join(word_list[int(bits[i:i+11], 2)] for i in range(0, len(bits), 11))

    def mnemonic_to_seed(self, mnemonic, passphrase=""):
        mnemonic = mnemonic.encode('utf-8')
        salt = ("mnemonic" + passphrase).encode('utf-8')
        return hashlib.pbkdf2_hmac("sha512", mnemonic, salt, 2048, 64)

    def generate_master_key(self):
        key = hmac.new(b"Bitcoin seed", self.seed, hashlib.sha512).digest()
        return {'private_key': key[:32], 'chain_code': key[32:]}

    def derive_child_key(self, parent_key, index):
        if index >= 0x80000000:
            data = b'\x00' + parent_key['private_key'] + index.to_bytes(4, 'big')
        else:
            parent_public_key = self.private_to_public(parent_key['private_key'])
            data = parent_public_key + index.to_bytes(4, 'big')

        key = hmac.new(parent_key['chain_code'], data, hashlib.sha512).digest()
        child_private_key = (int.from_bytes(key[:32], 'big') + int.from_bytes(parent_key['private_key'], 'big')) % ecdsa.SECP256k1.order
        child_chain_code = key[32:]

        return {'private_key': child_private_key.to_bytes(32, 'big'), 'chain_code': child_chain_code}

    def derive_path(self, path):
        key = self.master_key
        for index in path:
            key = self.derive_child_key(key, index)
        return key

    def private_to_public(self, private_key):
        sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        return b'\x02' + vk.to_string()[:32] if vk.pubkey.point.y() % 2 == 0 else b'\x03' + vk.to_string()[:32]

    def public_key_to_address(self, public_key):
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = ripemd160(sha256_hash)
        version_payload = b'\x6f' + ripemd160_hash
        checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
        binary_address = version_payload + checksum
        return base58.b58encode(binary_address).decode('utf-8')

    def private_key_to_wif(self, private_key):
        version_key = b'\xef' + private_key + b'\x01'  # \xef for testnet, \x01 for compressed
        checksum = hashlib.sha256(hashlib.sha256(version_key).digest()).digest()[:4]
        return base58.b58encode(version_key + checksum).decode('utf-8')
    def public_key_to_p2pkh_address(self, public_key):
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = ripemd160(sha256_hash)
        version_payload = b'\x6f' + ripemd160_hash  # 0x6f is the version byte for testnet
        checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
        binary_address = version_payload + checksum
        return base58.b58encode(binary_address).decode('utf-8')

    def public_key_to_p2sh_address(self, public_key):
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = ripemd160(sha256_hash)
        redeemScript = b'\x00\x14' + ripemd160_hash
        scriptHash = ripemd160(hashlib.sha256(redeemScript).digest())
        version_payload = b'\xc4' + scriptHash  # 0xc4 is the version byte for testnet P2SH
        checksum = hashlib.sha256(hashlib.sha256(version_payload).digest()).digest()[:4]
        binary_address = version_payload + checksum
        return base58.b58encode(binary_address).decode('utf-8')

    def public_key_to_bech32_address(self, public_key):
        sha256_hash = hashlib.sha256(public_key).digest()
        ripemd160_hash = ripemd160(sha256_hash)
        return bech32.encode('tb', 0, ripemd160_hash)
    


    def generate_address(self, account=0, index=0, address_type=1):
        if address_type == 1:  # P2PKH
            path = [0x8000002C, 0x80000001, 0x80000000 + account, 0, index]
            path_string = f"m/44'/1'/{account}'/0/{index}"
        elif address_type == 2:  # P2SH (Nested SegWit)
            path = [0x80000031, 0x80000001, 0x80000000 + account, 0, index]
            path_string = f"m/49'/1'/{account}'/0/{index}"
        elif address_type == 3:  # Bech32 (Native SegWit)
            path = [0x80000054, 0x80000001, 0x80000000 + account, 0, index]
            path_string = f"m/84'/1'/{account}'/0/{index}"
        else:
            raise ValueError("Invalid address type")

        key = self.derive_path(path)
        private_key = key['private_key']
        public_key = self.private_to_public(private_key)
        
        if address_type == 1:
            address = self.public_key_to_p2pkh_address(public_key)
            address_type_str = "P2PKH"
        elif address_type == 2:
            address = self.public_key_to_p2sh_address(public_key)
            address_type_str = "P2SH"
        elif address_type == 3:
            address = self.public_key_to_bech32_address(public_key)
            address_type_str = "Bech32"

        wif = self.private_key_to_wif(private_key)
        address_info = {
            "path": path_string,
            "address": address,
            "address_type": address_type_str,
            "private_key": private_key.hex(),
            "public_key": public_key.hex(),
            "wif": wif
        }
        self.addresses.append(address_info)
        return address_info

    def generate_addresses(self, num_addresses, address_type):
        return [self.generate_address(index=i, address_type=address_type) for i in range(num_addresses)]


    def load_word_list(self):
        with open("bip39_wordlist.txt", "r") as f:
            return [w.strip() for w in f.readlines()]

    def save_wallet(self, password):
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        encrypted_mnemonic = f.encrypt(self.mnemonic.encode())
        with open(self.wallet_file, 'wb') as file:
            file.write(salt + encrypted_mnemonic)

    def load_wallet(self, password):
        with open(self.wallet_file, 'rb') as file:
            data = file.read()
        salt = data[:16]
        encrypted_mnemonic = data[16:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        try:
            decrypted_mnemonic = f.decrypt(encrypted_mnemonic)
            return decrypted_mnemonic.decode()
        except:
            raise ValueError("Invalid password or corrupted wallet file.")

    def get_wallet_info(self):
        return {
            "mnemonic": self.mnemonic,
            "seed": self.seed.hex() if self.seed else None,
            "addresses": self.addresses
        }
