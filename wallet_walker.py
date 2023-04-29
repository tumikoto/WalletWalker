#
# Script to recover a Bitcoin wallet private key for a wallet address by identifying the seed data used (brainwallet) or by checking known wallet keys (poor man's brainflayer)
# python wallet_walker.py <btc_address> wordlist.txt <pass|key>
#

import sys
import hashlib
import ecdsa
import base58
import binascii


def generate_btc_data(do_hash, seed):
    # Generate a Bitcoin private/public key pair from a given seed
    if do_hash:
        # Derive the private key from the seed using SHA256
        privkey_bytes = hashlib.sha256(seed.encode()).digest()
    else:
        # Treat the input as a hex key and skip the SHA256 hash
        privkey_bytes = bytes.fromhex(seed)
    # Create a curve object using secp256k1, which is the elliptic curve used by Bitcoin
    curve = ecdsa.curves.SECP256k1
    # Create a private key object from the byte string and the curve object
    privkey = ecdsa.SigningKey.from_string(privkey_bytes, curve=curve)
    # Derive the public key from the private key
    pubkey = privkey.get_verifying_key()
    # Convert the public key to an uncompressed byte string
    pubkey_bytes = pubkey.to_string('uncompressed')
    # Add the prefix byte for mainnet Bitcoin public keys (0x04) to the uncompressed public key bytes
    pubkey_bytes_with_prefix = pubkey_bytes
    # Calculate the Bitcoin address from the public key using RIPEMD-160 and Base58Check encoding
    pubkey_hash = hashlib.new('ripemd160', hashlib.sha256(pubkey_bytes_with_prefix).digest()).digest()
    address = base58.b58encode_check(b'\x00' + pubkey_hash).decode()
    # Convert the private key to a WIF (wallet import format) string
    privkey_wif = base58.b58encode_check(b'\x80' + privkey_bytes).decode()
    # Return the calculated values
    return binascii.hexlify(bytearray(privkey.to_string())).decode(), privkey_wif, address


def main():
    # Get the Bitcoin address from the command-line argument
    target_addr = sys.argv[1]
    # Get the filename of the list of strings from the command-line argument
    filename = sys.argv[2]
    # Get the mode (derive key from string or treat string as the hex key)
    mode = sys.argv[3].lower()
    # Open the file and read the contents into a list of strings
    with open(filename, 'r') as f:
        strings = f.read().splitlines()
    # Loop over each string in the list
    print(f"\nLoaded {len(strings)} strings from wordlist\n")
    # Print table headers
    if mode == "pass":
        print(f"PRIVATE KEY (HEX){' '*55}WIF (U){' '*49}ADDRESS (U){' '*29}SEED")
        print(f"-----------------{' '*55}-------{' '*49}-----------{' '*29}----")
    else:
        print(f"PRIVATE KEY (HEX){' '*55}WIF (U){' '*49}ADDRESS (U)")
        print(f"-----------------{' '*55}-------{' '*49}-----------")
    for seed in strings:
        if mode == "pass":
            # Calculate Bitcoin private/public key pair and other data from the SHA256 hash of the string
            privkey_hex, privkey_wif, addr = generate_btc_data(True, seed)
        elif mode == "key":
            # Calculate Bitcoin private/public key pair and other data from the hex key
            privkey_hex, privkey_wif, addr = generate_btc_data(False, seed)
        else:
            return
        if mode == "pass":
            print(f"{privkey_hex}\t{privkey_wif}\t{addr}\t{seed}")
        else:
            print(f"{privkey_hex}\t{privkey_wif}\t{addr}")
        # Compare the derived address to the target address
        if addr == target_addr:
            # Abort loop if match is found
            print(f"\nMatch found!\n")
            return
    # End of loop reached with no match
    print("\nSeed for wallet not found in wordlist\n")


if __name__ == '__main__':
    main()
