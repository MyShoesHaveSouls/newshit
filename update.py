import os
from itertools import product
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins

def load_target_addresses(file_path):
    """Open and load target addresses from a file."""
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return set()
    with open(file_path, "r") as f:
        return set(line.strip().lower() for line in f.readlines())

def load_bip39_wordlist():
    """Load BIP-39 wordlist from a file."""
    file_path = "bip39_wordlist.txt"
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return []
    with open(file_path, "r") as f:
        return [word.strip() for word in f.readlines()]

def generate_eth_address(mnemonic):
    """Generate Ethereum address from a mnemonic phrase."""
    seed = Bip39SeedGenerator(mnemonic).Generate()
    bip44_mst_ctx = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0).Change(0).AddressIndex(0)
    eth_address = bip44_acc_ctx.PublicKey().ToAddress()
    priv_key = bip44_acc_ctx.PrivateKey().Raw().ToHex()
    return mnemonic, priv_key, eth_address

def check_mnemonic(mnemonic_words, target_addresses):
    """Generate and check mnemonic against target addresses."""
    mnemonic = " ".join(mnemonic_words)
    _, priv_key, eth_address = generate_eth_address(mnemonic)
    
    if eth_address.lower() in target_addresses:
        print(f"✅ Match found! Address: {eth_address} | Private Key: {priv_key}\n")
        with open("found_mnemonics.txt", "a") as f:
            f.write(f"{mnemonic}\n{priv_key}\n{eth_address}\n\n")

def main():
    """Main function to read wordlist, generate mnemonics, and check against target addresses."""
    target_file = "ethrichlist.txt"  # Now automatically using the file
    wordlist_file = "bip39_wordlist.txt"  # File containing BIP-39 words
    target_addresses = load_target_addresses(target_file)
    if not target_addresses:
        print("Error: Target address list is empty or not loaded.")
        return
    
    words_list = load_target_addresses("bip39_wordlist.txt")
    if not words_list:
        print("Error: Could not load bip39 wordlist.")
        return
    
    word_count = 12  # Mnemonic length
    
    for words in product(words_list, repeat=word_count):
        check_mnemonic(words, target_addresses)
        
if __name__ == "__main__":
    main()
