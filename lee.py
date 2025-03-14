import os
import concurrent.futures
import sys
from itertools import product
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from eth_utils import to_checksum_address
from web3 import Web3

# Load BIP-39 wordlist
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(SCRIPT_DIR, "bip39_wordlist.txt")
with open(WORDLIST_PATH, "r") as f:
    bip39_wordlist = [word.strip() for word in f.readlines()]

# Load target Ethereum addresses
with open("ethrichlist.txt", "r") as f:
    TARGET_ADDRESSES = set(line.strip().lower() for line in f.readlines())

def generate_eth_address(mnemonic):
    """Generate Ethereum address from a mnemonic phrase."""
    seed = Bip39SeedGenerator(mnemonic).Generate()
    bip44_wallet = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM).DeriveDefaultPath()
    priv_key = bip44_wallet.PrivateKey().Raw().ToHex()
    pub_key = bip44_wallet.PublicKey().ToAddress()
    eth_address = to_checksum_address(pub_key)
    return mnemonic, priv_key, eth_address

def save_matches_to_file(mnemonic, priv_key, eth_address):
    """Save matching mnemonic, private key, and Ethereum address to a file."""
    with open("found_matches.txt", "a") as f:
        f.write(f"Mnemonic: {mnemonic}\nPrivate Key: {priv_key}\nEthereum Address: {eth_address}\n\n")

def display_scrolling_mnemonic(mnemonic_words):
    """Display the current mnemonic as a scrolling text in the console."""
    mnemonic = " ".join(mnemonic_words)
    sys.stdout.write("\r" + "Checking mnemonic: " + mnemonic)
    sys.stdout.flush()

def check_mnemonic(mnemonic_words):
    """Generate and check mnemonic against target addresses."""
    mnemonic = " ".join(mnemonic_words)
    display_scrolling_mnemonic(mnemonic)  # Display scrolling mnemonic

    _, priv_key, eth_address = generate_eth_address(mnemonic)
    
    if eth_address.lower() in TARGET_ADDRESSES:
        print(f"\nMatch found! Mnemonic: {mnemonic} | Private Key: {priv_key} | Address: {eth_address}")
        save_matches_to_file(mnemonic, priv_key, eth_address)  # Save match to file

def parallel_search(batch_size=1000):
    """Parallelized mnemonic phrase search."""
    word_combinations = product(bip39_wordlist, repeat=12)
    
    with concurrent.futures.ProcessPoolExecutor() as executor:
        while True:
            batch = [next(word_combinations) for _ in range(batch_size)]
            executor.map(check_mnemonic, batch)

if __name__ == "__main__":
    parallel_search()
