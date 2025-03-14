import os
import concurrent.futures
import sys
import time
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

def flash_mnemonic(mnemonic_words, delay=0.05):
    """Rapidly flash the current mnemonic in the terminal."""
    mnemonic = " ".join(mnemonic_words)
    sys.stdout.write("\r" + "Checking mnemonic: " + mnemonic)
    sys.stdout.flush()
    time.sleep(delay)  # Adjust the speed of flashing

def check_mnemonic(mnemonic_words):
    """Generate and check mnemonic against target addresses."""
    mnemonic = " ".join(mnemonic_words)
    flash_mnemonic(mnemonic_words)  # Flash the mnemonic
    
    _, priv_key, eth_address = generate_eth_address(mnemonic)
    
    if eth_address.lower() in TARGET_ADDRESSES:
        print(f"\nMatch found! Mnemonic: {mnemonic} | Private Key: {priv_key} | Address: {eth_address}")
        save_matches_to_file(mnemonic, priv_key, eth_address)  # Save match to file

def parallel_search(batch_size=1000):
    """Parallelized mnemonic phrase search with better distribution of words."""
    # Split the bip39 word list into smaller chunks for faster parallelism
    chunk_size = len(bip39_wordlist) // 4  # Create 4 chunks
    word_combinations_chunks = []

    for i in range(0, len(bip39_wordlist), chunk_size):
        word_combinations_chunks.append(bip39_wordlist[i:i + chunk_size])

    # Now, instead of generating all 12 words in a single combination,
    # we'll distribute the work of each chunk across multiple processes
    with concurrent.futures.ProcessPoolExecutor() as executor:
        while True:
            # Create batches of 12 word combinations by taking combinations from each chunk
            batches = []
            for _ in range(batch_size):
                word_chunk_combination = [list(product(chunk, repeat=3)) for chunk in word_combinations_chunks]  # Each chunk is handled in parallel
                batches.extend(word_chunk_combination)

            # Submit the batches of mnemonic checks to the executor for parallel processing
            executor.map(check_mnemonic, batches)

if __name__ == "__main__":
    parallel_search()
