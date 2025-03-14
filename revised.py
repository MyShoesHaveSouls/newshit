import os
import threading
from itertools import product
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins
from eth_utils import to_checksum_address

# Global Variables
TARGET_ADDRESSES = set()
RUNNING = False

# Load BIP-39 wordlist
with open("bip39_wordlist.txt", "r") as f:
    BIP39_WORDLIST = [word.strip() for word in f.readlines()]

def load_target_addresses():
    """Load Ethereum addresses from a file."""
    file_path = input("Enter the file path to load target addresses: ")
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            global TARGET_ADDRESSES
            TARGET_ADDRESSES = set(line.strip().lower() for line in f.readlines())
        print(f"✅ Loaded {len(TARGET_ADDRESSES)} addresses from {file_path}\n")
    else:
        print(f"⚠️ File not found: {file_path}")

def generate_eth_address(mnemonic):
    """Generate Ethereum address from a mnemonic phrase."""
    seed = Bip39SeedGenerator(mnemonic).Generate()
    bip44_wallet = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM).DeriveDefaultPath()
    priv_key = bip44_wallet.PrivateKey().Raw().ToHex()
    pub_key = bip44_wallet.PublicKey().ToAddress()
    eth_address = to_checksum_address(pub_key)
    return mnemonic, priv_key, eth_address

def check_mnemonic(mnemonic_words):
    """Generate and check mnemonic against target addresses."""
    mnemonic = " ".join(mnemonic_words)
    _, priv_key, eth_address = generate_eth_address(mnemonic)
    
    print(f"Checking: {mnemonic}")
    
    if eth_address.lower() in TARGET_ADDRESSES:
        print(f"\n🔥 MATCH FOUND! 🔥\nMnemonic: {mnemonic}\nAddress: {eth_address}\nPrivate Key: {priv_key}\n")
        with open("found_mnemonics.txt", "a") as f:
            f.write(f"{mnemonic}\n{priv_key}\n{eth_address}\n\n")

def parallel_search():
    """Parallelized mnemonic phrase search."""
    global RUNNING
    RUNNING = True
    word_combinations = product(BIP39_WORDLIST, repeat=12)
    
    for words in word_combinations:
        if not RUNNING:
            break
        check_mnemonic(words)

def start_search():
    """Start the search in a new thread."""
    if not TARGET_ADDRESSES:
        print("⚠️ Please load an address list before starting.\n")
        return
    print("🚀 Starting search...\n")
    global search_thread
    search_thread = threading.Thread(target=parallel_search, daemon=True)
    search_thread.start()

def stop_search():
    """Stop the search process."""
    global RUNNING
    RUNNING = False
    print("🛑 Search stopped.\n")

# Main script execution
if __name__ == "__main__":
    print("Mnemonic Address Checker")
    
    # Load target addresses
    load_target_addresses()
    
    # Ask user to start or stop the search
    while True:
        action = input("\nWould you like to start or stop the search? (start/stop/exit): ").strip().lower()
        if action == "start":
            start_search()
        elif action == "stop":
            stop_search()
        elif action == "exit":
            print("Exiting the script...")
            break
        else:
            print("Invalid command. Please enter 'start', 'stop', or 'exit'.")
