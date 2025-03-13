import os
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext
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
    """Open file dialog to load Ethereum addresses from a file."""
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file_path:
        with open(file_path, "r") as f:
            global TARGET_ADDRESSES
            TARGET_ADDRESSES = set(line.strip().lower() for line in f.readlines())
        log_output.insert(tk.END, f"✅ Loaded {len(TARGET_ADDRESSES)} addresses from {file_path}\n")
        log_output.yview(tk.END)

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
    
    log_output.insert(tk.END, f"Checking: {mnemonic}\n")
    log_output.yview(tk.END)
    
    if eth_address.lower() in TARGET_ADDRESSES:
        log_output.insert(tk.END, f"\n🔥 MATCH FOUND! 🔥\nMnemonic: {mnemonic}\nAddress: {eth_address}\nPrivate Key: {priv_key}\n\n")
        log_output.yview(tk.END)
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
        log_output.insert(tk.END, "⚠️ Please load an address list before starting.\n")
        return
    log_output.insert(tk.END, "🚀 Starting search...\n")
    global search_thread
    search_thread = threading.Thread(target=parallel_search, daemon=True)
    search_thread.start()

def stop_search():
    """Stop the search process."""
    global RUNNING
    RUNNING = False
    log_output.insert(tk.END, "🛑 Search stopped.\n")
    log_output.yview(tk.END)

# GUI Setup
app = tk.Tk()
app.title("Mnemonic Address Checker")
app.geometry("600x400")

tk.Button(app, text="Load Address File", command=load_target_addresses).pack(pady=5)
tk.Button(app, text="Start Search", command=start_search).pack(pady=5)
tk.Button(app, text="Stop Search", command=stop_search).pack(pady=5)

log_output = scrolledtext.ScrolledText(app, height=15, width=70)
log_output.pack(pady=10)

app.mainloop()
