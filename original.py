import os
from itertools import product
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins

def load_target_addresses(file_path):
    """Load Ethereum addresses from a specified file."""
    if not os.path.exists(file_path):
        print(f"Error: {file_path} not found.")
        return set()
    with open(file_path, "r") as f:
        return set(line.strip().lower() for line in f.readlines())

def generate_eth_address(mnemonic):
    """Generate Ethereum address from a mnemonic phrase."""
    seed = Bip39SeedGenerator(mnemonic).Generate()
    bip44_mst_ctx = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM)
    bip44_acc_ctx = bip44_mst_ctx.Purpose().Coin().Account(0)
    bip44_chg_ctx = bip44_acc_ctx.Change(Bip44Changes.CHAIN_EXT)
    bip44_addr_ctx = bip44_chg_ctx.AddressIndex(0)
    priv_key = bip44_addr_ctx.PrivateKey().ToExtended()
    eth_address = bip44_chg_ctx.PublicKey().ToAddress()
    return mnemonic, priv_key, eth_address

def check_mnemonic(mnemonic_words, target_addresses):
    """Generate and check mnemonic against target addresses."""
    mnemonic = " ".join(mnemonic_words)
    _, priv_key, eth_address = generate_eth_address(mnemonic)
    print(f"Checking: {eth_address}")
    if eth_address in target_addresses:
        print(f"\nMATCH FOUND!\nMnemonic: {mnemonic}\nPrivate Key: {priv_key}\nEthereum Address: {eth_address}\n")
        with open("found_mnemonics.txt", "a") as f:
            f.write(f"{mnemonic}\n{priv_key}\n{eth_address}\n\n")

def main():
    """Main function to read wordlist, generate mnemonics, and check against target addresses."""
    target_file = "ethrichlist.txt"  # Automatically using the file from your repo
    bip39_file = "bip39_wordlist.txt"
    
    # Load BIP39 wordlist
    with open(bip39_wordlist.txt, "r") as f:
        bip39_wordlist = [word.strip() for word in f.readlines()]
    
    target_addresses = load_target_addresses("ethrichlist.txt")
    if not target_addresses:
        print("Error: Target address list is empty or not loaded.")
        return
    
    word_count = 12  # Mnemonic length
    
    from itertools import product
    for words in itertools.product(BIP39_WORDLIST, repeat=word_count):
        check_mnemonic(words, target_addresses)
    
if __name__ == "__main__":
    main()
