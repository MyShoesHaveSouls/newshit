
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

def check_mnemonic(mnemonic_words):
    """Generate and check mnemonic against target addresses."""
    mnemonic = " ".join(mnemonic_words)
    _, priv_key, eth_address = generate_eth_address(mnemonic)
    
    if eth_address.lower() in TARGET_ADDRESSES:
        print(f"Match found! Mnemonic: {mnemonic} | Private Key: {priv_key} | Address: {eth_address}")
        with open("found_mnemonics.txt", "a") as f:
            f.write(f"{mnemonic}\n{priv_key}\n{eth_address}\n\n")

def parallel_search(batch_size=1000):
    """Parallelized mnemonic phrase search."""
    word_combinations = product(BIP39_WORDLIST, repeat=12)
    
    with concurrent.futures.ProcessPoolExecutor() as executor:
        while True:
            batch = [next(word_combinations) for _ in range(batch_size)]
            executor.map(check_mnemonic, batch)

if __name__ == "__main__":
    parallel_search()
