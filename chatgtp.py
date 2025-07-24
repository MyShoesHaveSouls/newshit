import os
import time
import random
from bip_utils import (
    Bip39MnemonicGenerator, Bip39SeedGenerator,
    Bip39WordsNum, Bip44, Bip44Coins
)

def load_target_addresses(file_path):
    """Load a list of Ethereum addresses to compare against."""
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} not found.")
        return set()
    with open(file_path, "r") as f:
        return set(line.strip().lower() for line in f)

def generate_eth_address(mnemonic):
    """Generate Ethereum address and private key from a mnemonic."""
    seed = Bip39SeedGenerator(mnemonic).Generate()
    bip44_ctx = Bip44.FromSeed(seed, Bip44Coins.ETHEREUM).Purpose().Coin().Account(0).Change(0).AddressIndex(0)
    address = bip44_ctx.PublicKey().ToAddress()
    priv_key = bip44_ctx.PrivateKey().Raw().ToHex()
    return address.lower(), priv_key

def main():
    target_addresses = load_target_addresses("bip39_wordlist.txt")
    if not target_addresses:
        print("⚠️ No target addresses loaded. Exiting.")
        return

    print("🔁 Starting mnemonic generation...")

    while True:
        mnemonic = Bip39MnemonicGenerator().FromWordsNumber(Bip39WordsNum.WORDS_NUM_12)
        eth_address, priv_key = generate_eth_address(mnemonic)

        if eth_address in target_addresses:
            print(f"\n✅ Match found!\nAddress: {eth_address}\nMnemonic: {mnemonic}\nPrivate Key: {priv_key}\n")
            with open("found_mnemonics.txt", "a") as f:
                f.write(f"{mnemonic}\n{priv_key}\n{eth_address}\n\n")
        else:
            print(f"Checked: {eth_address} (No match)")

        # Optional delay
        time.sleep(0.1)

if __name__ == "__main__":
    main()
