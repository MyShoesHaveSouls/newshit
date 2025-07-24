import threading
import time
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip44, Bip44Coins, Bip44Changes
from eth_utils import to_checksum_address

# Load rich list addresses into a set for fast lookup
with open("ethrichlist.txt", "r") as f:
    richlist = set(line.strip().lower() for line in f if line.strip())

mnemo = Mnemonic("english")
lock = threading.Lock()

total_keys = 0
hits_found = 0
running = True

def mnemonic_to_eth_address(mnemonic_phrase):
    seed_bytes = Bip39SeedGenerator(mnemonic_phrase).Generate()
    bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.ETHEREUM)
    # Correct usage of Change with Bip44Changes enum
    addr = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0).PublicKey().ToAddress()
    return to_checksum_address(addr)

def worker():
    global total_keys, hits_found
    while running:
        phrase = mnemo.generate(strength=128)  # 12 words
        try:
            address = mnemonic_to_eth_address(phrase)
        except Exception as e:
            print(f"Error deriving address: {e}")
            continue

        with lock:
            total_keys += 1
            if address.lower() in richlist:
                hits_found += 1
                print(f"\n*** HIT! Address: {address} | Phrase: {phrase}\n")
                with open("matches.txt", "a") as f:
                    f.write(f"{address} | {phrase}\n")

def print_stats():
    global total_keys, hits_found
    last_total = 0
    while running:
        time.sleep(1)
        with lock:
            keys_this_sec = total_keys - last_total
            last_total = total_keys
            print(f"Keys/sec: {keys_this_sec:.2f} | Total Keys: {total_keys} | Hits: {hits_found}", end="\r")

if __name__ == "__main__":
    num_threads = 8  # Adjust to your CPU cores or preference
    print(f"Starting with {num_threads} threads...")

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    try:
        print_stats()
    except KeyboardInterrupt:
        print("\nStopping...")
        running = False
        for t in threads:
            t.join()
