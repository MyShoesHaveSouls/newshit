import time
import threading
from mnemonic import Mnemonic
from eth_utils import to_checksum_address
from bip32utils import BIP32Key
import hashlib

# Load rich list addresses (assumed checksummed)
with open("ethrichlist.txt", "r") as f:
    richlist = set(line.strip() for line in f if line.strip())

mnemo = Mnemonic("english")

# Stats
total_keys = 0
hits_found = 0
lock = threading.Lock()

def mnemonic_to_eth_address(mnemonic_phrase):
    # Convert mnemonic to seed
    seed = mnemo.to_seed(mnemonic_phrase)
    
    # Derive private key (using BIP32 with Ethereum path m/44'/60'/0'/0/0)
    master_key = BIP32Key.fromEntropy(seed)
    child_key = master_key.ChildKey(44 + 0x80000000) \
                          .ChildKey(60 + 0x80000000) \
                          .ChildKey(0 + 0x80000000) \
                          .ChildKey(0) \
                          .ChildKey(0)
    private_key_bytes = child_key.PrivateKey()
    
    # Get public key (uncompressed)
    public_key = child_key.PublicKey()
    
    # Ethereum address = last 20 bytes of keccak256(public_key[1:])
    keccak_hash = hashlib.new('keccak_256')
    keccak_hash.update(public_key[1:])
    address_bytes = keccak_hash.digest()[-20:]
    
    # Convert to hex and apply checksum
    address = to_checksum_address('0x' + address_bytes.hex())
    return address

def worker():
    global total_keys, hits_found
    while True:
        # Generate 12 word mnemonic
        phrase = mnemo.generate(strength=128)  # 12 words
        
        try:
            address = mnemonic_to_eth_address(phrase)
        except Exception as e:
            continue  # If error in derivation, skip
        
        with lock:
            total_keys += 1
            if address in richlist:
                hits_found += 1
                print(f"*** HIT! Address: {address} Phrase: {phrase}")
                with open("matches.txt", "a") as f:
                    f.write(f"{address} | {phrase}\n")

def stats_printer():
    global total_keys, hits_found
    prev = 0
    while True:
        time.sleep(5)
        with lock:
            current = total_keys
            keys_per_sec = (current - prev) / 5
            prev = current
            print(f"Keys/sec: {keys_per_sec:.2f} | Total Keys: {total_keys} | Hits: {hits_found}")

if __name__ == "__main__":
    import multiprocessing
    
    num_threads = multiprocessing.cpu_count()
    print(f"Starting with {num_threads} threads...")
    
    # Start stats printer thread
    threading.Thread(target=stats_printer, daemon=True).start()
    
    # Start worker threads
    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    
    # Keep main alive
    for t in threads:
        t.join()
