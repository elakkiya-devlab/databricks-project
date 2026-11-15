import argparse
import getpass
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet


def main():
    parser = argparse.ArgumentParser(description="Encrypt provider JSON without echoing sensitive input")
    parser.add_argument("--output", default="configs/provider.enc")
    args = parser.parse_args()
    key = os.getenv("SENTINELX_CONFIG_KEY") or getpass.getpass("Fernet key (hidden): ")
    config = json.loads(getpass.getpass("Provider configuration JSON (hidden): "))
    path = Path(args.output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(Fernet(key.encode()).encrypt(json.dumps(config).encode()))
    print(f"Encrypted configuration written to {path}; keep the key in your OS/cloud secret store")


if __name__ == "__main__":
    main()