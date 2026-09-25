"""
Tamper-evident but not tamper-proof blockchain.
"""

import hashlib
import json
import time
from typing import Any


def sha256(text: str):
    return hashlib.sha256(text.encode()).hexdigest()


def block_hash(block: dict[str, Any]) -> str:
    contents = {k: v for k, v in block.items() if k != "hash"}
    return sha256(json.dumps(contents, sort_keys=True))


def make_block(index, data, prev_hash) -> dict[str, Any]:
    block = {
        "index": index,
        "data": data,
        "prev_hash": prev_hash,
        "timestamp": time.time(),
    }
    block["hash"] = block_hash(block)
    return block


def is_valid(chain: list[dict[str, Any]]) -> bool:
    for i, block in enumerate(chain):
        if block["hash"] != block_hash(block):
            return False
        if i > 0 and (
            chain[i - 1]["hash"] != block["prev_hash"]
            or chain[i - 1]["index"] + 1 != block["index"]
        ):
            return False
    return True


if __name__ == "__main__":
    chain = [make_block(0, "genesis", "0" * 64)]
    for idx, txn in enumerate(["Alice pays Bob 5", "Bob pays Carol 2"], start=1):
        chain.append(make_block(idx, txn, chain[-1]["hash"]))
    print(is_valid(chain))

    # Tampering of data in the chain
    chain[1]["data"] = "Alice pays Bob 500"
    print(is_valid(chain))

    chain[1]["hash"] = block_hash(chain[1])
    print(is_valid(chain))

    chain[2]["prev_hash"] = chain[1]["hash"]
    print(is_valid(chain))

    chain[2]["hash"] = block_hash(chain[2])
    print(is_valid(chain))
