import hashlib
import json
import time
from collections import defaultdict
from typing import Any

from ecdsa import (
    SECP256k1,
    SigningKey,
    VerifyingKey,
)

DIFFICULTY = 4


def sha256(text: str):
    return hashlib.sha256(text.encode()).hexdigest()


def block_hash(block: dict[str, Any]) -> str:
    contents = {k: v for k, v in block.items() if k != "hash"}
    return sha256(json.dumps(contents, sort_keys=True))


def signing_payload(data: dict[str, Any]):
    contents = {k: v for k, v in data.items() if k != "signature"}
    return json.dumps(contents, sort_keys=True).encode()


def data_signature(data: dict[str, Any], private_key: SigningKey):
    return private_key.sign(signing_payload(data)).hex()


def make_transaction(
    from_private_key: SigningKey, to_public_key: VerifyingKey, amount, nonce
):
    data = {
        "from": from_private_key.get_verifying_key().to_string().hex(),
        "to": to_public_key.to_string().hex(),
        "amount": amount,
        "nonce": nonce,
    }
    data["signature"] = data_signature(data, from_private_key)
    return data


def verify_transaction(data: dict[str, Any]):
    try:
        VerifyingKey.from_string(
            bytes.fromhex(data["from"]),
            curve=SECP256k1,
            hashfunc=hashlib.sha256,
        ).verify(
            bytes.fromhex(data["signature"]),
            signing_payload(data),
        )
    except Exception:
        return False
    return True


def get_keys():
    pkey = SigningKey.generate(curve=SECP256k1, hashfunc=hashlib.sha256)
    return pkey, pkey.get_verifying_key()


def make_block(
    index,
    data: dict[str, Any],
    prev_hash,
) -> dict[str, Any]:
    block = {
        "index": index,
        "data": data,
        "prev_hash": prev_hash,
        "timestamp": time.time(),
    }
    block["hash"] = block_hash(block)
    return block


def mine_block(index, data: dict[str, Any], prev_hash) -> dict[str, Any]:
    block = {
        "index": index,
        "data": data,
        "prev_hash": prev_hash,
        "timestamp": time.time(),
        "nonce": 0,
    }
    while not (hash := block_hash(block)).startswith("0" * DIFFICULTY):
        block["nonce"] += 1
    block["hash"] = hash
    return block


def append_block(chain, data):
    chain.append(mine_block(len(chain), data, chain[-1]["hash"]))


def is_valid(chain: list[dict[str, Any]]) -> bool:
    nonce_map = defaultdict(int)
    for i, block in enumerate(chain):
        if block["hash"] != block_hash(block):
            return False
        if not block["hash"].startswith("0" * DIFFICULTY):
            return False
        if i > 0 and (
            chain[i - 1]["hash"] != block["prev_hash"]
            or chain[i - 1]["index"] + 1 != block["index"]
            or not verify_transaction(block["data"])
            or nonce_map[block["data"]["from"]] != block["data"].get("nonce")
        ):
            return False

        if i > 0:
            nonce_map[block["data"]["from"]] += 1
    return True


def choose_chains(chains):
    return max(filter(is_valid, chains), key=len, default=None)


if __name__ == "__main__":
    chain1 = [mine_block(0, {"note": "genesis"}, "0" * 64)]
    chain2 = [chain1[0]]
    alice_pkey, alice_pub_key = get_keys()
    bob_pkey, bob_pub_key = get_keys()
    carol_pkey, carol_pub_key = get_keys()

    for data in [
        {"from_private_key": alice_pkey, "to_public_key": bob_pub_key, "amount": 5},
        {"from_private_key": bob_pkey, "to_public_key": carol_pub_key, "amount": 2},
    ]:
        append_block(chain1, make_transaction(**data, nonce=0))

    for data in [
        {
            "from_private_key": alice_pkey,
            "to_public_key": carol_pub_key,
            "amount": 5,
            "nonce": 0,
        },
        {
            "from_private_key": alice_pkey,
            "to_public_key": carol_pub_key,
            "amount": 1,
            "nonce": 1,
        },
        {
            "from_private_key": alice_pkey,
            "to_public_key": carol_pub_key,
            "amount": 1,
            "nonce": 2,
        },
    ]:
        append_block(chain2, make_transaction(**data))

    winner = choose_chains([chain1, chain2])
    print(winner is chain2)

    bob = bob_pub_key.to_string().hex()
    print(any(b["data"]["to"] == bob for b in winner[1:]))
