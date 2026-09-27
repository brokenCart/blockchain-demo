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


def append_block(chain, data):
    chain.append(make_block(len(chain), data, chain[-1]["hash"]))


def is_valid(chain: list[dict[str, Any]]) -> bool:
    nonce_map = defaultdict(int)
    for i, block in enumerate(chain):
        if block["hash"] != block_hash(block):
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


if __name__ == "__main__":
    chain = [make_block(0, {"note": "genesis"}, "0" * 64)]
    alice_pkey, alice_pub_key = get_keys()
    bob_pkey, bob_pub_key = get_keys()
    carol_pkey, carol_pub_key = get_keys()

    for idx, data in enumerate(
        [
            {"from_private_key": alice_pkey, "to_public_key": bob_pub_key, "amount": 5},
            {"from_private_key": bob_pkey, "to_public_key": carol_pub_key, "amount": 2},
        ],
        start=1,
    ):
        chain.append(
            make_block(idx, make_transaction(**data, nonce=0), chain[-1]["hash"])
        )
    print(is_valid(chain))

    # Tampering of a block (handled by signatures)
    # chain[1]["data"]["amount"] = 500
    # print(is_valid(chain))

    # chain[1]["hash"] = block_hash(chain[1])
    # print(is_valid(chain))

    # chain[2]["prev_hash"] = chain[1]["hash"]
    # print(is_valid(chain))

    # chain[2]["hash"] = block_hash(chain[2])
    # print(is_valid(chain))

    # Forging a transaction as Bob
    # txn = {
    #     "from": alice_pub_key.to_string().hex(),
    #     "to": bob_pub_key.to_string().hex(),
    #     "amount": 50,
    # }
    # txn["signature"] = data_signature(txn, bob_pkey)
    # chain.append(make_block(3, txn, chain[-1]["hash"]))
    # print(is_valid(chain))

    # Appending genuine but duplicate transactions to the chain
    # append_block(chain, chain[1]["data"])
    # append_block(chain, chain[1]["data"])
    # append_block(chain, chain[1]["data"])

    # This prints True. To fix this we add nonce to the transaction
    # print(is_valid(chain))

    # After adding nonce
    # This prints False
    # append_block(chain, chain[1]["data"])
    # append_block(chain, chain[1]["data"])
    # append_block(chain, chain[1]["data"])
    # print(is_valid(chain))

    # Genuine transaction from Alice
    append_block(chain, make_transaction(alice_pkey, bob_pub_key, 10, 1))
    print(is_valid(chain))
