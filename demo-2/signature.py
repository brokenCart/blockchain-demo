import hashlib

from ecdsa import BadSignatureError, SECP256k1, SigningKey

private_key = SigningKey.generate(curve=SECP256k1, hashfunc=hashlib.sha256)
public_key = private_key.get_verifying_key()

message = b"Alice pays Bob 5"
signature = private_key.sign(message)

print(public_key.verify(signature, message))

try:
    public_key.verify(signature, b"Alice pays Bob 500")
except BadSignatureError:
    print("Rejected: signature doesn't match this message")
