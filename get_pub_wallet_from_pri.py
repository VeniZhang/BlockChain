import ecdsa
from Crypto.Hash import keccak

private_key = 'your private key base hex'
private_key_bytes = bytes.fromhex(private_key)
# Get ECDSA public key
key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1).verifying_key
key_bytes = key.to_string()
key_hex = key_bytes.hex()

print(key_hex)

public_key = key_hex
public_key_bytes = bytes.fromhex(public_key)
keccak_hash = keccak.new(digest_bits=256)
keccak_hash.update(public_key_bytes)
keccak_digest = keccak_hash.hexdigest()

# Take the last 20 bytes
wallet_len = 40
wallet = '0x' + keccak_digest[-wallet_len:]
print(wallet)

# refer: https://www.cxyzjd.com/article/cumi6497/108109330
