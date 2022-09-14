import hashlib

from Crypto.Cipher import AES
from Crypto.Hash import keccak
from Crypto.Util import Counter

keystore = {"address": "***",
   "crypto": {
       "cipher": "aes-128-ctr",
       "ciphertext": "***",
       "cipherparams": {
           "iv": "***"
       },
       "kdf": "scrypt",
       "kdfparams": {
           "dklen": 32,
           "n": 262144,
           "p": 1,
           "r": 8,
           "salt": "***"
       },
       "mac": "***"
   },
   "id": "4bac0494-e5e0-43b7-8c9b-124c26d16726",
   "version": 3
}
passwd = "your passwd"
dec_key = hashlib.scrypt(bytes(passwd, 'utf-8'), salt=bytes.fromhex(keystore['crypto']['kdfparams']['salt']),
                         n=keystore['crypto']['kdfparams']['n'], r=keystore['crypto']['kdfparams']['r'],
                         p=keystore['crypto']['kdfparams']['p'], maxmem=2000000000,
                         dklen=keystore['crypto']['kdfparams']['dklen'])

print(dec_key)

validate = dec_key[16:] + bytes.fromhex(keystore['crypto']['ciphertext'])

keccak_hash = keccak.new(digest_bits=256)
keccak_hash.update(validate)

print(keccak_hash.hexdigest())

iv_int = int(keystore['crypto']['cipherparams']['iv'], 16)

ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
dec_suite = AES.new(dec_key[0:16], AES.MODE_CTR, counter=ctr)

plain_key = dec_suite.decrypt(bytes.fromhex(keystore['crypto']['ciphertext']))

print(plain_key)

secret = plain_key.hex()
print(secret)

# refer https://ethereum.stackexchange.com/questions/3720/how-do-i-get-the-raw-private-key-from-my-mist-keystore-file?noredirect=1&lq=1
# requirements: pycryptodome
