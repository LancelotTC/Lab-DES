from feistel_implementation import feistel_encrypt, feistel_decrypt
from utils import derive_keys

if __name__ != "__main__":
    quit()


MASTER_KEY = 0xA5A5A5A5

# Example
keys = derive_keys(master_key=MASTER_KEY, n=16)
plaintext = "Lancelot"


cipher = feistel_encrypt(plaintext, keys)
plain2 = feistel_decrypt(cipher, keys)

print(plaintext)
print(hex(cipher))
print(plain2)
