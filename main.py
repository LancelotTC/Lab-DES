from feistel_implementation import feistel_encrypt, feistel_decrypt
from utils import derive_keys

if __name__ != "__main__":
    quit()


# Example
keys = derive_keys(master_key=0xA5A5A5A5, n=16)
plaintext = 0xDEADBEEFCAFEBABE


cipher = feistel_encrypt(plaintext, keys)
plain2 = feistel_decrypt(cipher, keys)

print(hex(plaintext))
print(hex(cipher))
print(hex(plain2))
