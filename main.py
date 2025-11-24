from feistel_implementation import feistel_encrypt, feistel_decrypt

if __name__ != "__main__":
    quit()

# Example
keys = [0x11111111, 0x22222222, 0x33333333, 0x44444444]
plaintext = 0xDEADBEEFCAFEBABE


cipher = feistel_encrypt(plaintext, keys)
plain2 = feistel_decrypt(cipher, keys)

print(hex(plaintext))
print(hex(cipher))
print(hex(plain2))
