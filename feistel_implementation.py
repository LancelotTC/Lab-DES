from collections.abc import Callable


def feistel_round(left: int, right: int, key: int, f: Callable[[int, int], int]):
    # One round: L', R' = R, L XOR F(R, key)
    return right, left ^ f(right, key)


def simple_f(x: int, k: int):
    # Tiny round function: just mixes x with key
    return (x ^ k) & 0xFFFFFFFF


def feistel_encrypt(
    block: int, keys: list[int], f: Callable[[int, int], int] = simple_f
):
    # block: 64-bit int → split into two 32-bit halves
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF

    for k in keys:
        L, R = feistel_round(L, R, k, f)

    # No swap at end (classic Feistel keeps final swap)
    return (L << 32) | R


def feistel_decrypt(
    block: int, keys: list[int], f: Callable[[int, int], int] = simple_f
):
    # same structure, but keys reversed
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF

    for k in reversed(keys):
        L, R = feistel_round(L, R, k, f)

    return (L << 32) | R


# Example
keys = [0x11111111, 0x22222222, 0x33333333, 0x44444444]
plaintext = 0xDEADBEEFCAFEBABE


cipher = feistel_encrypt(plaintext, keys)
plain2 = feistel_decrypt(cipher, keys)

print(hex(plaintext))
print(hex(cipher))
print(hex(plain2))
