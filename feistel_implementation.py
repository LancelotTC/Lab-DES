from collections.abc import Callable


def feistel_round(left: int, right: int, key: int, f: Callable[[int, int], int]):
    # One encryption round: L', R' = R, L XOR F(R, key)
    return right, (left ^ f(right, key)) & 0xFFFFFFFF


def simple_f(x: int, k: int):
    # Tiny round function: just mixes x with key
    return (x + k) & 0xFFFFFFFF


def feistel_encrypt(plaintext: str, keys: list[int], f: Callable[[int, int], int] = simple_f):
    block = int(plaintext.encode().hex(), 16)

    half_length = (((block.bit_length() + 7) // 8) * 8) // 2

    L = (block >> half_length) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF
    for k in keys:
        L, R = feistel_round(L, R, k, f)

    return (L << half_length) | R


def feistel_decrypt(block: int, keys: list[int], f: Callable[[int, int], int] = simple_f):
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF

    for k in reversed(keys):
        # Inverse of (L, R) -> (R, L ^ F(R, k))
        L, R = (R ^ f(L, k)) & 0xFFFFFFFF, L

    hex_deciphered = (L << 32) | R

    return bytes.fromhex(hex(hex_deciphered).removeprefix("0x")).decode()
