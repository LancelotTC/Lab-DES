from collections.abc import Callable


def feistel_round(left: int, right: int, key: int, f: Callable[[int, int], int]):
    # One encryption round: L', R' = R, L XOR F(R, key)
    return right, (left ^ f(right, key)) & 0xFFFFFFFF


def simple_f(x: int, k: int):
    # Tiny round function: just mixes x with key
    return (x ^ k) & 0xFFFFFFFF


def feistel_encrypt(
    block: int, keys: list[int], f: Callable[[int, int], int] = simple_f
):
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF

    for k in keys:
        L, R = feistel_round(L, R, k, f)

    return (L << 32) | R


def feistel_decrypt(
    block: int, keys: list[int], f: Callable[[int, int], int] = simple_f
):
    L = (block >> 32) & 0xFFFFFFFF
    R = block & 0xFFFFFFFF

    for k in reversed(keys):
        # Inverse of (L, R) -> (R, L ^ F(R, k))
        L, R = (R ^ f(L, k)) & 0xFFFFFFFF, L

    return (L << 32) | R
