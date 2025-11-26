from collections.abc import Callable
from constants import *


def runtime(func):
    return func


def permute(value: int, table: list[int], in_size: int) -> int:
    """Generic permutation: pick bits according to table."""
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (in_size - pos)) & 1)
    return out


def left_rotate_28(x: int, n: int) -> int:
    """Left rotate 28-bit value."""
    x &= (1 << 28) - 1
    return ((x << n) & ((1 << 28) - 1)) | (x >> (28 - n))


def sbox_substitution(x48: int) -> int:
    """Apply the 8 S-boxes to a 48-bit value."""
    out = 0
    for i in range(8):

        block = (x48 >> (42 - 6 * i)) & 0x3F
        row = ((block >> 5) << 1) | (block & 1)
        col = (block >> 1) & 0xF
        out = (out << 4) | S_BOXES[i][row][col]
    return out


def generate_subkeys(key64: int) -> list[int]:
    """Generate 16 48-bit subkeys from a 64-bit key (with 8 parity bits)."""

    key56 = permute(key64, PC1_TABLE, 64)
    C = (key56 >> 28) & ((1 << 28) - 1)
    D = key56 & ((1 << 28) - 1)

    subkeys: list[int] = []
    for shift in SHIFT_SCHEDULE:
        C = left_rotate_28(C, shift)
        D = left_rotate_28(D, shift)
        cd = (C << 28) | D

        K = permute(cd, PC2_TABLE, 56)
        subkeys.append(K)
    return subkeys


def des_f(R: int, subkey: int) -> int:
    """DES F(R, K): expansion -> XOR -> S-boxes -> P-box."""

    e = permute(R, E_TABLE, 32)

    x = e ^ subkey

    s = sbox_substitution(x)

    return permute(s, P_TABLE, 32)


def feistel_round(L: int, R: int, subkey: int, f: Callable[[int, int], int] = des_f):
    """One Feistel round: (L, R) -> (R, L XOR F(R, K))."""
    new_L = R & 0xFFFFFFFF
    new_R = (L ^ f(R & 0xFFFFFFFF, subkey)) & 0xFFFFFFFF
    return new_L, new_R


def des_encrypt_block(block64: int, key64: int) -> int:
    """Encrypt one 64-bit block with DES."""
    subkeys = generate_subkeys(key64)

    ip = permute(block64, IP_TABLE, 64)
    L = (ip >> 32) & 0xFFFFFFFF
    R = ip & 0xFFFFFFFF

    for K in subkeys:
        L, R = feistel_round(L, R, K)

    pre_output = (R << 32) | L
    return permute(pre_output, FP_TABLE, 64)


def des_decrypt_block(block64: int, key64: int) -> int:
    """Decrypt one 64-bit block with DES."""
    subkeys = generate_subkeys(key64)

    ip = permute(block64, IP_TABLE, 64)
    L = (ip >> 32) & 0xFFFFFFFF
    R = ip & 0xFFFFFFFF

    for K in reversed(subkeys):
        L, R = feistel_round(L, R, K)

    pre_output = (R << 32) | L
    return permute(pre_output, FP_TABLE, 64)


def des_encrypt(plaintext8: bytes, key8: bytes) -> bytes:
    """Encrypt 8-byte plaintext with 8-byte key (64-bit DES key)."""
    if len(plaintext8) != 8:
        raise ValueError("DES plaintext must be exactly 8 bytes")
    if len(key8) != 8:
        raise ValueError("DES key must be exactly 8 bytes")

    block = int.from_bytes(plaintext8, "big")
    key = int.from_bytes(key8, "big")
    cipher_block = des_encrypt_block(block, key)
    return cipher_block.to_bytes(8, "big")


def des_decrypt(ciphertext8: bytes, key8: bytes) -> bytes:
    """Decrypt 8-byte ciphertext with 8-byte key (64-bit DES key)."""
    if len(ciphertext8) != 8:
        raise ValueError("DES ciphertext must be exactly 8 bytes")
    if len(key8) != 8:
        raise ValueError("DES key must be exactly 8 bytes")

    block = int.from_bytes(ciphertext8, "big")
    key = int.from_bytes(key8, "big")
    plain_block = des_decrypt_block(block, key)
    return plain_block.to_bytes(8, "big")


def pad_pkcs7(data: bytes) -> bytes:
    pad_len = 8 - (data_len := len(data)) % 8
    return data + bytes([pad_len]) * pad_len


def unpad_pkcs7(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 8:
        raise ValueError("Invalid padding")
    return data[:-pad_len]


def des_encrypt_any(plaintext: bytes, key8: bytes) -> bytes:
    if len(key8) != 8:
        raise ValueError("DES key must be 8 bytes")

    plaintext = pad_pkcs7(plaintext)
    out = bytearray(len(plaintext))

    for i in range(0, len(plaintext), 8):
        block = plaintext[i : i + 8]
        out[i : i + 8] = des_encrypt(block, key8)

    return bytes(out)


def des_decrypt_any(ciphertext: bytes, key8: bytes) -> bytes:
    if len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext size must be multiple of 8 bytes")
    if len(key8) != 8:
        raise ValueError("DES key must be 8 bytes")

    out = bytearray(len(ciphertext))

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i : i + 8]
        out[i : i + 8] = des_decrypt(block, key8)

    return unpad_pkcs7(bytes(out))
