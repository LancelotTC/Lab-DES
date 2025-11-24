def derive_keys(master_key: int, n: int) -> list[int]:
    keys = []
    k = master_key & 0xFFFFFFFF

    for i in range(n):
        # Simple, deterministic expansion:
        # rotate left by i bits and xor with i
        rot = ((k << (i % 32)) | (k >> (32 - (i % 32)))) & 0xFFFFFFFF
        keys.append(rot ^ i)

    return keys
