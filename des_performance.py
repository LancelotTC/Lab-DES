import os
import time
from des import *


def benchmark_des(key8: bytes):
    results = []

    for n in range(10, 27):  # 2^10 .. 2^26
        size = 2**n
        msg = os.urandom(size)

        t0 = time.perf_counter()
        des_encrypt_any(msg, key8)  # your DES wrapper (works on any size)
        t1 = time.perf_counter()

        results.append((size, t1 - t0))
        print(f"Encrypted {size} bytes in {t1 - t0:.4f} seconds")

    return results


# Example usage
key = b"ABCDEFGH"
results = benchmark_des(key)
