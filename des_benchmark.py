import time
import secrets
import matplotlib.pyplot as plt

from des import des_encrypt_any


def measure_encryption(key, sizes):
    times = []
    ciphertext_sizes = []

    for size in sizes:
        msg = secrets.token_bytes(size)

        start = time.perf_counter()
        ct = des_encrypt_any(msg, key)
        end = time.perf_counter()

        t = end - start
        times.append(t)
        ciphertext_sizes.append(len(ct))

        print(f"{size} B → time={t:.5f}s, ciphertext={len(ct)} B")

    return times, ciphertext_sizes


def plot_results(sizes, times, ciphertext_sizes):
    plt.figure(figsize=(10, 5))
    plt.plot(sizes, times, marker="o")
    plt.xscale("log", base=2)
    plt.yscale("log", base=2)
    plt.title("DES Encryption Time vs Message Size")
    plt.xlabel("Message size (bytes)")
    plt.ylabel("Time (seconds)")
    plt.grid(True)

    plt.figure(figsize=(10, 5))
    plt.plot(sizes, ciphertext_sizes, marker="o", color="orange")
    plt.xscale("log", base=2)
    plt.yscale("log", base=2)
    plt.title("DES Ciphertext Size vs Message Size")
    plt.xlabel("Message size (bytes)")
    plt.ylabel("Ciphertext size (bytes)")
    plt.grid(True)

    plt.show()


def main():
    key = secrets.token_bytes(8)  # random 64-bit DES key
    sizes = [2**i for i in range(10, 22)]  # 2^10 .. 2^22

    print("Running DES benchmark...\n")
    times, ciphertext_sizes = measure_encryption(key, sizes)

    # Plots
    plot_results(sizes, times, ciphertext_sizes)


if __name__ == "__main__":
    main()
