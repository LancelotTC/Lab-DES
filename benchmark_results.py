import matplotlib.pyplot as plt

dct = {
    1024: 0.0372,
    2048: 0.0701,
    4096: 0.1408,
    8192: 0.2761,
    16384: 0.5456,
    32768: 1.0991,
    65536: 2.2255,
    131072: 4.4202,
    262144: 8.8179,
    524288: 24.7326,
    1048576: 46.5061,
}


plt.plot(dct.keys(), dct.values(), marker="o")
plt.xscale("log", base=2)
plt.yscale("log", base=2)
plt.xlabel("Message Size (bytes)")
plt.ylabel("Time (seconds)")
plt.title("DES Encryption Time vs Message Size")
plt.grid(True, which="both", ls="--", lw=0.5)
plt.show()
