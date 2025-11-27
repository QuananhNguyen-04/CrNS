import time
from typing import Dict, Tuple, List
from rsa_core import generate_keypair, encrypt, decrypt, decrypt_crt
from convert import bytes_to_int, int_to_bytes
from io_utils import read_input, read_key, write_output, write_key, diff_bytes
from math_utils import pollards_rho


# ============================================================
#  Encryption Workflow (Forward Path)
# ============================================================
def rsa_encrypt_file(filepath: str, key_bits: int) -> Dict:
    """
    Executes the RSA forward pipeline:
      - Key generation
      - Block segmentation
      - Per-block encryption
      - Consolidated export structure
    """

    max_payload_size = key_bits // 8 - 11
    print(f"Provisioning RSA keypair ({key_bits}-bit)…")

    # Generate primes for RSA
    public_key, private_key = generate_keypair(key_bits // 2)
    e, n = public_key
    d, _, p, q = private_key

    print(f"Public key   (e, n): e = {e}, n = {n}")
    print(f"Private key  (d, n): d = {d}, n = {n}")

    # Load file
    data = read_input(filepath)
    print(f"\nOriginal payload: {data}")

    # Chunk payload
    payload_chunks = [
        data[i : i + max_payload_size]
        for i in range(0, len(data), max_payload_size)
    ]

    print("Chunk sizes:")
    encrypted_chunks: List[int] = []

    # Encrypt each chunk
    for chunk in payload_chunks:
        m_int = bytes_to_int(chunk)
        c_int = encrypt(m_int, e, n)
        encrypted_chunks.append(c_int)

    return {
        "cipher_chunks": encrypted_chunks,
        "public_key": (e, n),
        "private_key": (d, n, p, q),
    }


# ============================================================
#  Decryption Workflow (Backward Path)
# ============================================================
def rsa_decrypt_file(
    cipher_path: str,
    key_path: str | None = None,
    key: Tuple[int, int, int, int] | None = None
) -> bytes:
    """
    Executes the RSA backward pipeline:
      - Read ciphertext
      - Load key
      - Block-slice ciphertext
      - Per-block decryption
      - Reassemble plaintext
    """

    ciphertext_bytes = read_input(cipher_path)

    # Key provisioning
    if key_path is None and key is None:
        raise ValueError("Missing private key")
    private_key = read_key(key_path) if key_path else key

    use_crt = False
    if len(private_key) == 4:
        d, n, p, q = private_key
        use_crt = True
        print("Using Optimized CRT Decryption")
    elif len(private_key) == 2:
        d, n = private_key
        print("Using Standard Decryption")
    else:
        raise ValueError(f"Invalid private key format: {private_key}")

    block_size = (n.bit_length() + 7) // 8
    payload_size = block_size - 11

    # Convert ciphertext → int chunks
    cipher_chunks = [
        bytes_to_int(ciphertext_bytes[i : i + block_size])
        for i in range(0, len(ciphertext_bytes), block_size)
    ]

    print("Block size:", block_size)

    plaintext_chunks: List[bytes] = []

    for idx, block in enumerate(cipher_chunks):
        if use_crt:
            decrypted_int = decrypt_crt(block, d, p, q)
        else:
            decrypted_int = decrypt(block, d, n)
        raw_bytes = int_to_bytes(decrypted_int, n)

        # Non-final block = fixed payload slice
        if idx < len(cipher_chunks) - 1:
            plaintext = raw_bytes[-payload_size:]
        else:
            # Final block may be shorter → strip leading padding only
            plaintext = raw_bytes.lstrip(b"\x00")

        plaintext_chunks.append(plaintext)

    return b"".join(plaintext_chunks)


def demo_hacking(bit_num):
    print("\n=== DEMO: HACKING WEAK KEY ===")
    # Generate weak key
    pub, _ = generate_keypair(bit_num) # 32 bits is tiny
    _, n = pub
    print(f"Weak Modulus: {n}")
    
    start = time.time()
    factor = pollards_rho(n)
    end = time.time()
    
    if factor:
        print(f"CRACKED! Factors: {factor} * {n//factor}")
        print(f"Time: {end-start:.5f}s")
    else:
        print("Failed.")


# ============================================================
#  End-to-End Demo
# ============================================================
def main():
    # 1. Run the Standard Assignment Flow
    print("=== STANDARD ASSIGNMENT FLOW ===")
    key_bits = 1024
    input_file = "./input.txt"

    # Forward
    result = rsa_encrypt_file(input_file, key_bits)
    _, n = result["public_key"]

    # Consolidate ciphertext
    ciphertext = b"".join(
        int_to_bytes(c, n) for c in result["cipher_chunks"]
    )

    write_output("cipher_text.txt", ciphertext)
    write_key("public_key.txt", result["public_key"])
    write_key("private_key.txt", result["private_key"])

    # Backward
    plaintext = rsa_decrypt_file("cipher_text.txt", "private_key.txt")
    write_output("output.txt", plaintext)

    print("\nDecryption successful:")
    diff_bytes(read_input(input_file), plaintext)

    # 2. Run the Creative Hacking Demo
    demo_hacking(48)


if __name__ == "__main__":
    main()