import os
import time
from typing import Dict, Tuple, List
from rsa_core import generate_keypair, encrypt, decrypt, decrypt_crt
from convert import bytes_to_int, int_to_bytes
from io_utils import read_input, read_key, write_output, write_key, diff_bytes
from math_utils import pollards_rho


def get_non_zero_random_bytes(length):
    """Generates random bytes that do not contain 0x00"""
    random_bytes = b""
    while len(random_bytes) < length:
        batch = os.urandom(length + 5)
        # Filter 0x00 bytes
        batch = bytes([b for b in batch if b != 0])
        random_bytes += batch
    return random_bytes[:length]


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

    k = key_bits // 8
    # PKCS#1 v1.5 standard overhead size: At least 11 bytes (3 marker + 8 padding)
    max_payload_size = k - 11
    print(f"Provisioning RSA keypair ({key_bits}-bit)…")
    print(f"Applying PKCS#1 v1.5 Padding. Max Payload per chunk: {max_payload_size} bytes")

    # Generate primes for RSA
    public_key, private_key = generate_keypair(key_bits // 2)
    e, n = public_key
    d, _, p, q = private_key

    # Load file
    data = read_input(filepath)
    print(f"\nOriginal payload: {data}")

    # Chunk payload
    payload_chunks = [
        data[i : i + max_payload_size]
        for i in range(0, len(data), max_payload_size)
    ]

    encrypted_chunks: List[int] = []

    # Encrypt each chunk
    for chunk in payload_chunks:
        # Structure: 00 02 [PS] 00 [Data]
        # Len(PS) = k - 3 - len(Data)
        ps_len = k - 3 - len(chunk)
        ps = get_non_zero_random_bytes(ps_len)
        emsa_block = b'\x02' + ps + b'\x00' + chunk

        # Encrypt
        m_int = bytes_to_int(emsa_block)
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

    for block_int in cipher_chunks:
        if use_crt:
            decrypted_int = decrypt_crt(block_int, d, p, q)
        else:
            decrypted_int = decrypt(block_int, d, n)

        em_bytes = int_to_bytes(decrypted_int, n)

        try:
            if em_bytes[0] == 0x00 and em_bytes[1] == 0x02:
                start_index = 2
            elif em_bytes[0] == 0x02:
                start_index = 1
            else:
                raise ValueError("Decryption Error: Invalid PKCS#1 marker")
            
            separator_index = -1
            for i in range(start_index, len(em_bytes)):
                if em_bytes[i] == 0x00:
                    separator_index = i
                    break
            
            if separator_index == -1:
                raise ValueError("Decryption Error: No separator found")
            
            real_data = em_bytes[separator_index + 1:]
            plaintext_chunks.append(real_data)

        except Exception as e:
            print(f"Warning: Block decryption failed - {e}")
        
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
    demo_hacking(50)


if __name__ == "__main__":
    main()