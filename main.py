from typing import Dict, Tuple, List, Union
from rsa_core import generate_keypair, encrypt, decrypt
from convert import bytes_to_int, int_to_bytes
from io_utils import read_input, read_key, write_output, write_key

def forward(filename: str, bits: int):

    max_chunks_size = bits // 8 - 11
    print(f"Đang tạo bộ khóa RSA {bits}-bit...")

    # 2. Sinh khóa ngẫu nhiên (p, q, e, d)
    public_key, private_key = generate_keypair(bits // 2)
    e, n = public_key
    d, _ = private_key

    print(f"Khóa công khai (e, n): e = {e}, n = {n}")
    print(f"Khóa bí mật (d, n): d = {d}, n = {n}")

    # 3. Đọc dữ liệu đầu vào
    data_bytes = read_input(filename)  # dữ liệu dạng chuỗi
    print(f"\nThông điệp gốc: {data_bytes}")

    chunks = [
        data_bytes[i : i + max_chunks_size]
        for i in range(0, len(data_bytes), max_chunks_size)
    ]
    cipher_chunks = []
    for chunk in chunks:
        # 4. Chuyển sang int để mã hóa
        m_int = bytes_to_int(chunk)

        # 5. Mã hóa
        c_int = encrypt(m_int, e, n)
        print(f"\nCiphertext (int): {c_int}")
        cipher_chunks.append(c_int)
    
    return {
        "cipher_chunks": cipher_chunks,
        "public_key": (e, n),
        "private_key": (d, n),
    }

def backward(cipher_filename: str, key_filename: None | str = None, key: None | Tuple = None) -> bytes:
    cipher_bytes = read_input(cipher_filename)
    if key_filename is None and key is None:
        raise ValueError("Can not decrypt file without private key")
    if key_filename is not None:
        private_key = read_key(key_filename)
    else:
        private_key = key
    
    if private_key is None:
        raise ValueError("Private key could not be loaded")

    if not isinstance(private_key, (tuple, list)) or len(private_key) < 2:
        raise ValueError(f"Invalid private key format: {private_key}")

    d, n = private_key[0], private_key[1]
    k = (n.bit_length() + 7) // 8

    cipher_chunks = [int.from_bytes(cipher_bytes[i:i+k], "big") for i in range(0, len(cipher_bytes), k)]

    plaintext_chunks = []
    for chunk in cipher_chunks:
        decrypted_int = decrypt(chunk, d, n)
        decrypted_bytes = int_to_bytes(decrypted_int, n)

        plaintext_chunks.append(decrypted_bytes.lstrip(b'\x00'))
    
    plaintext_bytes = b''.join(plaintext_chunks)
    return plaintext_bytes
def main():
    # 1. Chọn độ dài bit của số nguyên tố
    bits = 1024
    
    encrypt_result = forward("input.txt", bits)
    e, n = encrypt_result["public_key"]
    cipher_text = b''.join(int_to_bytes(cipher_chunk, n) for cipher_chunk in encrypt_result["cipher_chunks"])

    write_output("cipher_text.txt", cipher_text)
    write_key("public_key.txt", encrypt_result["public_key"])
    write_key("private_key.txt", encrypt_result["private_key"])
    # 6. Giải mã
    
    plaintext_bytes = backward("cipher_text.txt", "private_key.txt")
    # 7. Ghi kết quả ra file
    
    write_output("output.txt", plaintext_bytes)

    print(f"\nGiải mã thành công:")
    data = read_input("output.txt")
    plaintext = data.decode('utf-8')
    print(f"Plaintext: {plaintext}")

if __name__ == "__main__":
    main()