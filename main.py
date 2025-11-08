from rsa_core import generate_keypair, encrypt, decrypt
from convert import bytes_to_int, int_to_bytes
from io_utils import read_input, write_output


def main():
    # 1. Chọn độ dài bit của số nguyên tố
    bits = 512
    print(f"Đang tạo bộ khóa RSA {bits}-bit...")

    # 2. Sinh khóa ngẫu nhiên (p, q, e, d)
    public_key, private_key = generate_keypair(bits)
    e, n = public_key
    d, _ = private_key

    print(f"Khóa công khai (e, n): e = {e}, n = {n}")
    print(f"Khóa bí mật (d, n): d = {d}, n = {n}")

    # 3. Đọc dữ liệu đầu vào
    data = read_input("input.txt")  # dữ liệu dạng chuỗi
    print(f"\nThông điệp gốc: {data}")

    # 4. Chuyển sang int để mã hóa
    m_int = bytes_to_int(data)

    # 5. Mã hóa
    c_int = encrypt(m_int, e, n)
    print(f"\nCiphertext (int): {c_int}")

    # 6. Giải mã
    decrypted_int = decrypt(c_int, d, n)
    decrypted_bytes = int_to_bytes(decrypted_int)

    # 7. Ghi kết quả ra file
    write_output("output.txt", decrypted_bytes)

    print(f"\nGiải mã thành công:")
    data=read_input("output.txt")
    plaintext = data.decode('utf-8')
    print(f"Plaintext: {plaintext}")

if __name__ == "__main__":
    main()
