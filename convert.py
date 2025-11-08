def bytes_to_int(b: bytes) -> int:
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("Input must be bytes or bytearray")
    return int.from_bytes(b, byteorder='big', signed=False)

def int_to_bytes(i: int) -> bytes:
    min_len = 512 // 8  # Minimum length in bytes for 512 bits
    if not isinstance(i, int):
        raise TypeError("i must be int")
    if i < 0:
        raise ValueError("i must be non-negative")
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder='big')

from io_utils import read_input, write_output

data = read_input("input.txt")
print(f"Input Data: {data}")

i = bytes_to_int(data)

print(f"Bytes to Int: {i}")
b = int_to_bytes(i)
print(f"Int to Bytes: {b}")
write_output("output.txt", b)

