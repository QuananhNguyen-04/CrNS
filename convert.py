def bytes_to_int(b: bytes) -> int:
    if not isinstance(b, (bytes, bytearray)):
        raise TypeError("Input must be bytes or bytearray")
    return int.from_bytes(b, byteorder='big', signed=False)

def int_to_bytes(i: int, n) -> bytes:
    if not isinstance(i, int):
        raise TypeError("i must be int")
    if i < 0:
        raise ValueError("i must be non-negative")
    length = (n.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder='big')