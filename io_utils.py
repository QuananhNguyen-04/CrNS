def read_input(filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        data = f.read()
    # parse dữ liệu nếu cần
    return data

def write_output(filepath: str, result: bytes) -> None:
    with open(filepath, "wb") as f:
        f.write(result)