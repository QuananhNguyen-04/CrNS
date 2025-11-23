def read_input(filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        data = f.read()
    # parse dữ liệu nếu cần
    return data

def read_key(filepath: str) -> list[int]:
    data = []
    with open(filepath, "r") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue  # skip empty lines
            try:
                data.append(int(line))
            except ValueError:
                raise ValueError(f"Invalid integer on line {lineno}: {line!r}")
    return data

def write_output(filepath: str, result: bytes) -> None:
    with open(filepath, "wb") as f:
        f.write(result)

def write_key(filepath: str, key) -> None:
    if not isinstance(key, tuple) or len(key) < 2:
        raise ValueError(f"Key must contains at least 2 members {type(key)}")
    with open(filepath, "w") as f:  # overwrite file
        for k in key:
            f.write(f"{k}\n")  # convert int to str and add newline