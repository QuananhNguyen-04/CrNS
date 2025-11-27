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

def diff_bytes(a: bytes, b: bytes, *, context=32):
    """
    Deep-diff two byte sequences and report the first point of divergence.
    Produces structured diagnostics to facilitate root-cause isolation.
    """
    min_len = min(len(a), len(b))

    # Find first differing index
    for i in range(min_len):
        if a[i] != b[i]:
            start = max(0, i - context)
            end = min(min_len, i + context)

            print("\n=== BYTE DIVERGENCE DETECTED ===")
            print(f"Index: {i} {i / 1024} KB ")
            print(f"Original Byte : {a[i]:02X}")
            print(f"Recovered Byte: {b[i]:02X}")
            print("\nContext Window:")
            print(f"Original [{start}:{end}]: {a[start:end].hex()}")
            print(f"Recovered[{start}:{end}]: {b[start:end].hex()}")
            print("================================\n")
            return

    # No difference within shared length
    if len(a) != len(b):
        print("\n=== LENGTH MISMATCH ===")
        print(f"Original length : {len(a)}")
        print(f"Recovered length: {len(b)}")
        print("=======================\n")
        return

    print("No differences found. Byte sequences match exactly.")