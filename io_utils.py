def read_input(filepath: str) -> list:
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    # parse dữ liệu nếu cần
    return [line.strip() for line in lines]

def write_output(filepath: str, result):
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(str(result))
