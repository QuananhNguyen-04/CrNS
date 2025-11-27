import random
from math_utils import is_probable_prime, gcd, modinv, pow_mod, solve_crt


def generate_large_prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) # generate a random number which is bits long
        p |= (1 << bits - 1) # set the most significant bit to ensure the bits length
        p |= 1 # ensure the number is odd
        if is_probable_prime(p):
            return p


def generate_keypair(bits: int = 1024) -> tuple[tuple[int, int], tuple[int, int]]:
    """
    Return Public Key: (e, n)
    Return Private Key: (d, n, p, q)
    """
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    while p == q:
        p = generate_large_prime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1) # Euler's totient function
    # find e so that e and phi_n are coprime numbers
    while True:
        e = random.randint(2, phi_n - 1)
        if gcd(e, phi_n) == 1:
            break
    d = modinv(e, phi_n)
    return ( (e, n), (d, n, p, q) )


def encrypt(message_int: int, e: int, n: int) -> int:
    if message_int >= n:
        raise ValueError("Message integer must be less than n")
    return pow_mod(message_int, e, n)


def decrypt_crt(cipher_int: int, d: int, p: int, q: int) -> int:
    """
    Decrypts using Chinese Remainder Theorem (4x faster than standard)
    """
    dp = d % (p - 1)
    dq = d % (q - 1)

    m1 = pow_mod(cipher_int, dp, p)
    m2 = pow_mod(cipher_int, dq, q)

    return solve_crt(m1, m2, p, q)


def decrypt(cipher_int: int, d: int, n: int) -> int:
    # Standard slow decryption (keep as backup)
    return pow_mod(cipher_int, d, n)


if __name__ == '__main__':
    import time
    print("--- Testing RSA Core ---")
    
    # Test Key Gen
    bits = 1024
    print(f"Generating {bits}-bit keys...")
    pub, priv = generate_keypair(bits)
    e, n = pub
    d, _, p, q = priv
    print("[PASS] Key Generation")

    # Test Encrypt/Decrypt
    message = 123456789
    cipher = encrypt(message, e, n)
    plain = decrypt(cipher, d, n)
    assert plain == message
    print("[PASS] Standard Encrypt/Decrypt")

    # Test CRT Decrypt
    plain_crt = decrypt_crt(cipher, d, p, q)
    assert plain_crt == message
    print("[PASS] CRT Decrypt")

    # Speed Test
    print("\nRunning Speed Test (100 iterations)...")
    t0 = time.time()
    for _ in range(100): decrypt(cipher, d, n)
    t1 = time.time()
    for _ in range(100): decrypt_crt(cipher, d, p, q)
    t2 = time.time()
    
    print(f"Standard Time: {t1-t0:.4f}s")
    print(f"CRT Time:      {t2-t1:.4f}s")
    print(f"Speedup:       {(t1-t0)/(t2-t1):.2f}x")