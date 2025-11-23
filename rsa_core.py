def generate_large_prime(bits: int) -> int:
    while True:
        p = random.getrandbits(bits) # generate a random number which is bits long
        p |= (1 << bits - 1) # set the most significant bit to ensure the bits length
        p |= 1 # ensure the number is odd
        if is_probable_prime(p):
            return p

def generate_keypair(bits: int = 1024) -> tuple[tuple[int, int], tuple[int, int]]:
    """Return ((e, n), (d, n))"""
    p = generate_large_prime(bits)
    q = generate_large_prime(bits)
    while p == q:
        p = generate_large_prime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1) # Euler's totient function
    e = 65537
    while gcd(e, phi_n) != 1:
        e = random.randint(2, phi_n - 1)
    d = modinv(e, phi_n)
    return ( (e, n), (d, n) )

def encrypt(message_int: int, e: int, n: int) -> int:
    if message_int >= n:
        raise ValueError("Message integer must be less than n")
    return pow_mod(message_int, e, n)

def decrypt(cipher_int: int, d: int, n: int) -> int:
    return pow_mod(cipher_int, d, n)
