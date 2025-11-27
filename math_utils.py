import random


def gcd(a: int, b: int) -> int:
    """
    Iterative implementation of Euclidean Algorithm.
    Safe for large integers.
    """
    while b != 0:
        a, b = b, a % b
    return a


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Iterative implementation of Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that ax + by = gcd
    """
    x0, y0 = 1, 0 # a = 1*a + 0*b
    x1, y1 = 0, 1 # b = 0*a + 1*b
    while b != 0:
        q, a, b = a // b, b, a % b
        # New = Old - Quotient * Current
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a: int, m: int) -> int:
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


def pow_mod(base: int, exp: int, mod: int) -> int:
    res = 1
    base %= mod
    while exp > 0:
        if exp % 2 == 1: res = (res * base) % mod
        base = (base * base) % mod
        exp //= 2
    return res


def is_probable_prime(n: int, k: int = 20) -> bool:
    if n == 1: return False
    if n == 2 or n == 3: return True
    if n % 2 == 0: return False

    # Decompose n - 1 into 2^s * d
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        # a. Pick a random witness 'a'
        a = random.randrange(2, n - 1)
        # b. Calculate x = a^d mod n
        x = pow_mod(a, d, n)
        # c. Check primary condition
        if x == 1 or x == n - 1:
            continue
        # d. Squaring loop
        is_composite = True
        for k in range(1, s):
            x = pow_mod(x, 2, n) # a ^ (2^k * d)
            if x == n - 1:
                is_composite = False
                break
        # e. If the loop finished and we never found x = n-1, it's composite
        if is_composite:
            return False
        
    # If all k tests passed, it's probably prime
    return True


def solve_crt(rem_a: int, rem_b: int, m_a: int, m_b: int) -> int:
    """
    Solves the system of congruences using the Chinese Remainder Theorem:
    x = rem_a (mod m_a)
    x = rem_b (mod m_b)
    Assumes m_a and m_b are coprime.
    """
    M = m_a * m_b
    # Modular inverse of m_b modulo m_a
    y_a = modinv(m_b, m_a)
    # Modular inverse of m_a modulo m_b
    y_b = modinv(m_a, m_b)

    # x = (rem_a * m_b * y_a + rem_b * m_a * y_b) % M
    rem = (rem_a * m_b * y_a + rem_b * m_a * y_b) % M
    return rem


def pollards_rho(n: int) -> int:
    """
    Attempts to find a non-trivial factor of n using Pollard's Rho algorithm.
    This is a 'Las Vegas' algorithm: it may fail (return failure), 
    but if it returns a number, it is definitely a factor.
    Useful for checking if a generated RSA modulus is easily factorable (weak).
    """
    if n % 2 == 0:
        return 2
        
    # Initialize the Tortoise (x) and the Hare (y)
    x = 2
    y = 2
    d = 1
    
    # Define the function that generates the path
    # This makes the "Rho" shape.
    f = lambda v: (v * v + 1) % n

    # Start the race!
    while d == 1:
        # Tortoise takes 1 step
        x = f(x)          
        
        # Hare takes 2 steps
        y = f(f(y))       
        
        # We check if the DIFFERENCE between x and y shares a factor with n.
        # This allows us to find the factor 'p' long before x actually equals y.
        d = gcd(abs(x - y), n)

    if d == n:
        return None # Failed. The cycle matched n, not a factor.
    else:
        return d # Success! 'd' is a non-trivial factor.


if __name__ == '__main__':
    print("--- Testing Math Utils ---")
    
    # 1. Test GCD
    assert gcd(12, 15) == 3
    assert gcd(3, 7) == 1
    print("[PASS] GCD")

    # 2. Test Modular Inverse
    # 3 * x = 1 (mod 11) -> x should be 4 because 3*4 = 12 = 1 (mod 11)
    assert modinv(3, 11) == 4
    print("[PASS] Modular Inverse")

    # 3. Test Modular Exponentiation
    # 2^10 mod 1000 = 1024 mod 1000 = 24
    assert pow_mod(2, 10, 1000) == 24
    print("[PASS] Modular Exponentiation")

    # 4. Test Primality (Miller-Rabin)
    assert is_probable_prime(17) == True
    assert is_probable_prime(65537) == True
    assert is_probable_prime(15) == False
    assert is_probable_prime(561) == False # Carmichael number
    print("[PASS] Primality Test")

    # 5. Test Chinese Remainder Theorem (CRT)
    # Find x where x = 2 mod 3 AND x = 3 mod 5
    # Answer should be 8 (8%3=2, 8%5=3) or 23, etc.
    result = solve_crt(2, 3, 3, 5)
    assert result == 8
    print("[PASS] CRT")

    # 6. Test Pollard's Rho (Factoring)
    n = 8051 # 83 * 97
    factor = pollards_rho(n)
    assert factor == 83 or factor == 97
    print("[PASS] Pollard's Rho")