import random


def gcd(a: int, b: int) -> int:
    if b == 0: return a
    return gcd(b, a % b)


def egcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    gcd, x_prime, y_prime = egcd(b, a % b)
    x = y_prime
    y = x_prime - (a // b) * y_prime
    return (gcd, x, y)


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
    # Tests for function modinv
    # Let's say we need to find the private key 'd' for RSA
    e = 7
    phi_n = 20 # from p=3, q=11 -> (p-1)*(q-1) = 2*10=20

    # We need to find d = modinv(e, phi_n)
    d = modinv(e, phi_n)
    
    print(f"e = {e}, phi_n = {phi_n}")
    print(f"The private key d is: {d}")
    print(f"Verification: (e * d) % phi_n = ({e} * {d}) % {phi_n} = {(e * d) % phi_n}")
    # The result of the verification should be 1.


    # Tests for function is_probable_prime
    # Test with a known prime
    p = 13
    print(f"Is {p} probably prime? {is_probable_prime(p)}")

    # Test with a known composite
    c = 15
    print(f"Is {c} probably prime? {is_probable_prime(c)}")

    # Test with a large known prime
    large_prime = 65537
    print(f"Is {large_prime} probably prime? {is_probable_prime(large_prime)}")

    # Test with a large composite (Carmichael number, fools simpler tests)
    large_composite = 561
    print(f"Is {large_composite} probably prime? {is_probable_prime(large_composite)}")