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