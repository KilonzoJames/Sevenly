from Crypto.Util.number import bytes_to_long, getStrongPrime

flag = bytes_to_long(b"REDACTED")
e = 0x10001

p = getStrongPrime(4096)
q = getStrongPrime(4096)
n = p * q
R = Zmod(n)

class SecretFunction:
    def __init__(self, a, b, c, d):
        self.a = R(a)
        self.b = R(b)
        self.c = R(c)
        self.d = R(d)

    def __add__(self, other):
        return SecretFunction(
            self.a + other.a,
            self.b + other.b,
            self.c + other.c,
            self.d + other.d
        )

    def __mul__(self, other):
        a1, b1, c1, d1 = self.a, self.b, self.c, self.d
        a2, b2, c2, d2 = other.a, other.b, other.c, other.d

        new_a = a1*a2 - b1*b2 - c1*c2 - d1*d2
        new_b = a1*b2 + b1*a2 + c1*d2 - d1*c2
        new_c = a1*c2 - b1*d2 + c1*a2 + d1*b2
        new_d = a1*d2 + b1*c2 - c1*b2 + d1*a2

        return SecretFunction(new_a, new_b, new_c, new_d)

    def __pow__(self, exp):
        result = SecretFunction(1, 0, 0, 0)
        base = self
        while exp > 0:
            if exp % 2 == 1:
                result = result * base
            base = base * base
            exp //= 2
        return result

    def __repr__(self):
        return f"({self.a} + {self.b}·u + {self.c}·v + {self.d}·w)"


def MoreSecretFunction(mval, pval, qval):
    a = 1 * mval
    b = 3 * mval + 1 * pval + 337 * qval
    c = 3 * mval + 13 * pval + 37 * qval
    d = 7 * mval + 133 * pval + 7 * qval
    return SecretFunction(a, b, c, d)

enc = MoreSecretFunction(flag, p, q) ** e

print(f"{n = }")
print(f"{e = }")
print(f"{enc = }")