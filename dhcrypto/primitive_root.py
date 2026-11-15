"""Kiểm tra và tìm phần tử sinh (căn nguyên thuỷ) g modulo p.

g là căn nguyên thuỷ modulo p khi g^1, g^2, ..., g^(p-1) đi qua tất cả các số
1, 2, ..., p - 1. Không cần liệt kê hết: g là căn nguyên thuỷ khi và chỉ khi
g^((p-1)/r) mod p khác 1 với mọi ước nguyên tố r của p - 1.
"""
from .modmath import mod_pow
from .primes import is_probable_prime


def prime_factors(n: int):
    """Các ước nguyên tố của n bằng chia thử, chỉ dùng cho n nhỏ.

    Với p hàng trăm bít thì không phân tích được p - 1, vì vậy mới dùng số
    nguyên tố an toàn p = 2q + 1 để biết sẵn p - 1 = 2q.
    """
    factors = []
    d = 2
    while d * d <= n:
        if n % d == 0:
            factors.append(d)
            while n % d == 0:
                n //= d
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append(n)
    return factors


def check_primitive_root(g: int, p: int, factors=None):
    """Kiểm tra g có phải căn nguyên thuỷ modulo p.

    Trả về (kết luận, các bước), mỗi bước là (r, (p-1)/r, g^((p-1)/r) mod p).
    `factors` là các ước nguyên tố của p - 1 nếu đã biết, ví dụ [2, q].
    """
    if not 1 < g < p:
        return False, []
    if factors is None:
        factors = prime_factors(p - 1)
    steps = []
    for r in factors:
        e = (p - 1) // r
        steps.append((r, e, mod_pow(g, e, p)))
    return all(v != 1 for _, _, v in steps), steps


def is_primitive_root(g: int, p: int, factors=None) -> bool:
    return check_primitive_root(g, p, factors)[0]


def find_primitive_root(p: int, factors=None, start: int = 2) -> int:
    """Căn nguyên thuỷ nhỏ nhất không nhỏ hơn start."""
    if factors is None:
        factors = prime_factors(p - 1)
    for g in range(start, p):
        if is_primitive_root(g, p, factors):
            return g
    raise ValueError("không tìm được căn nguyên thuỷ")


def safe_prime_factors(p: int):
    """Với số nguyên tố an toàn p = 2q + 1, các ước nguyên tố của p - 1 là [2, q]."""
    q = (p - 1) // 2
    if not (is_probable_prime(p) and is_probable_prime(q)):
        raise ValueError("p không phải số nguyên tố an toàn")
    return [2, q]


def power_table(g: int, p: int):
    """Bảng g^k mod p với k = 1 .. p - 1, chỉ dùng cho p nhỏ."""
    table = []
    v = 1
    for k in range(1, p):
        v = v * g % p
        table.append((k, v))
    return table
