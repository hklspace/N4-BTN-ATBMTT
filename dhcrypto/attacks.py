"""Giải bài toán logarit rời rạc: biết p, g và y = g^x mod p, tìm x.

  brute_force_dlog   thử lần lượt x = 1, 2, 3, ...   O(n) phép nhân
  bsgs_dlog          Baby-step Giant-step              O(√n) thời gian và bộ nhớ
(n là cấp của g.)

Chỉ dùng để minh hoạ: với p nhỏ thì giải ngay, nhưng thời gian tăng theo hàm mũ
của số bít nên với p 2048 bít là không làm được.
"""
import math
import secrets

from .modmath import mod_inverse, mod_pow
from .primes import gen_safe_prime
from .primitive_root import find_primitive_root


def brute_force_dlog(g: int, y: int, p: int, max_steps: int = None):
    """Vét cạn. Trả về (x, số bước), hoặc (None, số bước) nếu vượt max_steps."""
    limit = p - 1 if max_steps is None else min(p - 1, max_steps)
    v = 1
    for x in range(1, limit + 1):
        v = v * g % p
        if v == y:
            return x, x
    return None, limit


def bsgs_dlog(g: int, y: int, p: int, order: int = None):
    """Baby-step Giant-step.

    Chọn m = ceil(√n), viết x = i*m + j với 0 <= i, j < m.
    Bước nhỏ: lưu bảng g^j -> j. Bước lớn: tính y * (g^(-m))^i, gặp giá trị có
    trong bảng thì x = i*m + j. Trả về (x, số phép toán) hoặc (None, số phép toán).
    """
    n = order or p - 1
    m = math.isqrt(n - 1) + 1
    table = {}
    v = 1
    for j in range(m):
        table.setdefault(v, j)
        v = v * g % p
    factor = mod_inverse(mod_pow(g, m, p), p)      # g^(-m)
    gamma = y % p
    for i in range(m):
        j = table.get(gamma)
        if j is not None:
            return i * m + j, m + i + 1
        gamma = gamma * factor % p
    return None, 2 * m


def make_dlp_instance(bits: int, secret_x: int = None):
    """Bài toán ngẫu nhiên với p là số nguyên tố an toàn `bits` bít.

    Trả về (p, g, x, y) với g là căn nguyên thuỷ và y = g^x mod p.
    """
    p = gen_safe_prime(bits)
    g = find_primitive_root(p, [2, (p - 1) // 2])
    x = secret_x if secret_x is not None else 2 + secrets.randbelow(p - 4)
    return p, g, x, mod_pow(g, x, p)
