"""Số học modulo: lũy thừa, Euclid mở rộng, nghịch đảo, ký hiệu Jacobi.

Lõi của chương trình không dùng pow(a, b, m) có sẵn của Python. Hàm pow chỉ
xuất hiện trong bộ kiểm thử để so kết quả.
"""

# Số mũ ngắn hơn ngưỡng này thì bình phương và nhân thường đã đủ nhanh.
WINDOW_THRESHOLD = 64


def _check_args(exp, mod):
    if mod <= 0:
        raise ValueError("modulo phải là số dương")
    if exp < 0:
        raise ValueError("số mũ phải không âm")


def mod_pow(base: int, exp: int, mod: int) -> int:
    """base^exp mod mod, tự chọn cách tính theo độ dài số mũ."""
    if exp.bit_length() <= WINDOW_THRESHOLD:
        return mod_pow_basic(base, exp, mod)
    return mod_pow_window(base, exp, mod)


def mod_pow_basic(base: int, exp: int, mod: int) -> int:
    """Bình phương và nhân, đọc số mũ từ bít thấp lên bít cao.

    Với exp = sum(b_i * 2^i), base^exp là tích các base^(2^i) có b_i = 1.
    Số mũ k bít cần k lần bình phương và tối đa k lần nhân.
    """
    _check_args(exp, mod)
    if mod == 1:
        return 0
    result = 1
    base %= mod
    while exp:
        if exp & 1:
            result = result * base % mod
        base = base * base % mod
        exp >>= 1
    return result


def mod_pow_window(base: int, exp: int, mod: int, w: int = 5) -> int:
    """Lũy thừa modulo kiểu cửa sổ trượt, đọc số mũ từ bít cao xuống.

    Tính sẵn base^1, base^3, ..., base^(2^w - 1). Gặp bít 0 thì chỉ bình phương;
    gặp bít 1 thì lấy một cửa sổ dài tối đa w bít kết thúc bằng bít 1, bình
    phương bằng số bít của cửa sổ rồi nhân một lần với giá trị tra trong bảng.
    Số phép bình phương không đổi, số phép nhân giảm từ khoảng n/2 xuống n/(w+1).
    """
    _check_args(exp, mod)
    if mod == 1:
        return 0
    base %= mod

    # odd[k] = base^(2k+1)
    sq = base * base % mod
    odd = [base]
    for _ in range((1 << (w - 1)) - 1):
        odd.append(odd[-1] * sq % mod)

    bits = bin(exp)[2:]          # duyệt chuỗi bít nhanh hơn dịch bít trên số lớn
    n = len(bits)
    result = 1
    i = 0
    while i < n:
        if bits[i] == "0":
            result = result * result % mod
            i += 1
            continue
        j = min(i + w, n)
        while bits[j - 1] == "0":
            j -= 1
        for _ in range(j - i):
            result = result * result % mod
        result = result * odd[int(bits[i:j], 2) >> 1] % mod
        i = j
    return result


def mod_pow_trace(base: int, exp: int, mod: int):
    """Bình phương và nhân (bít thấp lên cao), trả về thêm từng bước để in bảng.

    Mỗi bước gồm: i (vị trí bít), bit, power = base^(2^i) mod m,
    result (kết quả sau bước), used (bước này có nhân vào kết quả hay không).
    """
    _check_args(exp, mod)
    steps = []
    result = 1 % mod
    power = base % mod
    i = 0
    while exp:
        bit = exp & 1
        if bit:
            result = result * power % mod
        steps.append({"i": i, "bit": bit, "power": power, "result": result, "used": bool(bit)})
        power = power * power % mod
        exp >>= 1
        i += 1
    return result, steps


def mod_pow_trace_msb(base: int, exp: int, mod: int):
    """Bình phương và nhân, duyệt bít từ cao xuống thấp, trả về từng bước.

    Bắt đầu r = 1. Ở mỗi bít: r = r^2 mod m, nếu bít bằng 1 thì r = r * base mod m.
    Mỗi bước gồm: bit, square (r^2 mod m) và result (r sau bước).
    """
    _check_args(exp, mod)
    base %= mod
    r = 1 % mod
    steps = []
    for ch in bin(exp)[2:]:
        r = r * r % mod
        square = r
        if ch == "1":
            r = r * base % mod
        steps.append({"bit": int(ch), "square": square, "result": r})
    return r, steps


def jacobi(a: int, n: int) -> int:
    """Ký hiệu Jacobi (a/n) với n lẻ dương, trả về 1, -1 hoặc 0.

    Khi n nguyên tố thì đây là ký hiệu Legendre: (a/n) = 1 đúng khi a là số
    chính phương modulo n. Cách tính giống Euclid nên nhanh hơn nhiều so với
    tính a^((n-1)/2) mod n.
    """
    if n <= 0 or not n & 1:
        raise ValueError("n phải là số lẻ dương")
    a %= n
    result = 1
    while a:
        # tách hết thừa số 2 một lần; (2/n) = -1 khi n ≡ 3, 5 (mod 8)
        twos = (a & -a).bit_length() - 1
        a >>= twos
        if twos & 1 and n & 7 in (3, 5):
            result = -result
        # luật tương hỗ bậc hai
        if a & 3 == 3 and n & 3 == 3:
            result = -result
        a, n = n % a, a
    return result if n == 1 else 0


def egcd(a: int, b: int):
    """Euclid mở rộng: trả về (d, x, y) với a*x + b*y = d = gcd(a, b)."""
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r:
        k = old_r // r
        old_r, r = r, old_r - k * r
        old_x, x = x, old_x - k * x
        old_y, y = y, old_y - k * y
    return old_r, old_x, old_y


def gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return abs(a)


def mod_inverse(a: int, m: int) -> int:
    """a^(-1) mod m, báo lỗi khi gcd(a, m) khác 1."""
    d, x, _ = egcd(a % m, m)
    if d != 1:
        raise ValueError(f"{a} không có nghịch đảo modulo {m}")
    return x % m


def int_to_bytes(n: int, length: int = None) -> bytes:
    if length is None:
        length = max(1, (n.bit_length() + 7) // 8)
    return n.to_bytes(length, "big")


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")
