"""Kiểm tra và sinh số nguyên tố: Miller–Rabin, số nguyên tố ngẫu nhiên,
số nguyên tố an toàn p = 2q + 1.

Số ngẫu nhiên lấy từ module secrets của Python (nguồn ngẫu nhiên an toàn của hệ
điều hành), không phải thư viện mật mã.
"""
import secrets

from .modmath import mod_pow


def _sieve(limit: int):
    """Sàng Eratosthenes, trả về các số nguyên tố nhỏ hơn limit."""
    flags = bytearray([1]) * limit
    flags[0:2] = b"\x00\x00"
    for i in range(2, int(limit ** 0.5) + 1):
        if flags[i]:
            flags[i * i::i] = bytes(len(range(i * i, limit, i)))
    return [i for i in range(limit) if flags[i]]


SIEVE_PRIMES = _sieve(1 << 16)          # 6542 số nguyên tố dưới 65536, dùng để sàng
SMALL_PRIMES = SIEVE_PRIMES[:303]       # các số nguyên tố dưới 2000, dùng để chia thử


def miller_rabin(n: int, rounds: int = 40, bases=None) -> bool:
    """Kiểm tra Miller–Rabin.

    Viết n - 1 = 2^s * d với d lẻ. Với cơ số a, tính x = a^d mod n. Nếu x = 1
    hoặc x = n - 1 thì a không chứng minh được gì. Ngược lại bình phương x tối
    đa s - 1 lần, gặp n - 1 thì cũng bỏ qua, không gặp thì a là nhân chứng và
    n chắc chắn là hợp số. Sau `rounds` cơ số ngẫu nhiên, xác suất kết luận
    sai không quá 4^(-rounds).
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if not n & 1:
        return False

    d = n - 1
    s = (d & -d).bit_length() - 1
    d >>= s

    if bases is None:
        bases = (2 + secrets.randbelow(n - 3) for _ in range(rounds))
    for a in bases:
        a %= n
        if a in (0, 1, n - 1):
            continue
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Chia thử cho các số nguyên tố nhỏ trước, rồi mới Miller–Rabin."""
    if n < 2:
        return False
    for sp in SMALL_PRIMES:
        if n % sp == 0:
            return n == sp
    if n < SMALL_PRIMES[-1] ** 2:
        return True
    return miller_rabin(n, rounds)


def _candidates(start: int, span: int, safe: bool, limit: int):
    """Sàng các ứng viên n = start + 2k (k = 0 .. span-1).

    Loại những n chia hết cho một số nguyên tố nhỏ sp, và nếu safe=True thì
    loại cả những n mà 2n + 1 chia hết cho sp. Chỉ dùng sp < limit để không
    loại nhầm chính sp. Mỗi sp chỉ tốn một phép gán lát cắt trên bytearray,
    nhanh hơn nhiều so với chia thử từng ứng viên.
    """
    keep = bytearray([1]) * span
    for sp in SIEVE_PRIMES[1:]:
        if sp >= limit:
            break
        half = (sp + 1) >> 1                       # nghịch đảo của 2 modulo sp
        r = start % sp
        k = (-r * half) % sp                       # n ≡ 0 (mod sp)
        if k < span:
            keep[k::sp] = bytes(len(range(k, span, sp)))
        if safe:
            k = (-(2 * r + 1) * half * half) % sp  # 2n + 1 ≡ 0 (mod sp)
            if k < span:
                keep[k::sp] = bytes(len(range(k, span, sp)))
    return [start + 2 * k for k in range(span) if keep[k]]


def gen_prime(bits: int) -> int:
    """Số nguyên tố ngẫu nhiên có đúng `bits` bít."""
    if bits < 2:
        raise ValueError("bits phải >= 2")
    if bits <= 16:
        while True:
            n = secrets.randbits(bits) | (1 << (bits - 1)) | 1
            if bits == 2:
                n = 3
            if is_probable_prime(n):
                return n
    while True:
        start = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        for n in _candidates(start, 4 * bits, False, 1 << (bits - 1)):
            if n.bit_length() != bits:
                break
            if miller_rabin(n, 1, [2]) and miller_rabin(n, 40):
                return n


def gen_safe_prime(bits: int, progress=None) -> int:
    """Số nguyên tố an toàn p = 2q + 1 có đúng `bits` bít, q cũng nguyên tố.

    Khi đó p - 1 = 2q chỉ có hai ước nguyên tố là 2 và q, nên tấn công
    Pohlig–Hellman không chia nhỏ được bài toán. `progress(n)` (tuỳ chọn) được
    gọi sau mỗi ứng viên đã thử, để giao diện hiện tiến độ.
    """
    if bits < 3:
        raise ValueError("bits phải >= 3")
    if bits <= 5:
        for p in (5, 7, 11, 23):
            if p.bit_length() == bits:
                return p
    tried = 0
    while True:
        start = secrets.randbits(bits - 1) | (1 << (bits - 2)) | 1
        for q in _candidates(start, 64 * bits, True, 1 << (bits - 2)):
            p = 2 * q + 1
            if p.bit_length() != bits:
                break
            tried += 1
            if progress:
                progress(tried)
            # một vòng cơ số 2 cho cả q và p loại gần hết hợp số, rồi mới kiểm kỹ
            if (miller_rabin(q, 1, [2]) and miller_rabin(p, 1, [2])
                    and miller_rabin(q, 20) and miller_rabin(p, 20)):
                return p
