"""Hàm băm SHA-256 theo FIPS 180-4.

Dùng để dẫn xuất khoá (qua HMAC/HKDF), kiểm tra toàn vẹn tệp, băm thông điệp
trước khi ký RSA và tạo mã xác nhận ngắn. Không gọi hashlib; hashlib chỉ dùng
trong bộ kiểm thử để so kết quả.
"""
import struct

# 32 bít đầu phần thập phân căn bậc ba của 64 số nguyên tố đầu tiên
_K = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)

# 32 bít đầu phần thập phân căn bậc hai của 8 số nguyên tố đầu tiên
_H0 = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
       0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

_M = 0xFFFFFFFF
_unpack16 = struct.Struct(">16I").unpack_from


def _compress(h, buf, offset=0, _K=_K, _M=_M):
    """Hàm nén cho một khối 64 byte bắt đầu tại buf[offset].

    Đọc khối bằng unpack_from để khỏi cắt chuỗi, viết thẳng các phép quay bít
    và chỉ cắt về 32 bít ở chỗ cần thiết.
    """
    w = list(_unpack16(buf, offset))
    for t in range(16, 64):
        x, y = w[t - 15], w[t - 2]
        s0 = ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)
        s1 = ((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10)
        w.append((w[t - 16] + s0 + w[t - 7] + s1) & _M)

    a, b, c, d, e, f, g, hh = h
    for t in range(64):
        S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
        t1 = hh + (S1 & _M) + ((e & f) ^ (~e & g)) + _K[t] + w[t]
        S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
        t2 = (S0 & _M) + ((a & b) ^ (a & c) ^ (b & c))
        hh, g, f, e = g, f, e, (d + t1) & _M
        d, c, b, a = c, b, a, (t1 + t2) & _M

    return (
        (h[0] + a) & _M, (h[1] + b) & _M, (h[2] + c) & _M, (h[3] + d) & _M,
        (h[4] + e) & _M, (h[5] + f) & _M, (h[6] + g) & _M, (h[7] + hh) & _M,
    )


class SHA256:
    """Dùng giống hashlib: update() nhiều lần rồi digest()."""
    block_size = 64
    digest_size = 32

    def __init__(self, data: bytes = b""):
        self._h = _H0
        self._buf = b""
        self._len = 0
        if data:
            self.update(data)

    def update(self, data: bytes):
        self._len += len(data)
        if self._buf:
            data = self._buf + data
        full = len(data) & ~63
        h = self._h
        for off in range(0, full, 64):
            h = _compress(h, data, off)
        self._h = h
        self._buf = bytes(data[full:])
        return self

    def digest(self) -> bytes:
        # đệm: bít 1, các bít 0, rồi độ dài thông điệp tính bằng bít (64 bít)
        pad = b"\x80" + b"\x00" * ((55 - self._len) % 64) + struct.pack(">Q", self._len * 8)
        tail = self._buf + pad
        h = self._h
        for off in range(0, len(tail), 64):
            h = _compress(h, tail, off)
        return struct.pack(">8I", *h)

    def hexdigest(self) -> str:
        return self.digest().hex()


def sha256(data: bytes) -> bytes:
    return SHA256(data).digest()


def sha256_hex(data: bytes) -> str:
    return SHA256(data).hexdigest()
