"""Chữ ký số RSA rút gọn, dùng để xác thực khoá công khai Diffie–Hellman.

Mỗi bên có một cặp khoá RSA dài hạn và biết trước khoá công khai RSA của bên
kia (giống chứng chỉ trong TLS hay fingerprint trong SSH). Alice ký lên A trước
khi gửi, Bob kiểm tra chữ ký. Mallory không có khoá riêng RSA của Alice nên
không ký được giá trị giả của mình, và bị phát hiện.

Đây là bản rút gọn để minh hoạ (đệm giống PKCS#1 v1.5 nhưng bỏ DigestInfo).
Hệ thống thật dùng RSA-PSS, ECDSA hoặc Ed25519.
"""
from dataclasses import dataclass

from .modmath import gcd, mod_inverse, mod_pow
from .primes import gen_prime
from .sha256 import sha256, sha256_hex


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int

    def fingerprint(self) -> str:
        """Dấu vân tay ngắn để hai bên đọc cho nhau so sánh."""
        h = sha256_hex(self.n.to_bytes((self.n.bit_length() + 7) // 8, "big") + self.e.to_bytes(4, "big"))
        return ":".join(h[i:i + 4] for i in range(0, 16, 4))


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    d: int
    public: RSAPublicKey


def generate_rsa_keypair(bits: int = 1024, e: int = 65537) -> RSAPrivateKey:
    """Sinh cặp khoá RSA: n = p·q, d = e^(-1) mod φ(n)."""
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits - bits // 2)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if gcd(e, phi) == 1:
            n = p * q
            d = mod_inverse(e, phi)
            return RSAPrivateKey(n, d, RSAPublicKey(n, e))


def _encode(message: bytes, n: int) -> int:
    """Băm thông điệp rồi đệm: 00 01 FF..FF 00 || SHA-256(message)."""
    k = (n.bit_length() + 7) // 8
    digest = sha256(message)
    padding = b"\xff" * (k - len(digest) - 3)
    return int.from_bytes(b"\x00\x01" + padding + b"\x00" + digest, "big")


def sign(priv: RSAPrivateKey, message: bytes) -> int:
    """s = EM^d mod n."""
    return mod_pow(_encode(message, priv.n), priv.d, priv.n)


def verify(pub: RSAPublicKey, message: bytes, signature: int) -> bool:
    """Đúng khi s^e mod n bằng EM tính lại từ thông điệp."""
    if not (0 <= signature < pub.n):
        return False
    return mod_pow(signature, pub.e, pub.n) == _encode(message, pub.n)


def encrypt_int(pub: RSAPublicKey, m: int) -> int:
    """RSA thô c = m^e mod n, không đệm. Chỉ dùng để đo tốc độ khi so với DH."""
    return mod_pow(m, pub.e, pub.n)


def decrypt_int(priv: RSAPrivateKey, c: int) -> int:
    """RSA thô m = c^d mod n, không dùng CRT. Chỉ dùng để đo tốc độ."""
    return mod_pow(c, priv.d, priv.n)
