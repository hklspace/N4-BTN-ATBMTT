"""Trao đổi khoá Diffie–Hellman.

Ký hiệu (giống báo cáo):
  p, g       tham số công khai (số nguyên tố và phần tử sinh)
  q          cấp nhóm con do g sinh ra
  a, b       khoá riêng của Alice và Bob
  A = g^a mod p, B = g^b mod p   khoá công khai
  K = B^a mod p = A^b mod p = g^(ab) mod p   bí mật chung
"""
import secrets
from dataclasses import dataclass

from .groups import DHGroup
from .modmath import jacobi, mod_pow


class InvalidPublicKey(ValueError):
    """Khoá công khai nhận được không hợp lệ, có thể do bị tấn công."""


@dataclass
class KeyPair:
    group: DHGroup
    private: int
    public: int


def generate_private_key(group: DHGroup, short: bool = True) -> int:
    """Khoá riêng ngẫu nhiên trong [2, n - 1].

    n là cấp của g. Với nhóm RFC và short=True thì n bị giới hạn bởi
    2^private_bits (khoá riêng ngắn, xem groups.py).
    """
    n = group.order
    if n <= 3:
        raise ValueError("nhóm quá nhỏ")
    if short and group.private_bits:
        n = min(n, 1 << group.private_bits)
    return 2 + secrets.randbelow(n - 2)


def compute_public_key(group: DHGroup, private: int) -> int:
    if not 1 <= private < group.p - 1:
        raise ValueError("khoá riêng phải nằm trong khoảng 1 .. p - 2")
    return mod_pow(group.g, private, group.p)


def generate_keypair(group: DHGroup, private: int = None, short: bool = True) -> KeyPair:
    """Sinh cặp khoá. Truyền sẵn `private` khi muốn chạy lại ví dụ tính tay."""
    if private is None:
        private = generate_private_key(group, short)
    return KeyPair(group, private, compute_public_key(group, private))


def validate_public_key(group: DHGroup, y: int) -> None:
    """Kiểm tra khoá công khai của bên kia trước khi dùng (NIST SP 800-56A).

    1 < y < p - 1 loại các giá trị 0, 1, p - 1 (nhận y = 1 thì K luôn bằng 1).
    Nếu nhóm có cấp q đã biết thì y còn phải thuộc nhóm con cấp q, tức
    y^q ≡ 1 (mod p), để chặn tấn công nhóm con nhỏ.
    """
    if not isinstance(y, int):
        raise InvalidPublicKey("khoá công khai phải là số nguyên")
    if not 1 < y < group.p - 1:
        raise InvalidPublicKey(f"khoá công khai phải thoả 1 < y < p - 1 (nhận được y = {y})")
    if group.q is not None and not in_subgroup(group, y):
        raise InvalidPublicKey("khoá công khai không thuộc nhóm con cấp q (nghi tấn công nhóm con nhỏ)")


def in_subgroup(group: DHGroup, y: int) -> bool:
    """y có thuộc nhóm con cấp q không, tức y^q ≡ 1 (mod p)?

    Khi p = 2q + 1, nhóm con cấp q chính là tập các số chính phương modulo p,
    nên chỉ cần ký hiệu Legendre (y/p) = 1. Hai cách cho cùng kết quả nhưng
    tính Jacobi nhanh hơn tính y^q mod p hàng chục lần.
    """
    if group.q == (group.p - 1) // 2:
        return jacobi(y, group.p) == 1
    return mod_pow(y, group.q, group.p) == 1


def compute_shared_secret(group: DHGroup, my_private: int, their_public: int,
                          validate: bool = True) -> int:
    """K = (khoá công khai bên kia)^(khoá riêng của mình) mod p."""
    if validate:
        validate_public_key(group, their_public)
    return mod_pow(their_public, my_private, group.p)


def shared_secret_bytes(group: DHGroup, k: int) -> bytes:
    """K dạng chuỗi byte có độ dài cố định bằng độ dài của p.

    Giữ nguyên các byte 0 ở đầu để thời gian xử lý ở bước sau không phụ thuộc
    vào giá trị của K (lỗi này là nguyên nhân của tấn công Raccoon).
    """
    return k.to_bytes((group.bits + 7) // 8, "big")
