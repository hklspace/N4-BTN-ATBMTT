"""Mã hoá và giải mã tệp bằng khoá sinh từ bí mật chung Diffie–Hellman.

Kiểu encrypt-then-MAC:
    K --HKDF--> (k_enc, k_mac)
    bản mã = ChaCha20(k_enc, nonce, bản rõ)
    tag    = HMAC-SHA256(k_mac, phần đầu || bản mã)

Định dạng tệp .dhenc:
    "DHENC1" (6 byte) | độ dài tên (2 byte) | tên tệp gốc (UTF-8)
    | nonce (12 byte) | bản mã | tag (32 byte)
"""
import os
import secrets
import struct

from .chacha20 import chacha20_xor
from .kdf import constant_time_equal, hmac_sha256

MAGIC = b"DHENC1"
TAG_LEN = 32
NONCE_LEN = 12


class IntegrityError(ValueError):
    """Tag HMAC không khớp: dữ liệu bị sửa hoặc dùng sai khoá."""


def encrypt_bytes(k_enc: bytes, k_mac: bytes, plaintext: bytes, filename: str = "") -> bytes:
    name = os.path.basename(filename).encode("utf-8")[:255]
    nonce = secrets.token_bytes(NONCE_LEN)          # mỗi lần mã hoá một nonce mới
    header = MAGIC + struct.pack(">H", len(name)) + name + nonce
    ciphertext = chacha20_xor(k_enc, nonce, plaintext)
    tag = hmac_sha256(k_mac, header + ciphertext)
    return header + ciphertext + tag


def parse_blob(blob: bytes):
    """Tách dữ liệu đã mã hoá thành (phần đầu, tên tệp, nonce, bản mã, tag)."""
    if not blob.startswith(MAGIC) or len(blob) < len(MAGIC) + 2 + NONCE_LEN + TAG_LEN:
        raise ValueError("không phải dữ liệu .dhenc hợp lệ")
    (name_len,) = struct.unpack(">H", blob[6:8])
    pos = 8 + name_len
    if pos + NONCE_LEN + TAG_LEN > len(blob):
        raise ValueError("dữ liệu .dhenc bị cắt cụt")
    name = blob[8:pos].decode("utf-8", errors="replace")
    nonce = blob[pos:pos + NONCE_LEN]
    header = blob[:pos + NONCE_LEN]
    ciphertext = blob[pos + NONCE_LEN:-TAG_LEN]
    tag = blob[-TAG_LEN:]
    return header, name, nonce, ciphertext, tag


def decrypt_bytes(k_enc: bytes, k_mac: bytes, blob: bytes):
    """Trả về (tên tệp gốc, bản rõ). Báo IntegrityError nếu tag không khớp."""
    header, name, nonce, ciphertext, tag = parse_blob(blob)
    if not constant_time_equal(hmac_sha256(k_mac, header + ciphertext), tag):
        raise IntegrityError("kiểm tra toàn vẹn thất bại (sai khoá hoặc dữ liệu bị sửa)")
    return name, chacha20_xor(k_enc, nonce, ciphertext)


def encrypt_file(k_enc: bytes, k_mac: bytes, in_path: str, out_path: str) -> int:
    with open(in_path, "rb") as f:
        data = f.read()
    blob = encrypt_bytes(k_enc, k_mac, data, os.path.basename(in_path))
    with open(out_path, "wb") as f:
        f.write(blob)
    return len(blob)


def decrypt_file(k_enc: bytes, k_mac: bytes, in_path: str, out_dir: str, prefix: str = "decrypted_") -> str:
    with open(in_path, "rb") as f:
        blob = f.read()
    name, data = decrypt_bytes(k_enc, k_mac, blob)
    # chỉ lấy tên tệp, bỏ phần đường dẫn để không ghi ra ngoài thư mục out_dir
    name = os.path.basename(name.replace("\\", "/")) or "output.bin"
    out_path = os.path.join(out_dir, prefix + name)
    with open(out_path, "wb") as f:
        f.write(data)
    return out_path
