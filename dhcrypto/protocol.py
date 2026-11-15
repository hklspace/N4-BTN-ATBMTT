"""Mô phỏng một phiên trao đổi khoá giữa Alice và Bob qua kênh công khai, có
thể có Mallory đứng giữa.

Tệp này chỉ chứa phần xử lý. Mỗi việc xảy ra được báo ra ngoài bằng một Event
qua hàm `emit`, còn việc in ra màn hình do app/ đảm nhận.

  mitm=False, auth=False   DH thường, chỉ có người nghe lén thụ động
  mitm=True,  auth=False   Mallory chen giữa và đọc được toàn bộ dữ liệu
  mitm=True,  auth=True    mỗi bên ký RSA lên khoá công khai DH của mình,
                           Mallory không ký giả được nên bị phát hiện
"""
from dataclasses import dataclass, field
from typing import Callable, Optional

from .dh import compute_shared_secret, generate_keypair, shared_secret_bytes
from .file_cipher import decrypt_bytes, encrypt_bytes, parse_blob
from .groups import DHGroup
from .kdf import derive_session_keys
from .rsa_sign import RSAPrivateKey, generate_rsa_keypair, sign, verify
from .sha256 import sha256


class AuthenticationError(Exception):
    """Chữ ký trên khoá công khai DH không hợp lệ, nghi có người đứng giữa."""


@dataclass
class Event:
    actor: str           # Alice, Bob, Mallory hoặc Kênh
    kind: str            # info, send, compute, secret, attack, ok, fail
    text: str
    data: dict = field(default_factory=dict)


def short_auth_string(k_bytes: bytes) -> str:
    """Mã xác nhận ngắn tính từ bí mật chung, để hai bên đọc cho nhau so sánh."""
    h = sha256(k_bytes).hex()
    return f"{h[0:4]}-{h[4:8]}".upper()


def _pubkey_message(name: str, group: DHGroup, y: int) -> bytes:
    """Nội dung được ký gồm danh tính, nhóm tham số và khoá công khai DH."""
    return b"DH-PUBKEY|" + name.encode() + b"|" + group.name.encode() + b"|" + str(y).encode()


class Party:
    """Alice hoặc Bob."""

    def __init__(self, name: str, group: DHGroup, private: int = None,
                 rsa_key: Optional[RSAPrivateKey] = None):
        self.name = name
        self.group = group
        self.kp = generate_keypair(group, private)
        self.rsa_key = rsa_key
        self.trusted = {}                # tên bên kia -> khoá công khai RSA đã biết trước
        self.shared = None               # bí mật chung K
        self.k_enc = self.k_mac = None
        self.sas = None

    def hello(self, auth: bool) -> dict:
        msg = {"from": self.name, "y": self.kp.public}
        if auth:
            msg["sig"] = sign(self.rsa_key, _pubkey_message(self.name, self.group, self.kp.public))
        return msg

    def accept(self, msg: dict, peer: str, auth: bool):
        """Nhận khoá công khai bên kia, kiểm tra chữ ký nếu có, rồi tính K và khoá phiên."""
        y = msg["y"]
        if auth:
            pub = self.trusted[peer]
            sig = msg.get("sig")
            if sig is None or not verify(pub, _pubkey_message(peer, self.group, y), sig):
                raise AuthenticationError(
                    f"{self.name}: chữ ký trên khoá công khai của '{peer}' không hợp lệ")
        self.shared = compute_shared_secret(self.group, self.kp.private, y)
        kb = shared_secret_bytes(self.group, self.shared)
        self.k_enc, self.k_mac = derive_session_keys(kb)
        self.sas = short_auth_string(kb)
        return self.shared


class Mallory:
    """Kẻ đứng giữa, thay khoá công khai của cả hai bên bằng M = g^m mod p."""

    def __init__(self, group: DHGroup, rsa_key: Optional[RSAPrivateKey] = None, private: int = None):
        self.group = group
        self.kp = generate_keypair(group, private)
        self.rsa_key = rsa_key
        self.keys = {}          # tên nạn nhân -> (K, k_enc, k_mac, mã xác nhận)
        self.stolen = []        # các bản rõ đọc trộm được

    def intercept_hello(self, msg: dict, auth: bool) -> dict:
        victim = msg["from"]
        k = compute_shared_secret(self.group, self.kp.private, msg["y"])
        kb = shared_secret_bytes(self.group, k)
        self.keys[victim] = (k,) + derive_session_keys(kb) + (short_auth_string(kb),)
        forged = {"from": victim, "y": self.kp.public}
        if auth:
            # Mallory không có khoá riêng RSA của nạn nhân nên chỉ ký được bằng khoá của mình
            if self.rsa_key is None:
                self.rsa_key = generate_rsa_keypair(512)
            forged["sig"] = sign(self.rsa_key, _pubkey_message(victim, self.group, self.kp.public))
        return forged

    def intercept_data(self, blob: bytes, sender: str, receiver: str, tamper=None) -> bytes:
        _, k_enc, k_mac, _ = self.keys[sender]
        name, plain = decrypt_bytes(k_enc, k_mac, blob)
        self.stolen.append((sender, name, plain))
        if tamper:
            plain = tamper(plain)
        _, k_enc2, k_mac2, _ = self.keys[receiver]
        return encrypt_bytes(k_enc2, k_mac2, plain, name)


@dataclass
class SessionResult:
    ok: bool
    alice: Party
    bob: Party
    mallory: Optional[Mallory]
    received: Optional[bytes] = None
    received_name: str = ""
    error: str = ""
    blob: bytes = b""          # dữ liệu đã mã hoá mà Bob nhận được


def run_session(group: DHGroup, data: bytes, filename: str = "message.txt",
                mitm: bool = False, auth: bool = False, tamper: Callable = None,
                emit: Callable[[Event], None] = lambda e: None,
                a: int = None, b: int = None, m: int = None, rsa_bits: int = 1024) -> SessionResult:
    """Chạy trọn một phiên: trao đổi khoá, Alice mã hoá `data` gửi Bob, Bob giải mã.

    a, b, m là khoá riêng của Alice, Bob, Mallory; để None thì sinh ngẫu nhiên.
    """
    alice_rsa = bob_rsa = None
    if auth:
        emit(Event("Kênh", "info", f"Chuẩn bị: mỗi bên sinh cặp khoá RSA {rsa_bits} bít dài hạn "
                                   "và biết trước khoá công khai RSA của nhau (như chứng chỉ)."))
        alice_rsa, bob_rsa = generate_rsa_keypair(rsa_bits), generate_rsa_keypair(rsa_bits)

    alice = Party("Alice", group, a, alice_rsa)
    bob = Party("Bob", group, b, bob_rsa)
    if auth:
        alice.trusted["Bob"] = bob_rsa.public
        bob.trusted["Alice"] = alice_rsa.public
        emit(Event("Alice", "info", f"Vân tay RSA của Alice: {alice_rsa.public.fingerprint()}"))
        emit(Event("Bob", "info", f"Vân tay RSA của Bob:   {bob_rsa.public.fingerprint()}"))

    mallory = Mallory(group, private=m) if mitm else None
    emit(Event("Kênh", "info", f"Tham số công khai: {group.name}, p dài {group.bits} bít, g = {group.g}"))
    if group.private_bits:
        emit(Event("Kênh", "info", f"Khoá riêng dài {group.private_bits} bít (theo NIST SP 800-56A và RFC 7919)"))
    emit(Event("Alice", "secret", "Chọn khoá riêng a", {"x": alice.kp.private}))
    emit(Event("Alice", "compute", "Tính A = g^a mod p", {"y": alice.kp.public}))
    emit(Event("Bob", "secret", "Chọn khoá riêng b", {"x": bob.kp.private}))
    emit(Event("Bob", "compute", "Tính B = g^b mod p", {"y": bob.kp.public}))
    if mallory:
        emit(Event("Mallory", "attack", "Chọn khoá riêng m, tính M = g^m mod p", {"y": mallory.kp.public}))

    # Alice gửi A
    msg_a = alice.hello(auth)
    emit(Event("Alice", "send", "Gửi A" + (" kèm chữ ký RSA" if auth else "") + " cho Bob", {"y": msg_a["y"]}))
    if mallory:
        msg_a = mallory.intercept_hello(msg_a, auth)
        emit(Event("Mallory", "attack", "Chặn A, gửi M cho Bob và nói đó là của Alice"
                   + (" (chữ ký giả, vì Mallory chỉ có khoá RSA của chính mình)" if auth else ""),
                   {"y": msg_a["y"]}))

    # Bob gửi B
    msg_b = bob.hello(auth)
    emit(Event("Bob", "send", "Gửi B" + (" kèm chữ ký RSA" if auth else "") + " cho Alice", {"y": msg_b["y"]}))
    if mallory:
        msg_b = mallory.intercept_hello(msg_b, auth)
        emit(Event("Mallory", "attack", "Chặn B, gửi M cho Alice và nói đó là của Bob"
                   + (" (chữ ký giả)" if auth else ""), {"y": msg_b["y"]}))

    # Mỗi bên tính bí mật chung
    try:
        bob.accept(msg_a, "Alice", auth)
        if auth:
            emit(Event("Bob", "ok", "Chữ ký trên khoá công khai của Alice hợp lệ"))
        alice.accept(msg_b, "Bob", auth)
        if auth:
            emit(Event("Alice", "ok", "Chữ ký trên khoá công khai của Bob hợp lệ"))
    except AuthenticationError as exc:
        emit(Event("Bob" if "Bob:" in str(exc) else "Alice", "fail", str(exc)))
        emit(Event("Kênh", "fail", "Phát hiện người đứng giữa, huỷ phiên và không gửi dữ liệu."))
        return SessionResult(False, alice, bob, mallory, error=str(exc))

    emit(Event("Alice", "compute", "K = (khoá nhận được)^a mod p", {"k": alice.shared, "sas": alice.sas}))
    emit(Event("Bob", "compute", "K = (khoá nhận được)^b mod p", {"k": bob.shared, "sas": bob.sas}))
    if mallory:
        emit(Event("Mallory", "attack", "Có K_AM chung với Alice và K_BM chung với Bob",
                   {"k1": mallory.keys["Alice"][0], "k2": mallory.keys["Bob"][0]}))

    # Alice mã hoá dữ liệu gửi Bob
    blob = encrypt_bytes(alice.k_enc, alice.k_mac, data, filename)
    _, _, nonce, ct, tag = parse_blob(blob)
    emit(Event("Alice", "send", f"Mã hoá '{filename}' ({len(data):,} byte) bằng ChaCha20 + HMAC, gửi cho Bob",
               {"cipher_preview": ct[:24].hex(), "size": len(blob)}))
    if mallory:
        blob = mallory.intercept_data(blob, "Alice", "Bob", tamper)
        _, _, stolen = mallory.stolen[-1]
        emit(Event("Mallory", "attack", "Giải mã bằng khoá của K_AM, đọc nội dung, mã hoá lại bằng khoá của K_BM rồi chuyển cho Bob"
                   + (" (đã sửa nội dung)" if tamper else ""), {"plain_preview": stolen[:120]}))

    # Bob giải mã
    try:
        name, plain = decrypt_bytes(bob.k_enc, bob.k_mac, blob)
    except ValueError as exc:      # sai khoá hoặc dữ liệu bị sửa
        emit(Event("Bob", "fail", f"Giải mã thất bại: {exc}"))
        return SessionResult(False, alice, bob, mallory, error=str(exc))
    emit(Event("Bob", "ok", f"Giải mã thành công '{name}' ({len(plain):,} byte), kiểm tra HMAC đạt"))
    return SessionResult(True, alice, bob, mallory, plain, name, blob=blob)
