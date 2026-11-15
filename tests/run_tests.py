"""Bộ kiểm thử Diffie–Hellman.

Gồm các ca tự viết (VD: tính tay, tính chất của thuật toán, các ca lỗi) và các ca đối chiếu với thư viện hoặc test vector chuẩn (FIPS 180-4, RFC 4231, RFC 5869, RFC 8439, RFC 3526, RFC 7919) 

Chạy bằng  python main.py test  hoặc  python -m tests.run_tests
Kết quả được lưu tại output/test_report.txt
"""
import hashlib
import hmac as std_hmac
import os
import random
import secrets
import shutil
import subprocess
import sys# Tắt cảnh báo khi đối chiếu với thư viện cryptography
import time
import warnings

# Tắt cảnh báo khi đối chiếu với thư viện cryptography

warnings.filterwarnings("ignore", message=".*Diffie-Hellman over finite fields.*")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from dhcrypto import groups as G                                     # noqa: E402
from dhcrypto.attacks import brute_force_dlog, bsgs_dlog, make_dlp_instance  # noqa: E402
from dhcrypto.chacha20 import chacha20_block, chacha20_xor           # noqa: E402
from dhcrypto.dh import (InvalidPublicKey, compute_shared_secret,     # noqa: E402
                         generate_keypair, shared_secret_bytes, validate_public_key)
from dhcrypto.file_cipher import IntegrityError, decrypt_bytes, encrypt_bytes  # noqa: E402
from dhcrypto.kdf import derive_session_keys, hkdf, hmac_sha256      # noqa: E402
from dhcrypto.modmath import (jacobi, mod_inverse, mod_pow,           # noqa: E402
                              mod_pow_basic, mod_pow_trace, mod_pow_trace_msb, mod_pow_window)
from dhcrypto.primes import gen_prime, gen_safe_prime, is_probable_prime, miller_rabin  # noqa: E402
from dhcrypto.primitive_root import is_primitive_root, power_table    # noqa: E402
from dhcrypto.protocol import run_session                             # noqa: E402
from dhcrypto.rsa_sign import generate_rsa_keypair, sign, verify      # noqa: E402
from dhcrypto.sha256 import sha256_hex                                # noqa: E402

from app import ui                                                    # noqa: E402


class Skip(Exception):
    """Ca bị bỏ qua, ví dụ máy không có OpenSSL."""


TESTS = []


def _import(module_name, names):
    """Nhập thư viện dùng để so kết quả, trả về None nếu máy không có hoặc cài bị lỗi."""
    try:
        mod = __import__(module_name, fromlist=names)
        return [getattr(mod, n) for n in names]
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:          # bản cryptography cài lỗi có thể ném cả PanicException
        return None


def case(code, kind, desc):
    def deco(fn):
        TESTS.append((code, kind, desc, fn))
        return fn
    return deco


def check(cond, msg="sai kết quả"):
    if not cond:
        raise AssertionError(msg)


# ---------------------------------------------------------------------------
# Ca tự viết
# ---------------------------------------------------------------------------
@case("TC01", "Tự viết", "Ví dụ p=353, g=3, a=97, b=233 → A=40, B=248, K=160")
def tc01():
    grp = G.EXAMPLE_353
    A, B = generate_keypair(grp, 97), generate_keypair(grp, 233)
    check(A.public == 40 and B.public == 248, f"A={A.public}, B={B.public}")
    ka = compute_shared_secret(grp, A.private, B.public)
    kb = compute_shared_secret(grp, B.private, A.public)
    check(ka == kb == 160, f"K_A={ka}, K_B={kb}")
    # bảng tính tay 3^97 mod 353, duyệt bít từ cao xuống thấp
    _, steps = mod_pow_trace_msb(3, 97, 353)
    check([s["square"] for s in steps] == [1, 9, 23, 176, 265, 331, 131], "hàng r² khác bảng tính tay")
    check([s["result"] for s in steps] == [3, 27, 23, 176, 265, 331, 40], "hàng r khác bảng tính tay")
    return "A=40, B=248, K=160; bảng 3^97 mod 353 khớp từng ô với tính tay"


@case("TC02", "Tự viết", "Ví dụ p=23, g=5, a=6, b=15 → A=8, B=19, K=2")
def tc02():
    grp = G.EXAMPLE_23
    A, B = generate_keypair(grp, 6), generate_keypair(grp, 15)
    check((A.public, B.public) == (8, 19))
    check(compute_shared_secret(grp, 6, B.public) == compute_shared_secret(grp, 15, A.public) == 2)
    _, low = mod_pow_trace(5, 15, 23)                   # 5^15 duyệt từ thấp lên cao
    check([s["result"] for s in low] == [5, 10, 17, 19], "bảng 5^15 khác tính tay")
    _, high = mod_pow_trace_msb(5, 6, 23)               # 5^6 duyệt từ cao xuống thấp
    check([s["square"] for s in high] == [1, 2, 8] and [s["result"] for s in high] == [5, 10, 8],
          "bảng 5^6 khác tính tay")
    return "A=8, B=19, K=2; bảng 5^15 và 5^6 khớp tính tay"


@case("TC03", "Tự viết", "K_A = K_B = g^(ab) mod p trên 300 bộ số nhỏ ngẫu nhiên")
def tc03():
    rng = random.Random(2026)
    small = [n for n in range(50, 5000) if is_probable_prime(n)]
    for _ in range(300):
        p = rng.choice(small)
        g = next(x for x in range(2, p) if is_primitive_root(x, p))
        grp = G.DHGroup("tmp", p, g)
        a, b = rng.randrange(2, p - 1), rng.randrange(2, p - 1)
        A, B = generate_keypair(grp, a), generate_keypair(grp, b)
        ka = compute_shared_secret(grp, a, B.public, validate=False)
        kb = compute_shared_secret(grp, b, A.public, validate=False)
        check(ka == kb == mod_pow(g, a * b, p), f"p={p}, a={a}, b={b}")
    return "300/300 bộ đúng"


@case("TC04", "Tự viết", "100 cặp khoá ngẫu nhiên trên nhóm MODP 2048 bít, thêm 5 cặp khoá riêng đầy đủ: cùng K")
def tc04():
    grp = G.MODP_2048
    for _ in range(100):
        A, B = generate_keypair(grp), generate_keypair(grp)
        check(compute_shared_secret(grp, A.private, B.public) == compute_shared_secret(grp, B.private, A.public))
    for _ in range(5):
        A, B = generate_keypair(grp, short=False), generate_keypair(grp, short=False)
        check(compute_shared_secret(grp, A.private, B.public) == compute_shared_secret(grp, B.private, A.public))
    return "105/105 cặp khớp"


@case("TC05", "Tự viết", "Từ chối khoá công khai không hợp lệ (0, 1, p−1, ≥ p, ngoài nhóm con)")
def tc05():
    grp = G.MODP_2048
    outside = next(y for y in range(3, 100) if mod_pow(y, grp.q, grp.p) != 1)
    bad = {"0": 0, "1": 1, "p−1": grp.p - 1, "p": grp.p, "p+5": grp.p + 5, f"{outside} (ngoài nhóm con)": outside}
    for name, y in bad.items():
        try:
            validate_public_key(grp, y)
        except InvalidPublicKey:
            continue
        raise AssertionError(f"không từ chối y = {name}")
    validate_public_key(grp, generate_keypair(grp).public) # Kiểm tra khóa công khai hợp lệ
    return f"từ chối {len(bad)}/{len(bad)} giá trị xấu, chấp nhận khoá hợp lệ"


@case("TC06", "Tự viết", "Tiêu chuẩn g^((p−1)/r) ≠ 1 khớp định nghĩa căn nguyên thuỷ (bảng lũy thừa)")
def tc06():
    count = 0
    for p in [7, 11, 13, 23, 29, 37, 53, 101, 353]:
        for g in range(2, p):
            by_definition = len({v for _, v in power_table(g, p)}) == p - 1
            check(is_primitive_root(g, p) == by_definition, f"p={p}, g={g}")
            count += 1
    return f"{count} trường hợp khớp"


@case("TC07", "Tự viết", "Mã hoá rồi giải mã tệp văn bản và ảnh bằng khoá DH, SHA-256 trước và sau trùng nhau")
def tc07():
    grp = G.MODP_2048
    A, B = generate_keypair(grp), generate_keypair(grp)
    ka = shared_secret_bytes(grp, compute_shared_secret(grp, A.private, B.public))
    kb = shared_secret_bytes(grp, compute_shared_secret(grp, B.private, A.public))
    enc_a, mac_a = derive_session_keys(ka)
    enc_b, mac_b = derive_session_keys(kb)
    for name in ("sample.txt", "sample.png"):
        with open(os.path.join(ROOT, "data", name), "rb") as f:
            data = f.read()
        blob = encrypt_bytes(enc_a, mac_a, data, name)
        check(data not in blob, "bản mã chứa nguyên bản rõ")
        got_name, back = decrypt_bytes(enc_b, mac_b, blob)
        check(got_name == name and sha256_hex(back) == sha256_hex(data), f"{name} giải mã sai")
    return "sample.txt và sample.png khôi phục đúng"


@case("TC08", "Tự viết", "Sửa 1 bít dữ liệu hoặc dùng sai khoá thì HMAC báo lỗi")
def tc08():
    k_enc, k_mac = derive_session_keys(b"khoa-dung")
    blob = bytearray(encrypt_bytes(k_enc, k_mac, b"Noi dung bi mat", "a.txt"))
    blob[30] ^= 0x01
    try:
        decrypt_bytes(k_enc, k_mac, bytes(blob))
        raise AssertionError("không phát hiện dữ liệu bị sửa")
    except IntegrityError:
        pass
    blob[30] ^= 0x01
    w_enc, w_mac = derive_session_keys(b"khoa-sai")
    try:
        decrypt_bytes(w_enc, w_mac, bytes(blob))
        raise AssertionError("giải mã được bằng khoá sai")
    except IntegrityError:
        pass
    return "phát hiện cả hai trường hợp"


@case("TC09", "Tự viết", "Chữ ký RSA: ký và kiểm tra đúng; sửa thông điệp hoặc chữ ký thì kiểm tra thất bại")
def tc09():
    k = generate_rsa_keypair(1024)
    s = sign(k, b"A = 12345")
    check(verify(k.public, b"A = 12345", s), "chữ ký đúng bị từ chối")
    check(not verify(k.public, b"A = 12346", s), "chấp nhận thông điệp bị sửa")
    check(not verify(k.public, b"A = 12345", s ^ 1), "chấp nhận chữ ký bị sửa")
    other = generate_rsa_keypair(1024)
    check(not verify(other.public, b"A = 12345", s), "chấp nhận chữ ký với khoá khác")
    return "4/4 tình huống đúng"


@case("TC10", "Tự viết", "Người đứng giữa khi không xác thực: Mallory đọc và sửa được tin, mã xác nhận hai bên khác nhau")
def tc10():
    msg = "chuyển vào tài khoản 0123456789".encode()
    r = run_session(G.MODP_2048, msg, mitm=True, auth=False,
                    tamper=lambda x: x.replace(b"0123456789", b"9876543210"))
    check(r.ok and r.mallory.stolen[0][2] == msg, "Mallory không đọc được")
    check(b"9876543210" in r.received, "Mallory không sửa được")
    check(r.alice.sas != r.bob.sas and r.alice.shared != r.bob.shared, "mã xác nhận lẽ ra phải khác")
    return "tấn công thành công đúng như phân tích"


@case("TC11", "Tự viết", "Người đứng giữa khi có xác thực (ký RSA lên khoá DH): phiên bị huỷ, không lộ dữ liệu")
def tc11():
    r = run_session(G.MODP_2048, b"bi mat", mitm=True, auth=True)
    check(not r.ok and "không hợp lệ" in r.error, "không phát hiện tấn công")
    check(r.mallory.stolen == [], "dữ liệu vẫn bị lộ")
    r2 = run_session(G.MODP_2048, b"bi mat", mitm=False, auth=True)
    check(r2.ok and r2.received == b"bi mat", "phiên hợp lệ bị từ chối nhầm")
    return "phát hiện người đứng giữa, phiên hợp lệ vẫn chạy"


@case("TC12", "Tự viết", "Vét cạn và Baby-step Giant-step giải đúng 20 bài logarit rời rạc 20 bít")
def tc12():
    for _ in range(20):
        p, g, x, y = make_dlp_instance(20)
        xb, _ = brute_force_dlog(g, y, p)
        xs, _ = bsgs_dlog(g, y, p)
        check(xb == xs == x, f"p={p}: x={x}, vét cạn={xb}, BSGS={xs}")
    return "20/20 bài giải đúng"


# ---------------------------------------------------------------------------
# Ca đối chiếu với test vector và thư viện chuẩn
# ---------------------------------------------------------------------------
@case("TC13", "Đối chiếu", "Lũy thừa modulo (cơ bản và cửa sổ trượt) so với pow() có sẵn, 1000 bộ đến 2048 bít")
def tc13():
    rng = random.Random(1)
    edge = [(5, 0, 7), (0, 5, 7), (5, 3, 1), (2, 10, 1024), (7, 2 ** 65, 1000003)]
    for b, e, m in edge:
        check(mod_pow_basic(b, e, m) == mod_pow_window(b, e, m) == pow(b, e, m), f"{b}^{e} mod {m}")
    for i in range(1000):
        bits = 2048 if i % 50 == 0 else rng.choice([8, 32, 64, 256, 512])
        m = rng.getrandbits(bits) | 1
        b, e = rng.getrandbits(bits), rng.getrandbits(bits)
        ref = pow(b, e, m)
        check(mod_pow(b, e, m) == ref and mod_pow_window(b, e, m) == ref, f"sai với {bits} bít")
        if bits <= 512:
            check(mod_pow_basic(b, e, m) == ref)
    return "1005/1005 khớp với cả hai cách tính"


@case("TC14", "Đối chiếu", "Miller–Rabin so với chia thử (n < 20000), số Carmichael, số nguyên tố Mersenne")
def tc14():
    def trial(n):
        return n > 1 and all(n % d for d in range(2, int(n ** 0.5) + 1))
    for n in range(20000):
        check(miller_rabin(n) == trial(n), f"sai tại n = {n}")
    for n in [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265, 321197185]:   # Carmichael
        check(not miller_rabin(n), f"nhận nhầm số Carmichael {n}")
    for p in [2 ** 61 - 1, 2 ** 89 - 1, 2 ** 127 - 1, 2 ** 521 - 1]:
        check(miller_rabin(p), "bỏ sót số nguyên tố Mersenne")
    check(not miller_rabin(2 ** 128 + 1), "nhận nhầm F7 = 2^128 + 1")
    inv_ok = all(mod_inverse(a, 10007) == pow(a, -1, 10007) for a in range(1, 2000))
    check(inv_ok, "mod_inverse sai")
    return "đúng toàn bộ, kể cả nghịch đảo modulo so với pow(a, -1, m)"


@case("TC15", "Đối chiếu", "Nhóm RFC 2409/3526/7919 tính lại từ công thức là số nguyên tố an toàn và trùng OpenSSL")
def tc15():
    for grp in G.RFC_GROUPS:
        check(miller_rabin(grp.p, 5) and miller_rabin(grp.q, 5), f"{grp.name} không phải số nguyên tố an toàn")
        check(mod_pow(grp.g, grp.q, grp.p) == 1, f"{grp.name}: g không sinh nhóm con cấp q")
    if not shutil.which("openssl"):
        return "số nguyên tố an toàn ✔ (máy không có OpenSSL nên bỏ qua phần so khớp)"
    imported = _import("cryptography.hazmat.primitives.serialization", ["load_pem_parameters"])
    if imported is None:
        return "số nguyên tố an toàn ✔ (thiếu thư viện cryptography nên bỏ qua phần so khớp)"
    load_pem_parameters, = imported
    matched = []
    for name, grp in [("modp_1536", G.MODP_1536), ("modp_2048", G.MODP_2048),
                      ("modp_3072", G.MODP_3072), ("ffdhe2048", G.FFDHE_2048)]:
        out = subprocess.run(["openssl", "genpkey", "-genparam", "-algorithm", "DH",
                              "-pkeyopt", f"group:{name}"], capture_output=True, timeout=30)
        if out.returncode != 0:
            continue
        nums = load_pem_parameters(out.stdout).parameter_numbers()
        check(nums.p == grp.p and nums.g == grp.g, f"{grp.name} khác OpenSSL")
        matched.append(name)
    check(matched, "không so được với nhóm nào của OpenSSL")
    return "trùng OpenSSL: " + ", ".join(matched)


@case("TC16", "Đối chiếu", "Bí mật chung tự tính trùng thư viện cryptography (cùng p, g, a, b)")
def tc16():
    imported = _import("cryptography.hazmat.primitives.asymmetric", ["dh"])
    if imported is None:
        raise Skip("chưa cài thư viện cryptography (pip install cryptography)")
    dh, = imported
    for grp in (G.MODP_2048, G.FFDHE_2048, G.MODP_3072):
        pn = dh.DHParameterNumbers(grp.p, grp.g)
        A, B = generate_keypair(grp), generate_keypair(grp)
        priv_a = dh.DHPrivateNumbers(A.private, dh.DHPublicNumbers(A.public, pn)).private_key()
        pub_b = dh.DHPublicNumbers(B.public, pn).public_key()
        k_lib = int.from_bytes(priv_a.exchange(pub_b), "big")
        check(k_lib == compute_shared_secret(grp, A.private, B.public), f"{grp.name}: K khác thư viện")
        check(priv_a.public_key().public_numbers().y == A.public, f"{grp.name}: A khác thư viện")
    return "A và K trùng thư viện trên MODP2048, FFDHE2048, MODP3072"


@case("TC17", "Đối chiếu", "SHA-256: test vector FIPS 180-4 và so với hashlib trên dữ liệu ngẫu nhiên")
def tc17():
    vectors = {
        b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq":
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    }
    for m, h in vectors.items():
        check(sha256_hex(m) == h, f"sai với vector {m[:10]!r}")
    for n in [1, 55, 56, 63, 64, 65, 1000, 12345]:
        d = os.urandom(n)
        check(sha256_hex(d) == hashlib.sha256(d).hexdigest(), f"khác hashlib với {n} byte")
    return "3 vector FIPS và 8 độ dài ngẫu nhiên khớp"


@case("TC18", "Đối chiếu", "HMAC-SHA256 (RFC 4231), HKDF (RFC 5869 Test Case 1) và so với thư viện hmac")
def tc18():
    check(hmac_sha256(b"Jefe", b"what do ya want for nothing?").hex() ==
          "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "sai RFC 4231 TC2")
    okm = hkdf(bytes([0x0B]) * 22, 42, bytes(range(13)), bytes(range(0xF0, 0xFA)))
    check(okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
          "sai RFC 5869 TC1")
    for n in [0, 10, 64, 100]:
        k, m = os.urandom(n), os.urandom(200)
        check(hmac_sha256(k, m) == std_hmac.new(k, m, "sha256").digest(), "khác thư viện hmac")
    return "khớp RFC 4231, RFC 5869 và thư viện hmac"


@case("TC19", "Đối chiếu", "ChaCha20: test vector RFC 8439 mục 2.3.2 và so với thư viện cryptography")
def tc19():
    block = chacha20_block(bytes(range(32)), 1, bytes.fromhex("000000090000004a00000000"))
    check(block.hex() == ("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                          "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"), "sai RFC 8439")
    imported = _import("cryptography.hazmat.primitives.ciphers", ["Cipher", "algorithms"])
    if imported is None:
        return "khớp RFC 8439 (bỏ qua phần so với thư viện)"
    Cipher, algorithms = imported
    for n in [1, 64, 65, 1000, 50000]:
        key, nonce, data = os.urandom(32), os.urandom(12), os.urandom(n)
        ref = Cipher(algorithms.ChaCha20(key, (1).to_bytes(4, "little") + nonce), None).encryptor().update(data)
        check(chacha20_xor(key, nonce, data) == ref, f"khác thư viện với {n} byte")
    return "khớp RFC 8439 và thư viện cryptography"


@case("TC20", "Đối chiếu", "Ký hiệu Jacobi so với tiêu chuẩn Euler a^((p−1)/2) mod p (cách kiểm tra khoá nhanh)")
def tc20():
    count = 0
    for p in [n for n in range(3, 2000) if is_probable_prime(n)]:
        for a in range(0, p, max(1, p // 50)):
            euler = mod_pow(a, (p - 1) // 2, p)
            expect = 0 if a % p == 0 else (1 if euler == 1 else -1)
            check(jacobi(a, p) == expect, f"sai tại ({a}/{p})")
            count += 1
    grp = G.MODP_2048
    for _ in range(50):
        y = secrets.randbelow(grp.p - 3) + 2
        check((jacobi(y, grp.p) == 1) == (mod_pow(y, grp.q, grp.p) == 1), "sai trên nhóm 2048 bít")
    return f"{count} trường hợp nhỏ và 50 trường hợp 2048 bít khớp"


@case("TC21", "Tự viết", "Ví dụ người đứng giữa: p=23, g=5, a=6, b=15, m=3 → M=10, K_AM=6, K_BM=5")
def tc21():
    r = run_session(G.EXAMPLE_23, b"ok", mitm=True, auth=False, a=6, b=15, m=3)
    check(r.mallory.kp.public == 10, f"M = {r.mallory.kp.public}")
    check(r.alice.shared == 6 and r.mallory.keys["Alice"][0] == 6, "K_AM sai")
    check(r.bob.shared == 5 and r.mallory.keys["Bob"][0] == 5, "K_BM sai")
    check(r.mallory.stolen[0][2] == b"ok", "Mallory không đọc được dữ liệu")
    return "M=10, K_AM=6, K_BM=5, khớp tính tay"


@case("TC22", "Tự viết", "Sinh số nguyên tố an toàn p = 2q + 1 đúng độ dài, p và q đều nguyên tố")
def tc22():
    for bits in list(range(3, 40)) + [64, 128, 256]:
        p = gen_safe_prime(bits)
        q = (p - 1) // 2
        check(p.bit_length() == bits, f"{bits} bít: p dài {p.bit_length()} bít")
        check(is_probable_prime(p) and is_probable_prime(q), f"{bits} bít: p = {p} không phải số nguyên tố an toàn")
    for bits in (16, 64, 512):
        n = gen_prime(bits)
        check(n.bit_length() == bits and is_probable_prime(n), f"gen_prime({bits}) sai")
    return "40 số nguyên tố an toàn từ 3 đến 256 bít và 3 số nguyên tố ngẫu nhiên đều đúng"


def main():
    ui.title("BỘ KIỂM THỬ DIFFIE–HELLMAN")
    report = []
    passed = failed = skipped = 0
    for code, kind, desc, fn in TESTS:
        t0 = time.perf_counter()
        try:
            detail = fn() or ""
            status = "ĐẠT"
            passed += 1
        except Skip as exc:
            status, detail = "BỎ QUA", str(exc)
            skipped += 1
        except Exception as exc:
            status, detail = "KHÔNG ĐẠT", f"{type(exc).__name__}: {exc}"
            failed += 1
        dt = time.perf_counter() - t0
        colour = {"ĐẠT": ("green", "bold"), "BỎ QUA": ("yellow",), "KHÔNG ĐẠT": ("red", "bold")}[status]
        print(f"  {code}  {ui.c(f'{status:<9}', *colour)} {dt:6.2f}s  [{kind}] {desc}")
        print(ui.c(f"                              → {detail}", "gray"))
        report.append(f"{code}\t{status}\t{dt:.2f}s\t{kind}\t{desc}\t{detail}")
    print()
    summary = f"Tổng {len(TESTS)} ca: đạt {passed}, không đạt {failed}, bỏ qua {skipped}"
    (ui.ok if failed == 0 else ui.fail)(summary)

    os.makedirs(os.path.join(ROOT, "output"), exist_ok=True)
    with open(os.path.join(ROOT, "output", "test_report.txt"), "w", encoding="utf-8") as f:
        f.write("Mã\tKết quả\tThời gian\tLoại\tNội dung\tChi tiết\n")
        f.write("\n".join(report) + "\n" + summary + "\n")
    ui.note("Đã lưu output/test_report.txt")
    return failed == 0


if __name__ == "__main__":
    sys.exit(0 if main() else 1)
