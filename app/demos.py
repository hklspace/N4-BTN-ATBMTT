"""Các chức năng trong menu. Mọi phép tính mật mã đều gọi sang dhcrypto/."""
import csv
import math
import os
import time

from dhcrypto import groups as G
from dhcrypto.attacks import brute_force_dlog, bsgs_dlog, make_dlp_instance
from dhcrypto.dh import (InvalidPublicKey, compute_shared_secret, generate_keypair,
                         generate_private_key, in_subgroup, shared_secret_bytes, validate_public_key)
from dhcrypto.file_cipher import decrypt_bytes, encrypt_bytes, parse_blob
from dhcrypto.kdf import derive_session_keys
from dhcrypto.modmath import mod_pow, mod_pow_basic, mod_pow_trace, mod_pow_trace_msb, mod_pow_window
from dhcrypto.primes import gen_safe_prime, is_probable_prime
from dhcrypto.primitive_root import check_primitive_root, find_primitive_root, power_table, prime_factors
from dhcrypto.protocol import run_session
from dhcrypto.rsa_sign import decrypt_int, encrypt_int, generate_rsa_keypair
from dhcrypto.sha256 import sha256_hex

from . import ui
from .ui import c

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(ROOT, "data")
OUT_DIR = os.path.join(ROOT, "output")


def _out(name):
    os.makedirs(OUT_DIR, exist_ok=True)
    return os.path.join(OUT_DIR, name)


def _write_csv(name, header, rows):
    with open(_out(name), "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def _show_message_roundtrip(plain: bytes, blob: bytes, back: bytes):
    """In bản rõ, toàn bộ bản mã (hex) và bản giải mã của một tin nhắn ngắn."""
    _, _, nonce, ct, tag = parse_blob(blob)
    ui.info(f"Bản rõ      : {plain.decode('utf-8', errors='replace')}")
    ui.info(f"Nonce (hex) : {nonce.hex()}")
    hexed = ct.hex()
    for i in range(0, len(hexed), 64):
        ui.info(("Bản mã (hex): " if i == 0 else " " * 14) + hexed[i:i + 64])
    ui.info(f"Tag HMAC    : {tag.hex()}")
    ui.info(f"Bản giải mã : {back.decode('utf-8', errors='replace')}")
    if back == plain:
        ui.ok("Bản giải mã trùng khớp bản rõ ban đầu")
    else:
        ui.fail("Bản giải mã khác bản rõ!")


# ---------------------------------------------------------------------------
# 1. Ví dụ số nhỏ, in từng bước
# ---------------------------------------------------------------------------
def _print_trace(base, exp, mod, label, msb=True):
    """In bảng bình phương và nhân cho base^exp mod mod, trả về kết quả."""
    if msb:
        result, steps = mod_pow_trace_msb(base, exp, mod)
        ui.info(f"{label}: tính {base}^{exp} mod {mod}  (số mũ {exp} = {bin(exp)[2:]}, duyệt bít từ cao xuống thấp)")
        ui.table(["bít"] + [str(s["bit"]) for s in steps],
                 [[f"r² mod {mod}"] + [str(s["square"]) for s in steps],
                  ["r sau bước"] + [str(s["result"]) for s in steps]])
        ui.note(f"Mỗi bước: r = r² mod {mod}, nếu bít bằng 1 thì r = r · {base} mod {mod}.")
        ui.info(f"⇒ {base}^{exp} mod {mod} = {c(result, 'bold')}")
        return result

    result, steps = mod_pow_trace(base, exp, mod)
    ui.info(f"{label}: tính {base}^{exp} mod {mod}  (số mũ {exp} = {bin(exp)[2:]}, duyệt bít từ thấp lên cao)")
    rows = [[s["i"], s["bit"], f"{base}^{2 ** s['i']} ≡ {s['power']}",
             "nhân vào" if s["used"] else "bỏ qua", s["result"]] for s in steps]
    ui.table(["i", "bít", f"{base}^(2^i) mod {mod}", "thao tác", "kết quả"], rows,
             [">", ">", "<", "<", ">"])
    used = [f"{base}^{2 ** s['i']}" for s in steps if s["used"]]
    ui.info(f"⇒ {base}^{exp} = " + " · ".join(used) + f" ≡ {c(result, 'bold')} (mod {mod})")
    return result


def _ask_small_params():
    while True:
        p = ui.ask_int("Nhập số nguyên tố p (nên dưới 100000 để in từng bước)", 353, 5)
        if is_probable_prime(p):
            break
        ui.fail(f"{p} không phải số nguyên tố.")
    while True:
        g = ui.ask_int("Nhập g", find_primitive_root(p), 2, p - 1)
        if check_primitive_root(g, p)[0]:
            break
        ui.fail(f"{g} không phải căn nguyên thuỷ modulo {p}. Căn nguyên thuỷ nhỏ nhất là {find_primitive_root(p)}.")
    a = ui.ask_int("Nhập khoá riêng a", None, 2, p - 2)
    b = ui.ask_int("Nhập khoá riêng b", None, 2, p - 2)
    return G.DHGroup("Tham số tự nhập", p, g, sample_a=a, sample_b=b)


def demo_small(preset: int = None, msb: bool = None, message: str = None):
    ui.title("1. VÍ DỤ SỐ NHỎ, CHẠY TỪNG BƯỚC")
    if msb is None and preset is None:
        msb = ui.choose("Cách trình bày thuật toán bình phương và nhân", [
            "Duyệt bít từ cao xuống thấp",
            "Duyệt bít từ thấp lên cao (bảng g^(2^i))",
        ], 1) == 1
    msb = True if msb is None else msb
    if preset is None:
        preset = ui.choose("Chọn bộ số", [
            "p = 353, g = 3, a = 97, b = 233",
            "p = 23, g = 5, a = 6, b = 15",
            "Tự nhập p, g, a, b",
        ])
    grp = {1: G.EXAMPLE_353, 2: G.EXAMPLE_23}.get(preset) or _ask_small_params()
    p, g, a, b = grp.p, grp.g, grp.sample_a, grp.sample_b

    ui.section("Bước 1. Thống nhất tham số công khai p và g")
    ui.info(f"p = {p}, kiểm tra Miller–Rabin: "
            + (c("số nguyên tố", "green") if is_probable_prime(p) else c("hợp số", "red")))
    factors = prime_factors(p - 1)
    ui.info(f"p − 1 = {p - 1}, các ước nguyên tố: {', '.join(map(str, factors))}")
    is_root, steps = check_primitive_root(g, p, factors)
    ui.info(f"g = {g} là căn nguyên thuỷ khi g^((p−1)/r) ≠ 1 với mọi ước nguyên tố r của p − 1:")
    ui.table(["r", "(p−1)/r", f"{g}^((p−1)/r) mod {p}", "kết luận"],
             [[r, e, v, "≠ 1 ✔" if v != 1 else "= 1 ✘"] for r, e, v in steps], [">", ">", ">", "<"])
    (ui.ok if is_root else ui.fail)(f"g = {g} {'là' if is_root else 'không phải'} căn nguyên thuỷ modulo {p}")
    if p <= 60:
        tbl = power_table(g, p)
        ui.info(f"Bảng {g}^k mod {p}, đi qua đủ các số 1..{p - 1}:")
        ui.table(["k"] + [str(k) for k, _ in tbl], [[f"{g}^k"] + [str(v) for _, v in tbl]])
    ui.pause()

    ui.section("Bước 2. Alice chọn khoá riêng a, tính A = g^a mod p")
    ui.info(f"{ui.actor('Alice')} chọn a = {c(a, 'bold')}")
    A = _print_trace(g, a, p, "A", msb)
    ui.pause()
    ui.section("Bước 3. Bob chọn khoá riêng b, tính B = g^b mod p")
    ui.info(f"{ui.actor('Bob')} chọn b = {c(b, 'bold')}")
    B = _print_trace(g, b, p, "B", msb)
    ui.pause()

    ui.section("Bước 4. Trao đổi khoá công khai qua kênh không an toàn")
    ui.info(f"{ui.actor('Alice')} ──── A = {A} ───▶ {ui.actor('Bob')}")
    ui.info(f"{ui.actor('Alice')} ◀─── B = {B} ──── {ui.actor('Bob')}")
    ui.info(f"{ui.actor('Eve')} nghe lén được p = {p}, g = {g}, A = {A}, B = {B}, nhưng không biết a và b")
    ui.pause()

    ui.section("Bước 5. Mỗi bên tự tính bí mật chung K")
    ka = _print_trace(B, a, p, f"{ui.actor('Alice')} K = B^a mod p", msb)
    print()
    kb = _print_trace(A, b, p, f"{ui.actor('Bob')} K = A^b mod p", msb)
    direct = mod_pow(g, a * b, p)
    ui.info(f"Kiểm tra lại: g^(ab) mod p = {g}^{a * b} mod {p} = {direct}")
    (ui.ok if ka == kb == direct else ui.fail)(
        f"Alice và Bob có cùng K = {c(ka, 'bold', 'green')}" if ka == kb else "Hai bên ra hai giá trị khác nhau!")
    ui.pause()

    ui.section("Bước 6. Eve thử tìm a bằng cách vét cạn logarit rời rạc")
    t0 = time.perf_counter()
    x, n_steps = brute_force_dlog(g, A, p)
    dt = time.perf_counter() - t0
    ui.info(f"{ui.actor('Eve')} thử x = 1, 2, 3, … đến khi {g}^x ≡ {A} (mod {p}): "
            f"tìm được x = {x} sau {n_steps} lần thử ({dt * 1000:.2f} ms)")
    ui.info(f"{ui.actor('Eve')} tính được K = B^x mod p = {mod_pow(B, x, p)}")
    ui.note(f"p chỉ dài {p.bit_length()} bít nên phá ngay. Với nhóm 2048 bít thì cách này không làm được.")

    ui.pause()

    ui.section("Bước 7. Dùng K để mã hoá một tin nhắn rồi giải mã lại")
    if message is None:
        message = "Hẹn gặp nhau lúc 9 giờ sáng mai."
        if ui.PAUSE:
            message = ui.ask("Nhập tin nhắn Alice gửi Bob", message)
    k_enc, k_mac = derive_session_keys(shared_secret_bytes(grp, ka))
    ui.info(f"K = {ka} được đưa qua HKDF-SHA256 để sinh khoá mã hoá và khoá MAC 256 bít.")
    plain = message.encode("utf-8")
    blob = encrypt_bytes(k_enc, k_mac, plain, "message.txt")
    _, back = decrypt_bytes(*derive_session_keys(shared_secret_bytes(grp, kb)), blob)
    _show_message_roundtrip(plain, blob, back)
    ui.note("Với p nhỏ, kẻ tấn công có thể thử các giá trị K.")

    ui.section("Tổng kết")
    ui.table(["Đại lượng", "Giá trị", "Ai biết"], [
        ["p, g", f"{p}, {g}", "Công khai"],
        ["a", a, "Chỉ Alice"],
        ["b", b, "Chỉ Bob"],
        ["A = g^a mod p", A, "Công khai"],
        ["B = g^b mod p", B, "Công khai"],
        ["K", ka, "Alice và Bob"],
    ])
    return {"p": p, "g": g, "a": a, "b": b, "A": A, "B": B, "K": ka}


# ---------------------------------------------------------------------------
# In sự kiện của một phiên trao đổi khoá
# ---------------------------------------------------------------------------
def print_event(e):
    style = {"secret": ("dim",), "attack": ("red",), "ok": ("green",), "fail": ("red", "bold"),
             "send": ("bold",)}.get(e.kind, ())
    mark = {"ok": "✔ ", "fail": "✘ ", "attack": "! "}.get(e.kind, "")
    print(f"  {ui.actor(e.actor):<20} {c(mark + e.text, *style)}")
    d = e.data
    pad = " " * 13
    if "x" in d:
        print(pad + c(f"khoá riêng = {ui.short_int(d['x'])}", "dim"))
    if "y" in d:
        print(pad + f"khoá công khai = {ui.short_int(d['y'])}")
    if "k" in d:
        print(pad + f"K = {ui.short_int(d['k'])}   mã xác nhận: {c(d.get('sas', ''), 'bold')}")
    if "k1" in d:
        print(pad + c(f"K_AM (với Alice) = {ui.short_int(d['k1'])}", "red"))
        print(pad + c(f"K_BM (với Bob)   = {ui.short_int(d['k2'])}", "red"))
    if "cipher_preview" in d:
        print(pad + f"bản mã (24 byte đầu, hex): {d['cipher_preview']}…  tổng {d['size']:,} byte")
    if "plain_preview" in d:
        raw = d["plain_preview"]
        txt = raw.decode("utf-8", errors="replace")
        if b"\x00" in raw or raw.startswith(b"\x89PNG"):
            txt = f"<dữ liệu nhị phân, bắt đầu bằng {raw[:8].hex()}>"
        print(pad + c(f"Mallory đọc được: \"{txt}\"", "red", "bold"))


def _choose_group(default=4):
    labels = [f"{g.name:<16} ({g.source})" for g in G.RFC_GROUPS]
    labels.append("p = 353 (số nhỏ, chỉ để minh hoạ)")
    i = ui.choose("Chọn nhóm tham số", labels, default)
    return G.RFC_GROUPS[i - 1] if i <= len(G.RFC_GROUPS) else G.EXAMPLE_353


def _choose_data():
    i = ui.choose("Chọn dữ liệu cần gửi", [
        "Ảnh mẫu data/sample.png",
        "Văn bản mẫu data/sample.txt",
        "Nhập đường dẫn một tệp bất kỳ",
        "Gõ một tin nhắn",
    ], 1)
    if i == 4:
        text = ui.ask("Tin nhắn", "Xin chào Bob, đây là tin nhắn bí mật của Alice.")
        return text.encode("utf-8"), "message.txt"
    if i == 3:
        path = ui.ask("Đường dẫn tệp").strip('"')
    else:
        path = os.path.join(DATA_DIR, "sample.png" if i == 1 else "sample.txt")
    with open(path, "rb") as f:
        return f.read(), os.path.basename(path)


# ---------------------------------------------------------------------------
# 2. Trao đổi khoá 2048 bít, mã hoá và giải mã tệp
# ---------------------------------------------------------------------------
def demo_exchange(group=None, data=None, filename=None, show_text=False):
    ui.title("2. TRAO ĐỔI KHOÁ, MÃ HOÁ VÀ GIẢI MÃ TỆP")
    group = group or _choose_group()
    if data is None:
        data, filename = _choose_data()
        show_text = filename == "message.txt"

    ui.section("Phiên trao đổi khoá và truyền dữ liệu")
    t0 = time.perf_counter()
    res = run_session(group, data, filename, emit=print_event)
    dt = time.perf_counter() - t0
    if not res.ok:
        ui.fail(res.error)
        return res

    enc_path = _out(filename + ".dhenc")
    dec_path = _out("decrypted_" + os.path.basename(res.received_name))
    with open(enc_path, "wb") as f:
        f.write(res.blob)
    with open(dec_path, "wb") as f:
        f.write(res.received)

    if show_text:
        ui.section("Bản rõ, bản mã và bản giải mã")
        _show_message_roundtrip(data, res.blob, res.received)

    ui.section("Kiểm tra kết quả")
    h1, h2 = sha256_hex(data), sha256_hex(res.received)
    ui.table(["", "Giá trị"], [
        ["K của Alice bằng K của Bob", "Đúng" if res.alice.shared == res.bob.shared else "Sai"],
        ["Mã xác nhận Alice / Bob", f"{res.alice.sas} / {res.bob.sas}"],
        ["Tệp đã mã hoá", os.path.relpath(enc_path, ROOT)],
        ["Tệp Bob giải mã ra", os.path.relpath(dec_path, ROOT)],
        ["SHA-256 tệp gốc", h1[:32] + "…"],
        ["SHA-256 tệp giải mã", h2[:32] + "…"],
        ["Tổng thời gian", f"{dt:.3f} giây"],
    ])
    if h1 == h2:
        ui.ok("Giải mã ra đúng tệp ban đầu")
    else:
        ui.fail("Tệp giải mã khác tệp gốc!")
    ui.note("Mở thử tệp .dhenc bằng trình xem ảnh hay văn bản sẽ không đọc được vì đã bị mã hoá.")
    return res


# ---------------------------------------------------------------------------
# 3. Tấn công người đứng giữa và cách chống
# ---------------------------------------------------------------------------
DEFAULT_TRANSFER = "Bob ơi, chuyển giúp mình 5.000.000đ vào tài khoản 0123456789 nhé. Alice"


def _tamper(plain: bytes) -> bytes:
    return plain.replace(b"0123456789", b"9876543210")


def demo_mitm(group=None, message=None, interactive=True, small=None):
    ui.title("3. TẤN CÔNG NGƯỜI ĐỨNG GIỮA VÀ CÁCH PHÒNG CHỐNG")
    if small is None and group is None and interactive:
        small = ui.choose("Chọn bộ tham số", [
            "Nhóm MODP 2048 bít, khoá ngẫu nhiên",
            "Ví dụ tính tay: p = 23, g = 5, a = 6, b = 15, Mallory chọn m = 3",
        ], 1) == 2
    keys = {}
    if small:
        group = G.EXAMPLE_23
        keys = {"a": 6, "b": 15, "m": 3}
    group = group or G.MODP_2048
    message = (message or DEFAULT_TRANSFER).encode("utf-8")

    ui.section("Phần A. Diffie–Hellman không xác thực, Mallory chen vào giữa")
    res = run_session(group, message, "tin_nhan.txt", mitm=True, auth=False,
                      tamper=_tamper, emit=print_event, **keys)
    if small:
        print()
        ui.table(["Trường hợp", "Bí mật chung", "Ai biết"], [
            ["Trao đổi bình thường", f"K = 5^(6·15) mod 23 = {mod_pow(5, 90, 23)}", "Alice và Bob"],
            ["Alice với Mallory", f"K_AM = {res.alice.shared}", "Alice và Mallory"],
            ["Bob với Mallory", f"K_BM = {res.bob.shared}", "Bob và Mallory"],
        ])
        ui.info(f"Mallory gửi M = 5^3 mod 23 = {res.mallory.kp.public} cho cả hai bên, khớp ví dụ tính tay.")
    print()
    ui.table(["", "Nội dung"], [
        ["Alice gửi", message.decode()],
        ["Mallory đọc được", res.mallory.stolen[0][2].decode()],
        ["Bob nhận được", res.received.decode()],
    ])
    ui.fail("Bob nhận tin đã bị sửa số tài khoản mà không biết, vì HMAC vẫn đúng (Mallory có khoá của K_BM).")
    ui.info("Cách phát hiện thủ công: hai bên gọi điện đọc mã xác nhận (băm của K) cho nhau:")
    ui.table(["Bên", "Mã xác nhận"], [["Alice (từ K_AM)", res.alice.sas], ["Bob (từ K_BM)", res.bob.sas]])
    ui.fail("Hai mã khác nhau, chứng tỏ có người đứng giữa.")
    if interactive:
        ui.pause()

    ui.section("Phần B. Có xác thực: mỗi bên ký RSA lên khoá công khai của mình")
    res2 = run_session(group, message, "tin_nhan.txt", mitm=True, auth=True,
                       tamper=_tamper, emit=print_event, **keys)
    if not res2.ok:
        ui.ok("Mallory không có khoá riêng RSA của Alice nên không ký được M, tấn công bị chặn.")
    if interactive:
        ui.pause()

    ui.section("Phần C. Có xác thực và không có Mallory (phiên bình thường)")
    honest = {k: v for k, v in keys.items() if k != "m"}
    res3 = run_session(group, message, "tin_nhan.txt", auth=True, emit=print_event, **honest)
    if res3.ok:
        ui.ok(f"Bob nhận đúng: \"{res3.received.decode()}\"")
    return res, res2, res3


# ---------------------------------------------------------------------------
# 4. Giải logarit rời rạc và khoá công khai giả
# ---------------------------------------------------------------------------
def demo_attack(bit_list=(16, 20, 24, 28, 32, 36, 40), brute_limit_bits=24):
    ui.title("4. THỬ PHÁ DIFFIE–HELLMAN: GIẢI LOGARIT RỜI RẠC")
    ui.info("Mỗi dòng là một bài toán: p là số nguyên tố an toàn n bít, g là căn nguyên thuỷ, y = g^x mod p. Tìm x.")
    rows, csv_rows = [], []
    for bits in bit_list:
        p, g, x, y = make_dlp_instance(bits)
        tb = None
        brute = "bỏ qua (quá lâu)"
        if bits <= brute_limit_bits:
            t0 = time.perf_counter()
            _, nb = brute_force_dlog(g, y, p)
            tb = time.perf_counter() - t0
            brute = f"{nb:,} bước / {tb:.3f}s"
        t0 = time.perf_counter()
        xs, ns = bsgs_dlog(g, y, p)
        ts = time.perf_counter() - t0
        ok = mod_pow(g, xs, p) == y
        rows.append([bits, p, x, xs, "✔" if ok else "✘", brute, f"{ns:,} bước / {ts:.3f}s"])
        csv_rows.append([bits, p, x, xs, "" if tb is None else tb, ts])
        print(f"    … xong {bits} bít", flush=True)
    ui.table(["bít", "p", "x bí mật", "x tìm được", "đúng?", "Vét cạn", "Baby-step Giant-step"],
             rows, [">", ">", ">", ">", "^", ">", ">"])

    # BSGS tốn khoảng 2^(n/2) bước, ngoại suy từ bài lớn nhất vừa giải
    bits0, ts0 = bit_list[-1], csv_rows[-1][-1]
    per_step = ts0 / 2 ** (bits0 / 2)
    ui.section("Ngoại suy thời gian Baby-step Giant-step cho p lớn")
    est = []
    for n in (64, 128, 256, 1024, 2048):
        log_sec = math.log10(per_step) + (n / 2) * math.log10(2)
        log_year = log_sec - math.log10(3600 * 24 * 365)
        when = f"≈ 10^{log_year:.0f} năm" if log_year > 0 else f"≈ {10 ** log_sec:.1f} giây"
        est.append([n, f"≈ 2^{n // 2} bước", when])
    ui.table(["bít của p", "số bước", "thời gian (máy này)"], est, [">", ">", ">"])
    ui.note("Sàng trường số nhanh hơn BSGS nhiều, nhưng nhóm 2048 bít vẫn có mức an toàn khoảng 112 bít")
    ui.note("theo NIST SP 800-57, tức cỡ 2^112 phép tính. Khoá riêng 256 bít thì Pollard kangaroo cần cỡ")
    ui.note("2^128 bước, vẫn trên mức 112 bít nên không làm yếu nhóm.")
    _write_csv("attack_times.csv", ["bits", "p", "x", "x_found", "brute_seconds", "bsgs_seconds"], csv_rows)
    ui.ok("Đã lưu số liệu vào output/attack_times.csv")

    ui.section("Khoá công khai giả (y = 0, 1, p − 1) và cách kiểm tra")
    grp = G.MODP_2048
    victim = generate_keypair(grp)
    rows = []
    for label, fake in [("y = 1", 1), ("y = p − 1", grp.p - 1), ("y = 0", 0)]:
        k = mod_pow(fake, victim.private, grp.p)
        try:
            validate_public_key(grp, fake)
            verdict = "chấp nhận"
        except InvalidPublicKey:
            verdict = c("từ chối", "green", "bold")
        rows.append([label, ui.short_int(k, 6), verdict])
    ui.table(["Khoá giả", "K nếu không kiểm tra", "Có kiểm tra"], rows)
    ui.note("Không kiểm tra thì K chỉ có thể là 0, 1 hoặc p − 1, kẻ tấn công đoán ngay được.")


# ---------------------------------------------------------------------------
# 5. Đo thời gian
# ---------------------------------------------------------------------------
def _avg_ms(fn, runs):
    t0 = time.perf_counter()
    for _ in range(runs):
        fn()
    return (time.perf_counter() - t0) / runs * 1000


def demo_benchmark(runs=5, sizes=(1_000, 10_000, 100_000, 500_000)):
    ui.title("5. ĐO THỜI GIAN CHẠY")

    ui.section(f"Trước và sau tối ưu (nhóm MODP 2048 bít, trung bình {runs} lần)")
    grp = G.MODP_2048
    p, g = grp.p, grp.g
    x_full = generate_private_key(grp, short=False)
    peer = generate_keypair(grp)
    rows = [
        ["Lũy thừa g^x, x dài ~2047 bít",
         _avg_ms(lambda: mod_pow_basic(g, x_full, p), runs),
         _avg_ms(lambda: mod_pow_window(g, x_full, p), runs),
         "bình phương và nhân → cửa sổ trượt"],
        ["Sinh cặp khoá",
         _avg_ms(lambda: mod_pow_basic(g, generate_private_key(grp, short=False), p), runs),
         _avg_ms(lambda: generate_keypair(grp), runs),
         "thêm khoá riêng 256 bít"],
        ["Kiểm tra khoá công khai nhận được",
         _avg_ms(lambda: mod_pow_basic(peer.public, grp.q, p), runs),
         _avg_ms(lambda: in_subgroup(grp, peer.public), runs),
         "y^q mod p → ký hiệu Legendre"],
    ]
    ui.table(["Thao tác", "trước (ms)", "sau (ms)", "nhanh hơn", "cách tối ưu"],
             [[r[0], f"{r[1]:.2f}", f"{r[2]:.2f}", f"{r[1] / r[2]:.1f} lần", r[3]] for r in rows],
             ["<", ">", ">", ">", "<"])
    _write_csv("benchmark_optimization.csv", ["operation", "before_ms", "after_ms", "method"], rows)

    ui.section(f"Thời gian theo độ dài p (khoá riêng 256 bít, trung bình {runs} lần)")
    rows, csv_rows = [], []
    for grp_i in (G.MODP_768, G.MODP_1024, G.MODP_1536, G.MODP_2048, G.MODP_3072):
        a, b = generate_keypair(grp_i), generate_keypair(grp_i)
        t_gen = _avg_ms(lambda: generate_keypair(grp_i), runs)
        t_k = _avg_ms(lambda: compute_shared_secret(grp_i, a.private, b.public), runs)
        # pow() có sẵn chỉ để so sánh tốc độ và kiểm tra kết quả
        t_pow = _avg_ms(lambda: pow(b.public, a.private, grp_i.p), runs)
        same = compute_shared_secret(grp_i, a.private, b.public) == pow(b.public, a.private, grp_i.p)
        rows.append([grp_i.bits, f"{t_gen:.2f}", f"{t_k:.2f}", f"{t_pow:.2f}", "✔" if same else "✘"])
        csv_rows.append([grp_i.bits, t_gen, t_k, t_pow])
        print(f"    … xong {grp_i.bits} bít", flush=True)
    ui.table(["bít của p", "sinh cặp khoá (ms)", "tính K và kiểm tra (ms)", "pow() có sẵn (ms)", "khớp"],
             rows, [">", ">", ">", ">", "^"])
    _write_csv("benchmark_dh.csv", ["bits", "keygen_ms", "shared_with_check_ms", "builtin_pow_ms"], csv_rows)

    ui.section("Diffie–Hellman và RSA ở cùng mức an toàn khoảng 112 bít (p, n dài 2048 bít)")
    rsa_runs = 3
    t0 = time.perf_counter()
    rsa_keys = [generate_rsa_keypair(2048) for _ in range(rsa_runs)]
    t_rsa_gen = (time.perf_counter() - t0) / rsa_runs * 1000
    rk = rsa_keys[0]
    secret = int.from_bytes(os.urandom(32), "big")
    ct = encrypt_int(rk.public, secret)
    assert decrypt_int(rk, ct) == secret
    t_rsa_enc = _avg_ms(lambda: encrypt_int(rk.public, secret), runs)
    t_rsa_dec = _avg_ms(lambda: decrypt_int(rk, ct), runs)
    a2, b2 = generate_keypair(grp), generate_keypair(grp)
    t_dh_gen = _avg_ms(lambda: generate_keypair(grp), runs)
    t_dh_k = _avg_ms(lambda: compute_shared_secret(grp, a2.private, b2.public), runs)
    ui.table(["Thao tác", "DH (MODP 2048, khoá riêng 256 bít)", "RSA-2048 vận chuyển khoá"], [
        ["Sinh khoá", f"{t_dh_gen:.2f} ms (khoá tạm, mỗi phiên)",
         f"{t_rsa_gen:.0f} ms (sinh 2 số nguyên tố 1024 bít, khoá dài hạn)"],
        ["Bên gửi", f"{t_dh_k:.2f} ms (tính K và kiểm tra)", f"{t_rsa_enc:.2f} ms (mã hoá, e = 65537)"],
        ["Bên nhận", f"{t_dh_k:.2f} ms (tính K và kiểm tra)", f"{t_rsa_dec:.2f} ms (giải mã, d 2048 bít, không CRT)"],
        ["Bảo mật chuyển tiếp", "Có (khoá tạm thời mỗi phiên)", "Không"],
    ])
    _write_csv("benchmark_dh_vs_rsa.csv", ["metric", "dh_ms", "rsa_ms"],
               [["keygen", t_dh_gen, t_rsa_gen], ["sender", t_dh_k, t_rsa_enc], ["receiver", t_dh_k, t_rsa_dec]])
    ui.note("Thư viện thật dùng CRT cho RSA (giải mã nhanh hơn khoảng 3 đến 4 lần) và viết bằng C cho cả hai.")

    ui.section("Mã hoá và giải mã dữ liệu theo kích thước (ChaCha20 và HMAC-SHA256)")
    k_enc, k_mac = derive_session_keys(b"benchmark-key")
    rows, csv_rows = [], []
    for n in sizes:
        data = os.urandom(n)
        t0 = time.perf_counter()
        blob = encrypt_bytes(k_enc, k_mac, data)
        t1 = time.perf_counter()
        _, back = decrypt_bytes(k_enc, k_mac, blob)
        t2 = time.perf_counter()
        assert back == data
        rows.append([f"{n:,}", f"{(t1 - t0) * 1000:.1f}", f"{(t2 - t1) * 1000:.1f}", f"{n / (t1 - t0) / 1e6:.2f}"])
        csv_rows.append([n, t1 - t0, t2 - t1])
    ui.table(["kích thước (byte)", "mã hoá (ms)", "giải mã (ms)", "tốc độ (MB/s)"], rows, [">"] * 4)
    _write_csv("benchmark_cipher.csv", ["bytes", "encrypt_seconds", "decrypt_seconds"], csv_rows)
    ui.ok("Đã lưu các tệp output/benchmark_*.csv")
    ui.note("Thời gian DH tăng nhanh theo độ dài p, còn mã hoá dữ liệu tăng tuyến tính theo kích thước.")
    ui.note("Phần mã hoá dữ liệu viết bằng Python thuần nên chậm hơn nhiều so với thư viện viết bằng C.")


# ---------------------------------------------------------------------------
# 6. Sinh tham số mới
# ---------------------------------------------------------------------------
def demo_params(bits=None):
    ui.title("6. SINH THAM SỐ MỚI: SỐ NGUYÊN TỐ AN TOÀN p VÀ CĂN NGUYÊN THUỶ g")
    if bits is None:
        bits = ui.ask_int("Số bít của p (16–1024; trên 512 bít có thể mất vài giây)", 64, 16, 1024)
    ui.info(f"Đang tìm số nguyên tố an toàn p = 2q + 1 dài {bits} bít (q cũng nguyên tố)…")
    count = {"n": 0}

    def progress(n):
        count["n"] = n
        if n % 200 == 0:
            print(".", end="", flush=True)

    t0 = time.perf_counter()
    p = gen_safe_prime(bits, progress)
    dt = time.perf_counter() - t0
    print()
    q = (p - 1) // 2
    ui.ok(f"Tìm được sau {count['n']:,} ứng viên, {dt:.2f} giây")
    ui.info(f"p = {p}")
    ui.info(f"q = (p − 1)/2 = {q}")
    g = find_primitive_root(p, [2, q])
    _, steps = check_primitive_root(g, p, [2, q])
    ui.info(f"p − 1 = 2q nên chỉ cần thử hai ước nguyên tố. Căn nguyên thuỷ nhỏ nhất g = {g}:")
    ui.table(["r", "g^((p−1)/r) mod p", "kết luận"],
             [[ui.short_int(r), ui.short_int(v), "≠ 1 ✔" if v != 1 else "= 1 ✘"] for r, _, v in steps])
    grp = G.DHGroup(f"Tự sinh {bits} bít", p, g)
    alice, bob = generate_keypair(grp), generate_keypair(grp)
    ka = compute_shared_secret(grp, alice.private, bob.public)
    kb = compute_shared_secret(grp, bob.private, alice.public)
    ui.info(f"Thử trao đổi khoá: K của Alice = {ui.short_int(ka)}")
    ui.info(f"                   K của Bob   = {ui.short_int(kb)}")
    (ui.ok if ka == kb else ui.fail)("Hai bên ra cùng K" if ka == kb else "Hai bên ra K khác nhau!")
    return grp
