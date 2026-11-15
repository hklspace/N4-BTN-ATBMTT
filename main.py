"""Chương trình demo trao đổi khoá Diffie–Hellman.

    python main.py            mở menu
    python main.py small      chạy thẳng một chức năng (xem README.md)
    python main.py test       chạy bộ kiểm thử
"""
import argparse
import os
import sys

from app import demos, ui
from app.ui import c

MENU = [
    ("Ví dụ số nhỏ, hiển thị từng bước tính", lambda: demos.demo_small()),
    ("Trao đổi khoá 2048 bít, mã hoá và giải mã tệp", lambda: demos.demo_exchange()),
    ("Tấn công người đứng giữa và cách phòng chống", lambda: demos.demo_mitm()),
    ("Thử giải logarit rời rạc và kiểm tra khoá công khai giả", lambda: demos.demo_attack()),
    ("Đo thời gian chạy", lambda: demos.demo_benchmark()),
    ("Sinh tham số mới (số nguyên tố an toàn p, căn nguyên thuỷ g)", lambda: demos.demo_params()),
    ("Chạy bộ kiểm thử", lambda: _run_tests()),
]


def _run_tests():
    from tests.run_tests import main as run_all
    return run_all()


def interactive_menu():
    while True:
        ui.title("TRAO ĐỔI KHOÁ DIFFIE–HELLMAN – Nhóm 4")
        for i, (label, _) in enumerate(MENU, 1):
            print(f"    {c(str(i), 'cyan', 'bold')}. {label}")
        print(f"    {c('0', 'cyan', 'bold')}. Thoát")
        choice = ui.ask("Chọn chức năng", 1)
        if choice in ("0", "q", "exit"):
            break
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            try:
                MENU[int(choice) - 1][1]()
            except KeyboardInterrupt:
                print()
                ui.note("Đã dừng chức năng, quay lại menu.")
            except Exception as exc:          # lỗi ở một chức năng thì quay lại menu, không thoát
                ui.fail(f"Lỗi: {exc}")
            ui.pause("Nhấn Enter để quay lại menu…")
        else:
            ui.fail("Lựa chọn không hợp lệ.")


def main(argv=None):
    p = argparse.ArgumentParser(description="Demo trao đổi khoá Diffie–Hellman")
    p.add_argument("command", nargs="?", default="menu",
                   choices=["menu", "small", "exchange", "mitm", "attack", "bench", "params", "test"])
    p.add_argument("--preset", type=int, choices=[1, 2, 3],
                   help="small: 1 là ví dụ p = 353, 2 là ví dụ p = 23, 3 là tự nhập")
    p.add_argument("--lsb", action="store_true",
                   help="small: in bảng bình phương và nhân duyệt bít từ thấp lên cao; mặc định: từ cao xuống thấp")
    p.add_argument("--small", action="store_true",
                   help="mitm: chạy ví dụ tính tay p = 23, g = 5, a = 6, b = 15, m = 3")
    p.add_argument("--file", help="exchange: đường dẫn tệp cần mã hoá")
    p.add_argument("--message", help="small, exchange: tin nhắn cần mã hoá")
    p.add_argument("--bits", type=int, help="params: số bít của p")
    p.add_argument("--no-pause", action="store_true", help="không dừng chờ Enter giữa các bước")
    p.add_argument("--no-color", action="store_true", help="tắt màu")
    args = p.parse_args(argv)
    ui.set_options(color=False if args.no_color else None, pause=not args.no_pause)

    if args.command == "menu":
        interactive_menu()
    elif args.command == "small":
        demos.demo_small(args.preset, msb=not args.lsb, message=args.message)
    elif args.command == "exchange":
        if args.message:
            demos.demo_exchange(demos.G.DEFAULT_GROUP, args.message.encode("utf-8"), "message.txt", show_text=True)
        elif args.file:
            with open(args.file, "rb") as f:
                data = f.read()
            demos.demo_exchange(demos.G.DEFAULT_GROUP, data, os.path.basename(args.file))
        else:
            demos.demo_exchange()
    elif args.command == "mitm":
        demos.demo_mitm(interactive=not args.no_pause, small=args.small or None)
    elif args.command == "attack":
        demos.demo_attack()
    elif args.command == "bench":
        demos.demo_benchmark()
    elif args.command == "params":
        demos.demo_params(args.bits)
    elif args.command == "test":
        return 0 if _run_tests() else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
