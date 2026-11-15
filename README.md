# Trao đổi khoá Diffie–Hellman

Bài tập nhóm môn An toàn và bảo mật thông tin, Nhóm 4.

Chương trình cài đặt trao đổi khoá Diffie–Hellman (DH) bằng Python, phần thuật toán tự viết hoàn toàn, không dùng thư viện mật mã. Chương trình có thể:

- chạy từng bước trên bộ số nhỏ, in bảng tính giống hệt ví dụ tính tay trong báo cáo, rồi dùng khoá vừa tạo để mã hoá một tin nhắn;
- trao đổi khoá 2048 bít rồi dùng khoá đó mã hoá, giải mã tệp ảnh hoặc văn bản;
- minh hoạ tấn công người đứng giữa và cách chống bằng chữ ký số;
- thử phá DH bằng cách giải logarit rời rạc;
- đo thời gian chạy và chạy 22 ca kiểm thử.

Ký hiệu dùng giống báo cáo: **p** là số nguyên tố, **g** là phần tử sinh, **q** là cấp nhóm con, **a, b** là khoá riêng, **A = g^a mod p, B = g^b mod p** là khoá công khai, **K** là bí mật chung.

---

## 1. Chạy nhanh

```bash
cd dh-project
python main.py                 # mở menu
python main.py test            # chạy bộ kiểm thử, khoảng 10 giây
```

Không cần cài thêm gì. Trên macOS hoặc Linux, nếu lệnh `python` không chạy thì dùng `python3`.

## 2. Yêu cầu và cài đặt

| Thành phần | Yêu cầu |
|---|---|
| Python | 3.8 trở lên (đã chạy thử trên 3.11, 3.12, 3.13) |
| Thư viện bắt buộc | Không có. Chương trình chính chỉ dùng thư viện chuẩn của Python |
| Thư viện tuỳ chọn | `cryptography`, chỉ để bộ kiểm thử so kết quả |
| OpenSSL (tuỳ chọn) | Để bộ kiểm thử so tham số nhóm RFC |
| Terminal | Windows Terminal, terminal của VS Code, hoặc Terminal trên macOS/Linux để hiện màu và tiếng Việt |

Muốn chạy đủ cả phần so kết quả với thư viện chuẩn thì cài thêm:

```bash
pip install -r requirements.txt
```

Không cài thì ca TC16 hiện "bỏ qua", các ca khác vẫn chạy bình thường.

## 3. Cách chạy

### 3.1. Menu

```bash
python main.py
```

```
1. Ví dụ số nhỏ, in từng bước như tính tay
2. Trao đổi khoá 2048 bít, mã hoá và giải mã tệp
3. Tấn công người đứng giữa và cách phòng chống
4. Thử phá DH: giải logarit rời rạc, khoá công khai giả
5. Đo thời gian chạy
6. Sinh tham số mới (số nguyên tố an toàn p, căn nguyên thuỷ g)
7. Chạy bộ kiểm thử
0. Thoát
```

Giữa các bước chương trình dừng chờ Enter để người trình bày kịp giải thích.

### 3.2. Chạy thẳng một chức năng

| Lệnh | Chức năng |
|---|---|
| `python main.py small --preset 1` | p = 353, g = 3, a = 97, b = 233 → A = 40, B = 248, K = 160 |
| `python main.py small --preset 2` | p = 23, g = 5, a = 6, b = 15 → A = 8, B = 19, K = 2 |
| `python main.py small --preset 3` | Tự nhập p, g, a, b |
| `python main.py small --preset 2 --lsb` | In bảng bình phương và nhân duyệt bít từ thấp lên cao (mặc định từ cao xuống thấp) |
| `python main.py exchange` | Trao đổi khoá rồi chọn tệp để mã hoá |
| `python main.py exchange --file data/sample.png` | Mã hoá và giải mã thẳng một tệp với nhóm MODP 2048 bít |
| `python main.py exchange --message "Xin chào Bob"` | Mã hoá một tin nhắn, in bản rõ, toàn bộ bản mã và bản giải mã |
| `python main.py mitm` | Người đứng giữa: không xác thực (phần A), có xác thực (B), phiên bình thường (C) |
| `python main.py mitm --small` | Như trên với ví dụ tính tay p = 23, g = 5, a = 6, b = 15, m = 3 → M = 10, K_AM = 6, K_BM = 5 |
| `python main.py attack` | Giải logarit rời rạc từ 16 đến 40 bít, ngoại suy lên 2048 bít, thử khoá công khai giả |
| `python main.py bench` | Đo thời gian: trước và sau tối ưu, theo độ dài p, so với RSA-2048, mã hoá theo kích thước dữ liệu |
| `python main.py params --bits 512` | Sinh số nguyên tố an toàn p và căn nguyên thuỷ g mới |
| `python main.py test` | Chạy 22 ca kiểm thử |

Tuỳ chọn dùng được với mọi lệnh: `--no-pause` (không dừng chờ Enter, tiện khi quay video) và `--no-color` (tắt màu).

### 3.3. Tệp kết quả trong thư mục `output/`

| Tệp | Nội dung |
|---|---|
| `sample.png.dhenc` | Ảnh sau khi mã hoá, không mở xem được |
| `decrypted_sample.png` | Ảnh Bob giải mã ra, giống hệt ảnh gốc |
| `test_report.txt` | Kết quả bộ kiểm thử |
| `attack_times.csv` | Thời gian giải logarit rời rạc theo số bít |
| `benchmark_*.csv` | Số liệu đo thời gian |

## 4. Kịch bản demo

| # | Kịch bản | Lệnh | Kết quả đúng |
|---|---|---|---|
| 1 | Thuật toán chạy đúng trên số nhỏ | `python main.py small --preset 1` | A = 40, B = 248, K = 160, bảng từng bước khớp tính tay |
| 2 | Nhập bản rõ, xem bản mã, giải mã lại | `python main.py exchange --message "Xin chào Bob"` | In toàn bộ bản mã, bản giải mã trùng tin nhắn đã nhập |
| 3 | Trao đổi khoá thật và mã hoá tệp | `python main.py exchange --file data/sample.png` | Hai bên cùng K, SHA-256 ảnh giải mã trùng ảnh gốc |
| 4 | Người đứng giữa khi không xác thực | `python main.py mitm --small` (phần A) | Mallory sửa số tài khoản, Bob không biết, mã xác nhận hai bên khác nhau |
| 5 | Người đứng giữa khi có chữ ký RSA | `python main.py mitm --small` (phần B) | Phiên bị huỷ, Mallory không đọc được gì |
| 6 | Khoá công khai giả, dữ liệu bị sửa | `python main.py attack` (phần cuối), TC05, TC08 | Khoá giả bị từ chối, HMAC báo lỗi |
| 7 | Phá DH khi tham số nhỏ | `python main.py attack` | Giải được khi p 16–40 bít, thời gian tăng theo hàm mũ |

## 5. Giới hạn

- DH không tự xác thực hai bên, nên luôn bị tấn công người đứng giữa nếu thiếu chữ ký hoặc mã xác nhận (kịch bản 4). Đây là giới hạn của thuật toán, không phải lỗi chương trình.
- Bộ số nhỏ (p = 23, p = 353) phá được ngay, chỉ dùng để minh hoạ. Nhóm 768 và 1024 bít có trong chương trình để đo thời gian nhưng không còn an toàn.
- Vét cạn chỉ chạy tới khoảng 24 bít, Baby-step Giant-step tới khoảng 40 bít. Với 2048 bít thì không giải được, đó chính là độ khó của bài toán.
- Số nguyên của Python không có thời gian chạy cố định, nên chương trình không chống được tấn công kênh kề đo thời gian.
- Phần mã hoá dữ liệu viết bằng Python thuần, tốc độ khoảng vài trăm KB/s, chậm hơn nhiều so với thư viện viết bằng C. Tệp vài MB vẫn chạy được nhưng mất vài giây.
- Chữ ký RSA dùng cách đệm rút gọn để minh hoạ, chưa phải RSA-PSS.

## 6. Cấu trúc thư mục

Phần thuật toán (`dhcrypto/`) tách riêng khỏi phần giao diện (`app/`, `main.py`).

```
dh-project/
├── main.py                  menu và tham số dòng lệnh
├── dhcrypto/                phần thuật toán, tự viết
│   ├── modmath.py           bình phương và nhân, cửa sổ trượt, Euclid mở rộng, Jacobi
│   ├── primes.py            Miller–Rabin, sinh số nguyên tố, số nguyên tố an toàn
│   ├── primitive_root.py    kiểm tra và tìm căn nguyên thuỷ g
│   ├── groups.py            bộ số nhỏ và các nhóm chuẩn RFC 2409/3526/7919
│   ├── dh.py                sinh khoá, kiểm tra khoá công khai, tính K
│   ├── sha256.py            SHA-256 (FIPS 180-4)
│   ├── kdf.py               HMAC-SHA256 và HKDF, biến K thành khoá mã hoá và khoá MAC
│   ├── chacha20.py          mã dòng ChaCha20 (RFC 8439)
│   ├── file_cipher.py       mã hoá và giải mã tệp (ChaCha20 và HMAC)
│   ├── rsa_sign.py          chữ ký RSA để xác thực khoá công khai DH
│   ├── attacks.py           vét cạn và Baby-step Giant-step
│   └── protocol.py          mô phỏng phiên Alice, Bob, Mallory
├── app/                     phần giao diện
│   ├── ui.py                màu, bảng, nhập liệu
│   └── demos.py             các chức năng trong menu
├── tests/
│   └── run_tests.py         22 ca kiểm thử
├── data/                    sample.png, sample.txt để thử mã hoá
└── tools/
    ├── derive_rfc_groups.py tính lại các số nguyên tố RFC từ công thức (cần mpmath)
    └── make_sample_image.py tạo ảnh mẫu data/sample.png
```

## 7. Luồng xử lý

```
Tham số công khai p, g
   Alice: chọn a, A = g^a mod p  ──── A ───▶  Bob
   Bob:   chọn b, B = g^b mod p  ◀─── B ────  Alice
   Kiểm tra khoá nhận được: 1 < y < p − 1 và y thuộc nhóm con cấp q
   Alice: K = B^a mod p          Bob: K = A^b mod p          (hai bên ra cùng K)
   K ──HKDF-SHA256──▶ khoá mã hoá 256 bít và khoá MAC 256 bít
   Alice: bản mã = ChaCha20(tệp), tag = HMAC(bản mã) ──▶ Bob kiểm tra tag rồi giải mã
```

Khi bật xác thực, mỗi bên có cặp khoá RSA dài hạn và biết trước khoá công khai RSA của bên kia, giống chứng chỉ trong TLS. Mỗi bên ký lên khoá công khai DH của mình trước khi gửi. Mallory không có khoá riêng RSA của Alice nên không ký được giá trị giả và bị phát hiện.

## 8. Phần tự viết và phần dùng thư viện

| Thành phần | Tự viết | Thư viện dùng và lý do |
|---|---|---|
| Lũy thừa modulo, Miller–Rabin, sinh số nguyên tố, căn nguyên thuỷ, DH | ✔ | |
| SHA-256, HMAC, HKDF, ChaCha20, chữ ký RSA | ✔ | |
| Số ngẫu nhiên | | `secrets` của thư viện chuẩn, lấy số ngẫu nhiên an toàn từ hệ điều hành |
| So kết quả trong bộ kiểm thử | | `pow`, `hashlib`, `hmac`, `cryptography`, OpenSSL |
| Hằng số nhóm RFC | ✔ tính lại từ công thức trong RFC | `mpmath`, chỉ dùng trong `tools/` để tính π và e đủ chính xác |

## 9. Bộ kiểm thử

| Mã | Loại | Nội dung |
|---|---|---|
| TC01–TC02 | Tự viết | Ví dụ tính tay (353, 3, 97, 233) → K = 160 và (23, 5, 6, 15) → K = 2, so từng ô bảng tính |
| TC03–TC04 | Tự viết | K_A = K_B trên 300 bộ số nhỏ và 105 cặp khoá 2048 bít |
| TC05 | Tự viết | Từ chối khoá công khai xấu: 0, 1, p − 1, ≥ p, ngoài nhóm con |
| TC06 | Tự viết | Tiêu chuẩn căn nguyên thuỷ khớp định nghĩa |
| TC07–TC08 | Tự viết | Mã hoá và giải mã tệp đúng; phát hiện dữ liệu bị sửa hoặc sai khoá |
| TC09–TC11 | Tự viết | Chữ ký RSA; người đứng giữa thành công khi không xác thực, bị chặn khi có xác thực |
| TC12 | Tự viết | Vét cạn và BSGS giải đúng logarit rời rạc |
| TC13–TC14 | Đối chiếu | `mod_pow` so với `pow()`; Miller–Rabin so với chia thử và số Carmichael |
| TC15 | Đối chiếu | Nhóm RFC 3526/7919 trùng OpenSSL |
| TC16 | Đối chiếu | A và K trùng thư viện `cryptography` |
| TC17–TC19 | Đối chiếu | SHA-256 (FIPS 180-4), HMAC (RFC 4231), HKDF (RFC 5869), ChaCha20 (RFC 8439) |
| TC20 | Đối chiếu | Ký hiệu Jacobi khớp tiêu chuẩn Euler |
| TC21 | Tự viết | Ví dụ người đứng giữa tính tay: M = 10, K_AM = 6, K_BM = 5 |
| TC22 | Tự viết | Sinh số nguyên tố an toàn và số nguyên tố ngẫu nhiên đúng độ dài |

## 10. Tối ưu

Mọi chỗ tối ưu đều cho kết quả giống hệt cách làm cơ bản và đã được kiểm thử. Số liệu đo bằng `python main.py bench` trên nhóm MODP 2048 bít, thay đổi tuỳ máy.

| Tối ưu | Ở đâu | Hiệu quả |
|---|---|---|
| Lũy thừa modulo kiểu cửa sổ trượt 5 bít cho số mũ lớn. Số mũ nhỏ vẫn dùng bình phương và nhân cơ bản để in từng bước | `modmath.mod_pow_window` | Nhanh hơn khoảng 1,5 lần, ngang hàm `pow()` viết bằng C |
| Khoá riêng 256 bít thay vì khoảng 2047 bít, đúng mức tối thiểu NIST SP 800-56A và RFC 7919 cho phép | `groups.SHORT_PRIVATE_BITS` | Sinh cặp khoá nhanh hơn khoảng 11–14 lần |
| Kiểm tra khoá công khai bằng ký hiệu Legendre thay cho tính y^q mod p. Hàm Jacobi tách hết thừa số 2 trong một bước | `modmath.jacobi`, `dh.in_subgroup` | Nhanh hơn hàng chục lần (lần đo gần nhất khoảng 90 lần) |
| Sinh số nguyên tố an toàn bằng cách sàng cả một đoạn ứng viên với 6.542 số nguyên tố nhỏ, thử cơ số 2 cho cả q và p trước khi kiểm tra kỹ | `primes.gen_safe_prime` | p 1024 bít từ khoảng 25 giây xuống khoảng 3 giây |
| ChaCha20 giữ trạng thái trong biến cục bộ thay vì list | `chacha20._block_words` | Nhanh hơn khoảng 1,3 lần |

Tính chung, một lần trao đổi khoá 2048 bít (sinh khoá, kiểm tra khoá nhận được, tính K) giảm từ hơn 100 ms xuống dưới 10 ms.

## 11. Xử lý sự cố

- Lỗi font hoặc ký tự lạ trên Windows: dùng Windows Terminal hoặc terminal của VS Code, hoặc chạy `chcp 65001` trước.
- Màu hiện thành ký tự `[31m`: thêm `--no-color`.
- Chương trình dừng chờ Enter: đây là chủ ý để thuyết trình, thêm `--no-pause` để chạy liền.

## 12. Ghi chú

- Chương trình phục vụ học tập. Hệ thống thật nên dùng thư viện mật mã đã được kiểm định.
- Nhóm có dùng công cụ AI (Claude) hỗ trợ viết mã nguồn; nội dung cụ thể được khai báo ở mục 4.4 (Bảng 4.6) của báo cáo.
