# Trao đổi khóa Diffie–Hellman

Bài tập nhóm 4 môn An toàn và bảo mật thông tin.

Chương trình mô phỏng trao đổi khóa Diffie–Hellman bằng Python, minh họa tấn công người đứng giữa và sử dụng khóa chung để mã hóa dữ liệu.

## Tính năng chính

* Trao đổi khóa với bộ số nhỏ, hiển thị các bước tính và mã hóa tin nhắn.
* Trao đổi khóa 2048 bit, mã hóa và giải mã tệp ảnh hoặc văn bản.
* Mô phỏng tấn công người đứng giữa, xác thực bằng chữ ký RSA và thử giải bài toán logarit rời rạc.
* Sinh tham số DH, đo thời gian chạy và kiểm thử chương trình.

## Yêu cầu

* Python 3.8 trở lên.
* Chương trình chính chỉ dùng thư viện chuẩn Python, không cần cài thêm thư viện mật mã.
* `cryptography` và OpenSSL là tùy chọn, dùng để đối chiếu kết quả trong bộ kiểm thử. `mpmath` chỉ cần khi chạy công cụ tính lại tham số nhóm RFC.

## Cài đặt và chạy

Tải hoặc clone repository, mở terminal tại thư mục dự án và chạy:

```bash
python main.py
```

Trên macOS hoặc Linux, dùng `python3` nếu lệnh `python` không hoạt động. Để cài thư viện tùy chọn cho kiểm thử:

```bash
pip install -r requirements.txt
```

Nếu không cài đặt `cryptography`, ca kiểm thử TC16 sẽ được bỏ qua.

## Hướng dẫn sử dụng

Khi chạy `python main.py`, chọn chức năng tương ứng trong menu:

1. Ví dụ số nhỏ và các bước tính.
2. Trao đổi khóa 2048 bit, mã hóa và giải mã tệp.
3. Mô phỏng tấn công người đứng giữa và phòng chống
4. Thử giải logarit rời rạc và kiểm tra khóa công khai giả
5. Đo thời gian chạy.
6. Sinh tham số mới.
7. Chạy bộ kiểm thử.
8. Thoát chương trình.

Chương trình dừng chờ Enter giữa các bước. Có thể chạy trực tiếp từng chức năng bằng các lệnh sau:

|Lệnh|Chức năng|
|-|-|
|`python main.py small --preset 1`|Chạy ví dụ p = 353, g = 3, a = 97, b = 233; kết quả A = 40, B = 248, K = 160.|
|`python main.py small --preset 2`|Chạy ví dụ p = 23, g = 5, a = 6, b = 15; kết quả A = 8, B = 19, K = 2.|
|`python main.py small --preset 3`|Tự nhập p, g, a và b.|
|`python main.py small --preset 2 --lsb`|Hiển thị bảng bình phương và nhân, duyệt bit từ thấp lên cao.|
|`python main.py exchange`|Trao đổi khóa và chọn tệp để mã hóa.|
|`python main.py exchange --file data/sample.png`|Mã hóa và giải mã ảnh mẫu bằng nhóm MODP 2048 bit.|
|`python main.py exchange --message "Xin chào Bob"`|Mã hóa và giải mã tin nhắn.|
|`python main.py mitm`|Mô phỏng tấn công khi không xác thực, khi có xác thực và phiên bình thường.|
|`python main.py mitm --small`|Mô phỏng tấn công với bộ số nhỏ: M = 10, K\_AM = 6, K\_BM = 5.|
|`python main.py attack`|Thử giải logarit rời rạc và kiểm tra khóa công khai giả.|
|`python main.py bench`|Đo thời gian trao đổi khóa, mã hóa và so sánh hiệu năng.|
|`python main.py params --bits 512`|Sinh số nguyên tố an toàn p và căn nguyên thủy g.|
|`python main.py test`|Chạy 22 ca kiểm thử.|

Thêm `--no-pause` để chạy không dừng hoặc `--no-color` để tắt màu.

Kết quả được lưu trong thư mục `output/`, gồm tệp mã hóa, tệp giải mã, báo cáo kiểm thử và các tệp CSV đo thời gian.

## Kiểm thử

```bash
python main.py test
```

Bộ kiểm thử gồm 22 ca, kiểm tra kết quả DH với các bộ số nhỏ và nhóm 2048 bit; kiểm tra khóa công khai, mã hóa tệp, chữ ký RSA, mô phỏng tấn công và sinh tham số. Một số ca đối chiếu kết quả với `pow`, `hashlib`, `hmac`, `cryptography`, OpenSSL hoặc các giá trị chuẩn.

Kết quả được lưu tại `output/test\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_report.txt`.

## Cấu trúc thư mục

```text
dh-project/
├── main.py                  # Menu và tham số dòng lệnh
├── dhcrypto/                # Các thuật toán mật mã
│   ├── modmath.py           # Phép toán modulo và ký hiệu Jacobi
│   ├── primes.py            # Kiểm tra và sinh số nguyên tố
│   ├── primitive\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_root.py    # Kiểm tra và tìm căn nguyên thủy
│   ├── groups.py            # Các nhóm tham số DH
│   ├── dh.py                # Sinh, kiểm tra và trao đổi khóa DH
│   ├── sha256.py            # Hàm băm SHA-256
│   ├── kdf.py               # HMAC-SHA256 và HKDF
│   ├── chacha20.py          # Mã dòng ChaCha20
│   ├── file\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_cipher.py       # Mã hóa và giải mã tệp
│   ├── rsa\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\_sign.py          # Chữ ký RSA
│   ├── attacks.py           # Các phương pháp giải logarit rời rạc
│   └── protocol.py          # Mô phỏng Alice, Bob và Mallory
├── app/                     # Giao diện và các chức năng demo
├── tests/                   # Bộ kiểm thử
├── data/                    # Tệp ảnh và văn bản mẫu
├── output/                  # Tệp kết quả khi chạy chương trình
└── tools/                   # Công cụ tạo dữ liệu và tính tham số RFC
```

## Cách chương trình hoạt động

Hai bên sử dụng tham số công khai p, g, tự chọn khóa riêng a, b và trao đổi khóa công khai A = g^a mod p, B = g^b mod p. Sau khi kiểm tra khóa nhận được, mỗi bên tính bí mật chung K. Chương trình dùng HKDF-SHA256 để tạo khóa mã hóa và khóa MAC từ K, sau đó dùng ChaCha20 và HMAC để bảo vệ dữ liệu.

Các thuật toán DH, phép toán modulo, sinh số nguyên tố, SHA-256, HMAC, HKDF, ChaCha20 và chữ ký RSA được nhóm chúng em tự cài đặt. Chương trình dùng `secrets` để lấy số ngẫu nhiên; các thư viện và công cụ đối chiếu chỉ phục vụ kiểm thử hoặc tạo tham số.

## Giới hạn

* DH cần cơ chế xác thực để phát hiện tấn công người đứng giữa. Bộ số nhỏ chỉ dùng để minh họa; các nhóm 768 và 1024 bit trong chương trình chỉ dùng để đo thời gian.
* Tấn công vét cạn được thử đến khoảng 24 bit, Baby-step Giant-step đến khoảng 40 bit. Chương trình không có khả năng chống tấn công kênh kề theo thời gian.
* Mã hóa bằng Python thuần có thể chậm với tệp lớn. Phần chữ ký RSA dùng cách đệm rút gọn, chưa phải RSA-PSS.

## Xử lý sự cố

* **Lỗi ký tự trên Windows:** dùng Windows Terminal, terminal của VS Code hoặc chạy `chcp 65001` trước khi chạy chương trình.
* **Mã màu hiển thị thành ký tự:** thêm `--no-color` vào lệnh.
* **Không muốn dừng chờ Enter:** thêm `--no-pause` vào lệnh.

## Thành viên

Nhóm 4 – môn An toàn và bảo mật thông tin.

Tạ Trần Khánh Huyền

Hà Khánh Linh

Thái Huyền Trang

Nguyễn Xuân Dương

Nguyễn Minh Phúc

