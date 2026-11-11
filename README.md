# Application of Digital Signatures for the Document Approval Process

Đồ án môn **Introduction to Cryptography** — mô phỏng quy trình Alice ký số một tài liệu và Bob xác thực, chứng minh **message authentication**, **data integrity** và **non-repudiation**.

## Trạng thái triển khai

| Giai đoạn | Nội dung | Trạng thái |
|---|---|---|
| P0 | Cấu trúc dự án, quy ước package, test harness | ✅ Hoàn thành |
| P1 | Crypto core: modexp, Miller-Rabin, RSA keygen, ký/verify raw, CRT | ✅ Hoàn thành |
| P2 | SHA-256 streaming + padding EMSA-PKCS1-v1_5 + API ký/verify an toàn | ✅ Hoàn thành |
| P3 | Signing/verification service + package `.sig` | ⏳ Tiếp theo |
| P4 | CLI | ⏳ |
| P5 | GUI Tkinter | ⏳ |
| P6 | Test matrix & hardening | ⏳ |
| P7 | Báo cáo, slide, demo | ⏳ |

> ✅ **P2 đã an toàn để ký tài liệu.** Luôn dùng `sign_file` / `verify_file` (hoặc `sign_bytes` / `verify_bytes`); không gọi trực tiếp `sign_int` / `verify_int` với hash tài liệu.

## Cấu trúc

```text
digital-signature-approval/
├── src/
│   ├── crypto/
│   │   ├── numtheory.py   # modexp (square-and-multiply), egcd, modinv, gcd/lcm
│   │   ├── primes.py      # Miller-Rabin, sinh số nguyên tố
│   │   ├── rsa.py         # keygen, raw sign/verify, CRT, fingerprint
│   │   ├── hashing.py     # SHA-256 streaming (1 MiB/chunk)
│   │   ├── padding.py     # EMSA-PKCS1-v1_5 encode/decode nghiêm ngặt
│   │   ├── signature.py   # API ký/verify tài liệu an toàn
│   │   └── encoding.py    # int <-> bytes, base64url
│   ├── services/          # P3
│   └── models/            # P3
├── tests/
│   ├── test_numtheory.py
│   ├── test_primes.py
│   ├── test_rsa.py
│   ├── test_hashing.py
│   ├── test_padding.py
│   ├── test_signature.py
│   └── test_encoding.py
└── docs/
    ├── pre_project_report.md
    ├── KE_HOACH_TRIEN_KHAI.md
    └── references/
        ├── *.pdf              # bài giảng, lab, chương sách
        └── _extracted/*.txt   # text trích xuất để tra cứu
```

## Cài đặt và chạy test

```powershell
pip install -r requirements.txt
python -m pytest -q
```

Test bao gồm:

- đối chiếu `modexp` với `pow` của Python, kiểm tra định lý Bézout, nghịch đảo modulo (bài Lab 2);
- Miller-Rabin với số nguyên tố/composite đã biết (561, 1105, 1729, 2047…);
- vector RSA kinh điển `p=61, q=53, e=17, d=2753, m=65 → s=588`;
- sinh khóa 1024-bit cho test chức năng và 2048-bit cho yêu cầu dự án;
- roundtrip ký/verify, kiểm tra CRT khớp `pow(m, d, n)`, phát hiện chữ ký bị sửa/sai khóa;
- SHA-256 vector NIST (`""`, `"abc"`) và streaming với nhiều kích thước chunk;
- kiểm tra cấu trúc padding, từ chối sai header/PS/separator/DigestInfo;
- ký/verify file 1.7 MB, phát hiện flip 1 bit;
- **cross-check với thư viện `cryptography`**: chữ ký của dự án phải giống từng byte với OpenSSL.

Chạy thêm cross-check (tùy chọn):

```powershell
pip install -r requirements-dev.txt
python -m pytest -q
```

## Dùng nhanh

```python
from src.crypto.rsa import generate_keypair
from src.crypto.signature import sign_file, verify_file

key = generate_keypair(bits=2048)

signature = sign_file(key, "contract.pdf")
assert verify_file(key.public_key, "contract.pdf", signature)
print(key.public_key.fingerprint)
```

Với dữ liệu trong bộ nhớ:

```python
from src.crypto.signature import sign_bytes, verify_bytes

signature = sign_bytes(key, b"noi dung tai lieu")
assert verify_bytes(key.public_key, b"noi dung tai lieu", signature)
assert not verify_bytes(key.public_key, b"noi dung bi sua", signature)
```

## Đặc điểm kỹ thuật của P2

- `EM = 0x00 || 0x01 || 0xFF... || 0x00 || DigestInfo(SHA-256) || digest` đúng RFC 8017 §9.2.
- Decode kiểm tra **toàn bộ cấu trúc**, không chỉ 32 byte cuối; PS tối thiểu 8 byte.
- Chữ ký có độ dài cố định bằng modulus (256 byte với RSA-2048), kể cả khi có byte 0 đứng đầu.
- So sánh digest bằng `hmac.compare_digest`.
- Sau khi ký, tự kiểm tra lại bằng khóa công khai để phát hiện lỗi CRT (fault attack).
- Hash file theo chunk 1 MiB, không nạp cả tài liệu vào RAM.

## Quy ước kỹ thuật

- Modulus mặc định **2048 bit**, `e = 65537`, Miller-Rabin **40 rounds**.
- `d` được tính theo `φ(N)`, các tham số CRT `dp`, `dq`, `qinv` được kiểm tra nhất quán.
- Khóa riêng có `repr` an toàn, không in `d`, `p`, `q`.
- Fingerprint = `SHA-256("RSA-PUB/1" || len(n) || n || len(e) || e)`.
- Không phụ thuộc thư viện mật mã ngoài; chỉ dùng `hashlib`/`secrets` của stdlib.

## Tài liệu

- `docs/pre_project_report.md` — báo cáo tiền dự án.
- `docs/KE_HOACH_TRIEN_KHAI.md` — kế hoạch triển khai đầy đủ (P0–P7, test matrix, báo cáo, demo).
- `docs/references/` — PDF bài giảng, lab và chương sách tham khảo.
- `docs/references/_extracted/` — text trích từ các PDF để tra cứu nhanh.
