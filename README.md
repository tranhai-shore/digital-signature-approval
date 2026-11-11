# Application of Digital Signatures for the Document Approval Process

Đồ án môn **Introduction to Cryptography** — mô phỏng quy trình Alice ký số một tài liệu và Bob xác thực, chứng minh **message authentication**, **data integrity** và **non-repudiation**.

## Trạng thái triển khai

| Giai đoạn | Nội dung | Trạng thái |
|---|---|---|
| P0 | Cấu trúc dự án, quy ước package, test harness | ✅ Hoàn thành |
| P1 | Crypto core: modexp, Miller-Rabin, RSA keygen, ký/verify raw, CRT | ✅ Hoàn thành |
| P2 | SHA-256 streaming + padding EMSA-PKCS1-v1_5 + API ký/verify an toàn | ✅ Hoàn thành |
| P3 | TBS metadata, package `.sig`, key service, mã lỗi xác thực | ✅ Hoàn thành |
| P4 | CLI | ⏳ Tiếp theo |
| P5 | GUI Tkinter | ⏳ |
| P6 | Test matrix & hardening | ⏳ |
| P7 | Báo cáo, slide, demo | ⏳ |

> ✅ **P3 đã có luồng ký/xác thực hoàn chỉnh.** `SignService` ký tài liệu và sinh package `.sig`; `VerifyService` kiểm tra toàn bộ chuỗi (package → khóa → kích thước → SHA-256 → chữ ký → TBS) và trả về **mã lỗi ổn định** cho CLI/GUI ở P4–P5.

## Cấu trúc

```text
digital-signature-approval/
├── src/
│   ├── crypto/
│   │   ├── numtheory.py       # modexp (square-and-multiply), egcd, modinv, gcd/lcm
│   │   ├── primes.py          # Miller-Rabin, sinh số nguyên tố
│   │   ├── rsa.py             # keygen, raw sign/verify, CRT, fingerprint, key JSON
│   │   ├── hashing.py         # SHA-256 streaming (1 MiB/chunk)
│   │   ├── padding.py         # EMSA-PKCS1-v1_5 encode/decode nghiêm ngặt
│   │   ├── signature.py       # API ký/verify tài liệu an toàn
│   │   └── encoding.py        # int <-> bytes, base64url, so sánh hằng thời gian
│   ├── models/
│   │   ├── signature_package.py  # schema package `.sig`, chuẩn hóa metadata
│   │   ├── timestamp.py          # timestamp UTC chuẩn (…Z)
│   │   └── verification.py       # VerificationReason + kết quả xác thực
│   └── services/
│       ├── tbs.py             # TBS canonical (length-prefixed, domain-separated)
│       ├── sign_service.py    # ký file / dữ liệu, sinh package
│       ├── verify_service.py  # xác thực file / dữ liệu, ánh xạ mã lỗi
│       ├── package_service.py # đọc/ghi `.sig` JSON
│       ├── key_service.py     # sinh/lưu/nạp khóa, khóa riêng có mật khẩu
│       └── file_service.py    # ghi atomic, đường dẫn `.sig` mặc định
├── tests/
│   ├── test_numtheory.py
│   ├── test_primes.py
│   ├── test_rsa.py
│   ├── test_hashing.py
│   ├── test_padding.py
│   ├── test_signature.py
│   ├── test_encoding.py
│   ├── test_tbs.py
│   ├── test_package.py
│   ├── test_key_service.py
│   └── test_sign_verify_service.py
└── docs/
    ├── pre_project_report.md
    ├── SIGNATURE_FORMAT.md       # đặc tả TBS, package `.sig`, mã lỗi
    ├── KE_HOACH_TRIEN_KHAI.md
    └── references/
        ├── *.pdf                 # bài giảng, lab, chương sách
        └── _extracted/*.txt      # text trích xuất để tra cứu
```

## Cài đặt và chạy test

```powershell
pip install -r requirements.txt
python -m pytest -q
```

Kết quả hiện tại: **206 passed**.

Test bao gồm:

- đối chiếu `modexp` với `pow` của Python, kiểm tra định lý Bézout, nghịch đảo modulo (bài Lab 2);
- Miller-Rabin với số nguyên tố/composite đã biết (561, 1105, 1729, 2047…);
- vector RSA kinh điển `p=61, q=53, e=17, d=2753, m=65 → s=588`;
- sinh khóa 1024-bit cho test chức năng và 2048-bit cho yêu cầu dự án;
- roundtrip ký/verify, kiểm tra CRT khớp `pow(m, d, n)`, phát hiện chữ ký bị sửa/sai khóa;
- SHA-256 vector NIST (`""`, `"abc"`) và streaming với nhiều kích thước chunk;
- kiểm tra cấu trúc padding, từ chối sai header/PS/separator/DigestInfo;
- ký/verify file 1.7 MB, phát hiện flip 1 bit;
- **TBS**: tất định, mỗi trường metadata đều làm thay đổi TBS, chống nhập nhằng nhờ length-prefix, chuẩn hóa Unicode NFC và timestamp UTC;
- **package `.sig`**: roundtrip JSON, giữ tiếng Việt, từ chối format/algorithm/digest/fingerprint/signature sai;
- **key service**: sinh/lưu/nạp khóa, quyền file, khóa riêng mã hóa bằng mật khẩu, phát hiện sai mật khẩu và dữ liệu bị sửa;
- **luồng ký/xác thực**: sửa 1 bit, sửa kích thước, sửa metadata, sai khóa, sai người ký, package thiếu/hỏng/không phải UTF-8, tên tệp Unicode;
- **cross-check với thư viện `cryptography`**: chữ ký của dự án phải giống từng byte với OpenSSL.

Chạy thêm cross-check và test khóa có mật khẩu (tùy chọn):

```powershell
pip install -r requirements-dev.txt
python -m pytest -q
```

## Dùng nhanh

### P2 — ký/verify ở mức byte

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

### P3 — ký tài liệu kèm metadata và xác thực

```python
from src.services.key_service import KeyService
from src.services.sign_service import SignService
from src.services.verify_service import VerifyService

# 1. Sinh khóa (private 0o600, public 0o644).
generated = KeyService.generate("alice", bits=2048, keys_dir="keys")

# 2. Ký: tạo contract.pdf.sig bên cạnh tài liệu.
result = SignService.sign_file(
    generated.private_key,
    "contract.pdf",
    signer="Nguyễn Văn A",
)
print(result.package_path)                 # contract.pdf.sig
print(result.package.key_fingerprint)

# 3. Xác thực bằng khóa công khai đã chia sẻ.
verification = VerifyService.verify_file(
    "contract.pdf",
    result.package_path,
    generated.private_key.public_key,
    expected_signer="Nguyễn Văn A",
)
print(verification.reason.value, verification.message)
assert verification.valid
```

Nạp khóa từ đĩa và bảo vệ khóa riêng bằng mật khẩu:

```python
from src.services.key_service import KeyService

generated = KeyService.generate("alice", password="correct horse battery staple")
private_key = KeyService.load_private(
    generated.private_path,
    password="correct horse battery staple",
)
public_key = KeyService.load_public(generated.public_path)
```

> Khóa riêng có mật khẩu cần gói tùy chọn `cryptography` (PBKDF2 + AES-256-GCM). Không có mật khẩu, khóa riêng vẫn là JSON thuần và toàn bộ phần mật mã lõi chạy bằng stdlib.

## Đặc tả package `.sig`

Chi tiết đầy đủ ở [`docs/SIGNATURE_FORMAT.md`](docs/SIGNATURE_FORMAT.md). Tóm tắt:

- Package là JSON UTF-8, định danh `format: "DSIG/1"`, thuật toán `RSA-PKCS1v15-SHA256`.
- Metadata được ký (**TBS**) gồm: algorithm, signer, tên tệp gốc, kích thước, thời điểm ký UTC và SHA-256 của tài liệu.
- TBS dùng **domain separator** `DSIGv1\0` và **length-prefix** cho mọi trường biến độ dài → không thể nhập nhằng `("ab","c")` với `("a","bc")`.
- Chữ ký là `RSA(private_key, SHA-256(TBS))` theo EMSA-PKCS1-v1_5; ký lại metadata không làm hỏng chữ ký, nhưng sửa metadata thì `TBS_MISMATCH`.
- Ghi atomic (temp file + `os.replace`), không để lại tệp tạm.

## Mã lỗi xác thực

`VerifyService` trả về `VerificationResult` với `reason` ổn định (dùng cho CLI/GUI và test):

| Mã | Ý nghĩa |
|---|---|
| `VALID` | Chữ ký hợp lệ, tài liệu chưa bị thay đổi. |
| `PACKAGE_NOT_FOUND` | Không tìm thấy tệp `.sig`. |
| `PACKAGE_READ_ERROR` | Không đọc được `.sig` (ví dụ là thư mục, lỗi quyền). |
| `PACKAGE_MALFORMED` | JSON/UTF-8 hỏng hoặc sai schema. |
| `UNSUPPORTED_ALGORITHM` | Package khai báo thuật toán không hỗ trợ. |
| `KEY_MISMATCH` | Khóa công khai không khớp fingerprint trong package. |
| `SIGNER_MISMATCH` | Người ký khác `expected_signer`. |
| `FILE_NOT_FOUND` | Không tìm thấy tài liệu. |
| `FILE_READ_ERROR` | Không đọc được tài liệu. |
| `SIZE_MISMATCH` | Kích thước tài liệu khác metadata. |
| `HASH_MISMATCH` | Nội dung tài liệu đã thay đổi (SHA-256 khác). |
| `SIGNATURE_MALFORMED` | Chữ ký sai độ dài/định dạng hoặc ≥ modulus. |
| `PADDING_INVALID` | Cấu trúc EMSA-PKCS1-v1_5 không hợp lệ. |
| `TBS_MISMATCH` | Chữ ký không khớp metadata đã ký. |

Thứ tự kiểm tra: **parse package → expected signer → fingerprint khóa → tồn tại tệp → kích thước → SHA-256 → chữ ký/padding → TBS**. Nhờ vậy lỗi được báo ở bước sớm nhất và không lộ chi tiết mật mã không cần thiết.

## Đặc điểm kỹ thuật

### P2 — padding và ký

- `EM = 0x00 || 0x01 || 0xFF... || 0x00 || DigestInfo(SHA-256) || digest` đúng RFC 8017 §9.2.
- Decode kiểm tra **toàn bộ cấu trúc**, không chỉ 32 byte cuối; PS tối thiểu 8 byte.
- Chữ ký có độ dài cố định bằng modulus (256 byte với RSA-2048), kể cả khi có byte 0 đứng đầu.
- So sánh digest bằng `hmac.compare_digest`.
- Sau khi ký, tự kiểm tra lại bằng khóa công khai để phát hiện lỗi CRT (fault attack).
- Hash file theo chunk 1 MiB, không nạp cả tài liệu vào RAM.

### P3 — metadata, khóa và package

- Signer và tên tệp được chuẩn hóa **Unicode NFC**; tên tệp phải là basename, từ chối `/`, `\`, `.`, `..`.
- Timestamp bắt buộc có múi giờ và được đưa về UTC dạng `2026-11-11T10:00:00Z`.
- `original_name` nằm trong TBS nên đổi tên trong package sẽ bị phát hiện.
- Khóa công khai: JSON `RSA-PUB/1`; khóa riêng: JSON `RSA-PRIV/1`.
- Khóa riêng có mật khẩu: envelope `RSA-PRIV-ENC/1`, PBKDF2-HMAC-SHA256 200.000 vòng, AES-256-GCM, AAD gắn với fingerprint.
- Tên khóa giới hạn `[A-Za-z0-9][A-Za-z0-9._-]{0,63}` để tránh path traversal.
- Ghi file atomic; khóa riêng `0o600`, khóa công khai và package `0o644`.

## Quy ước kỹ thuật

- Modulus mặc định **2048 bit**, `e = 65537`, Miller-Rabin **40 rounds**.
- `d` được tính theo `φ(N)`, các tham số CRT `dp`, `dq`, `qinv` được kiểm tra nhất quán.
- Khóa riêng có `repr` an toàn, không in `d`, `p`, `q`.
- Fingerprint = `SHA-256("RSA-PUB/1" || len(n) || n || len(e) || e)`.
- Không phụ thuộc thư viện mật mã ngoài; chỉ dùng `hashlib`/`secrets` của stdlib. `cryptography` chỉ là tùy chọn cho khóa riêng có mật khẩu và cross-check.

## Tài liệu

- `docs/SIGNATURE_FORMAT.md` — đặc tả TBS, package `.sig`, định dạng khóa và mã lỗi.
- `docs/pre_project_report.md` — báo cáo tiền dự án.
- `docs/KE_HOACH_TRIEN_KHAI.md` — kế hoạch triển khai đầy đủ (P0–P7, test matrix, báo cáo, demo).
- `docs/references/` — PDF bài giảng, lab và chương sách tham khảo.
- `docs/references/_extracted/` — text trích từ các PDF để tra cứu nhanh.
