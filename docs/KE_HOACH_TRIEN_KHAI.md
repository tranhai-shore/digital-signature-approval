# KẾ HOẠCH TRIỂN KHAI DỰ ÁN
## Application of Digital Signatures for the Document Approval Process

> Tài liệu lập ngày: 11/11/2026  
> Cơ sở: `pre_project_report.md`, Session 7 (Digital Signature & Hash), Session 8 (MAC & PKI), Lab 2 (Square-and-Multiply, nghịch đảo modulo), Lab 3 (RSA), `ElgamalDigitalSignature.pdf`.

---

## 1. Tóm tắt yêu cầu rút ra từ tài liệu

Dự án mô phỏng quy trình **Alice ký – Bob xác thực** một tài liệu, nhằm chứng minh 3 tính chất:

| Tính chất | Cơ chế đảm bảo |
|---|---|
| Message Authentication | Chữ ký tạo bằng khóa riêng của Alice, xác thực bằng khóa công khai của Alice |
| Data Integrity | So sánh hash của tài liệu nhận được với hash được bảo vệ trong chữ ký |
| Non-repudiation | Chỉ Alice giữ `d`, nên không thể phủ nhận chữ ký (trong phạm vi mô hình) |

Trình tự kỹ thuật bắt buộc:

1. **Key generation:** sinh `p`, `q` nguyên tố lớn → `N = p·q`, `φ(N) = (p−1)(q−1)`, chọn `e` (thường 65537), tính `d ≡ e⁻¹ mod φ(N)`.
2. **Signing:** `z = SHA-256(x)` → áp dụng padding → `s = EM^d mod N`.
3. **Verification:** `EM' = s^e mod N` → kiểm tra cấu trúc padding → so sánh digest bên trong với `SHA-256(x)`.

Điểm quan trọng về mặt học thuật: **không ký trực tiếp `z` kiểu textbook RSA**, mà phải dùng padding (EMSA-PKCS1-v1_5 hoặc PSS) để chống forgery attack — đúng như cảnh báo trong Session 7 và pre-project report.

---

## 2. Mục tiêu và phạm vi

### 2.1. Mục tiêu

- Xây dựng ứng dụng chạy được, cho phép:
  - Sinh – lưu – nạp cặp khóa RSA 2048-bit.
  - Ký số một file bất kỳ (PDF, TXT, DOCX, ảnh…).
  - Xác thực file + chữ ký, phát hiện mọi thay đổi dù chỉ 1 bit.
  - Hiển thị kết quả rõ ràng: `VALID` / `INVALID` kèm lý do.
- Chứng minh bằng demo 2 kịch bản trong báo cáo: luồng hợp lệ và tấn công MitM/chỉnh sửa nội dung.
- Viết báo cáo, slide và kịch bản demo theo chuẩn môn học.

### 2.2. Trong phạm vi (In scope)

- RSA 2048-bit, SHA-256, padding PKCS#1 v1.5.
- Đóng gói chữ ký thành file `.sig` (JSON) độc lập với tài liệu.
- CLI + GUI desktop đơn giản (Tkinter).
- Quản lý khóa cơ bản: file khóa riêng/công khai, fingerprint, tùy chọn mật khẩu bảo vệ khóa riêng.
- Kiểm thử tự động + bộ test case phục vụ báo cáo.

### 2.3. Ngoài phạm vi (Out of scope – ghi rõ trong báo cáo)

- PKI/CA thật, chứng chỉ X.509, CRL/OCSP (chỉ nêu hướng mở rộng).
- Timestamp authority (TSA) tin cậy.
- Nhúng chữ ký hiển thị trực tiếp vào PDF (visible signature).
- HSM, smartcard, ký hàng loạt quy mô lớn.
- Chống side-channel (timing/power analysis) — chỉ nêu lý thuyết.

---

## 3. Yêu cầu chức năng (Functional Requirements)

| ID | Yêu cầu | Ưu tiên |
|---|---|---|
| FR-01 | Sinh cặp khóa RSA 2048-bit, hiển thị fingerprint SHA-256 của khóa công khai | Must |
| FR-02 | Xuất/nhập khóa công khai; xuất khóa riêng có cảnh báo bảo mật | Must |
| FR-03 | Ký một file, sinh package `.sig` chứa chữ ký + metadata | Must |
| FR-04 | Xác thực file + `.sig`, trả về `VALID`/`INVALID` + lý do cụ thể | Must |
| FR-05 | Phát hiện tài liệu bị sửa (1 bit), chữ ký bị sửa, sai khóa, sai định dạng | Must |
| FR-06 | Hiển thị digest, signer, thời gian ký, thuật toán, fingerprint | Must |
| FR-07 | Bảo vệ khóa riêng bằng mật khẩu (PBKDF2 + AES-256-GCM) | Should |
| FR-08 | GUI 3 tab: Keys / Sign / Verify, có banner kết quả màu xanh/đỏ | Must |
| FR-09 | CLI đầy đủ cho việc test và demo tự động | Must |
| FR-10 | Tab "Demo tấn công": sửa 1 byte tài liệu để minh họa | Should |
| FR-11 | Lịch sử ký/xác thực trong phiên (audit log) | Could |
| FR-12 | Xuất báo cáo kết quả xác thực ra `.txt`/`.json` | Could |

### Yêu cầu phi chức năng (NFR)

- **Bảo mật:** modulus ≥ 2048 bit; `e = 65537`; SHA-256; không log khóa riêng; không dùng `random` mà dùng `secrets`.
- **Hiệu năng:** ký/xác thực file 50 MB < 2 giây (không tính keygen); hash theo chunk 1 MB để không load cả file vào RAM.
- **Tương thích:** Python 3.11+ trên Windows/Linux; không cần mạng.
- **Khả năng kiểm thử:** toàn bộ crypto core có unit test, không phụ thuộc GUI.
- **Usability:** thông báo lỗi bằng tiếng Việt/Anh rõ ràng, không crash khi file hỏng.

---

## 4. Kiến trúc hệ thống

```
┌─────────────────────────────────────────────────────┐
│  Presentation                                       │
│  ├── CLI (argparse)                                 │
│  └── GUI (Tkinter: Keys | Sign | Verify | Demo)     │
├─────────────────────────────────────────────────────┤
│  Application Services                               │
│  ├── KeyService        (generate/load/save/export)  │
│  ├── SignService       (build TBS → sign → package) │
│  ├── VerifyService     (parse → verify → report)    │
│  └── FileService       (stream hash, atomic write)  │
├─────────────────────────────────────────────────────┤
│  Crypto Core (pure Python, không phụ thuộc UI)      │
│  ├── sha256.py         (hash file/bytes, streaming) │
│  ├── rsa.py            (keygen, sign, verify, CRT)  │
│  ├── primes.py         (Miller-Rabin, random prime) │
│  ├── numtheory.py      (modexp, egcd, modinv)       │
│  ├── padding.py        (EMSA-PKCS1-v1_5)            │
│  └── encoding.py       (int ↔ bytes, base64url)     │
├─────────────────────────────────────────────────────┤
│  Storage                                            │
│  ├── keys/alice_private.json | alice_public.json    │
│  └── signatures/<document>.sig                      │
└─────────────────────────────────────────────────────┘
```

### 4.1. Luồng ký

```
File x ──SHA-256 stream──► digest z
Metadata (signer, original_name, size, signed_at, z)
        └──► TBS (domain-separated, length-prefixed)
                └──► EMSA-PKCS1-v1_5 encode ──► EM
                        └──► s = EM^d mod N
                                └──► package .sig (JSON + base64)
```

### 4.2. Luồng xác thực

```
File x' ──SHA-256──► z'
Package .sig ──► parse + kiểm tra schema
        ├── dựng lại TBS từ metadata
        ├── EM' = s^e mod N
        ├── kiểm tra prefix 0x00 0x01 FF..FF 0x00 + DigestInfo + z_package
        └── so sánh z' == z_package  ⇒ VALID / INVALID
```

### 4.3. Định dạng package chữ ký (`.sig`)

```json
{
  "format": "DSIG/1",
  "alg": "RSA-2048-PKCS1v15-SHA256",
  "signer": "alice",
  "key_fingerprint": "sha256:9f2c...",
  "file": {
    "original_name": "contract.pdf",
    "size": 12345,
    "sha256": "ab34..."
  },
  "signed_at": "2026-11-11T10:00:00Z",
  "signature": "base64url(...)"
}
```

**Quyết định thiết kế quan trọng:**

- **TBS (To-Be-Signed)** phải gồm cả metadata được bảo vệ, không chỉ nội dung file:
  ```
  TBS = b"DSIGv1\x00"
        || u32(len(signer)) || signer_utf8
        || u32(len(original_name)) || original_name_utf8
        || u64(size)
        || u32(len(signed_at)) || signed_at_utf8
        || sha256(file_bytes)
  ```
  nhờ đó kẻ tấn công không thể đổi tên file, signer hay thời gian trong package mà vẫn qua kiểm tra.
- **Độ dài có tiền tố (length-prefixed)** để tránh tấn công nối chuỗi mơ hồ (`ab|c` vs `a|bc`).
- **Không canonicalize nội dung file**: ký đúng byte nhận được; PDF/DOCX có thể thay đổi metadata nội bộ nếu mở và lưu lại → phải nêu rõ trong báo cáo.
- **So sánh toàn bộ EM** sau khi giải mã chữ ký, không chỉ so hash, để phát hiện lỗi padding.
- **Thời gian `signed_at` chỉ là tự khai báo**, không phải bằng chứng thời gian tin cậy; muốn chắc cần TSA (ngoài phạm vi).
- **Fingerprint** = SHA-256 của public key (encoding chuẩn `N || e`) để người dùng đối chiếu qua kênh khác, giảm rủi ro thay khóa công khai.

---

## 5. Công nghệ và cấu trúc thư mục

### 5.1. Công nghệ

| Thành phần | Lựa chọn | Lý do |
|---|---|---|
| Ngôn ngữ | Python 3.11+ | Phù hợp Lab 1–3, dễ demo, thư viện chuẩn mạnh |
| Hash | `hashlib.sha256` | Có sẵn, streaming, đã kiểm chứng |
| RSA core | Tự cài đặt | Thể hiện hiểu thuật toán (yêu cầu môn học) |
| Số nguyên tố | Miller-Rabin tự cài đặt | Tái sử dụng Lab 2 |
| modexp / modinv | Square-and-Multiply, Extended Euclid | Tái sử dụng Lab 2 |
| GUI | Tkinter (stdlib) | Không cần cài đặt thêm, chạy mọi máy |
| Test | `pytest` | Unit + integration test rõ ràng |
| Đóng gói | `pyinstaller` (tùy chọn) | Xuất `.exe` demo nếu cần |

> Nếu giảng viên cho phép dùng thư viện: dùng `cryptography` để **đối chứng** chữ ký (cross-check), nhưng core vẫn tự cài đặt để đáp ứng yêu cầu học thuật.

### 5.2. Cấu trúc thư mục đề xuất

```
Cryptography/
├── src/
│   ├── crypto/
│   │   ├── __init__.py
│   │   ├── numtheory.py
│   │   ├── primes.py
│   │   ├── rsa.py
│   │   ├── padding.py
│   │   ├── encoding.py
│   │   └── hashing.py
│   ├── services/
│   │   ├── key_service.py
│   │   ├── sign_service.py
│   │   ├── verify_service.py
│   │   └── file_service.py
│   ├── models/
│   │   ├── keypair.py
│   │   └── signature_package.py
│   ├── cli.py
│   └── gui.py
├── tests/
│   ├── test_numtheory.py
│   ├── test_primes.py
│   ├── test_rsa.py
│   ├── test_padding.py
│   ├── test_sign_verify.py
│   └── test_scenarios.py
├── keys/                  # không commit khóa thật
├── samples/               # hợp đồng mẫu, file test
├── signatures/
├── docs/
│   ├── report.md / report.pdf
│   ├── slides.pdf
│   └── demo_script.md
├── requirements.txt
├── README.md
└── .gitignore
```

---

## 6. Thiết kế chi tiết phần mã hóa

### 6.1. Sinh khóa RSA 2048-bit

1. Sinh `p`, `q` nguyên tố 1024-bit bằng `secrets.randbits`, kiểm tra Miller-Rabin với 40 vòng (xác suất sai < 2⁻⁸⁰).
2. Đảm bảo `p ≠ q`, `N = p·q` có đúng 2048 bit.
3. `φ = (p−1)(q−1)`, `e = 65537`, kiểm tra `gcd(e, φ) = 1`.
4. `d = modinv(e, φ)` bằng Extended Euclid.
5. Tính trước hệ số CRT: `dp = d mod (p−1)`, `dq = d mod (q−1)`, `qinv = q⁻¹ mod p`.
6. Kiểm tra tự kiểm: `(m^e)^d ≡ m (mod N)` với vài giá trị ngẫu nhiên.

### 6.2. Padding EMSA-PKCS1-v1_5 (SHA-256)

```
EM = 0x00 || 0x01 || PS (0xFF × k) || 0x00 || DigestInfo || z
```
- `k` = độ dài modulus tính bằng byte (256 với RSA-2048).
- `DigestInfo` cho SHA-256:
  `30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20`.
- `PS` dài tối thiểu 8 byte; nếu không đủ chỗ → báo lỗi cấu hình.
- Khi verify: kiểm tra chính xác cấu trúc, không chấp nhận EM tuỳ ý.

### 6.3. Ký và xác thực

```
Sign:    s = pow(EM, d, N)          (dùng CRT để tăng tốc)
Verify:  EM' = pow(s, e, N)
         parse(EM') hợp lệ và digest == SHA-256(file)  ⇒ VALID
```

Xử lý lỗi cần phân biệt khi trả kết quả:

| Trường hợp | Kết quả |
|---|---|
| File đổi 1 bit | `INVALID: HASH_MISMATCH` |
| Chữ ký sai 1 bit | `INVALID: SIGNATURE_MALFORMED` hoặc `PADDING_INVALID` |
| Dùng khóa công khai của người khác | `INVALID: HASH_MISMATCH` |
| Package đổi `original_name`/`signer`/`signed_at` | `INVALID: TBS_MISMATCH` |
| Thiếu field / JSON hỏng | `INVALID: PACKAGE_MALFORMED` |
| File không tồn tại / không đọc được | Lỗi I/O có thông báo rõ |

### 6.4. Lưu trữ khóa

- `alice_public.json`: `{format, n, e, fingerprint}` — số nguyên dạng chuỗi thập phân hoặc base64url.
- `alice_private.json`: `{format, n, e, d, p, q, dp, dq, qinv}`.
- Tùy chọn (FR-07): mã hóa private key bằng:
  - `salt = secrets.token_bytes(16)`
  - `key = PBKDF2-HMAC-SHA256(passphrase, salt, 200_000)`
  - `AES-256-GCM(key, nonce, plaintext_key)`
  - Lưu `{kdf, salt, nonce, ciphertext, tag}`.
- Luôn đặt quyền file hạn chế (Linux `0600`); trên Windows ghi cảnh báo.
- `.gitignore`: `keys/*`, `*.sig`, `__pycache__`.

### 6.5. Ghi chú bảo mật để đưa vào báo cáo

- Textbook RSA không padding bị forgery: chọn `s` bất kỳ → `m = s^e mod N` là “chữ ký hợp lệ” cho message `m`. Padding + DigestInfo khắc phục.
- Không dùng chung khóa cho mã hóa và ký.
- Kích thước 1024-bit không còn an toàn; dự án dùng 2048-bit.
- Việc xác thực khóa công khai vẫn là điểm yếu: kẻ tấn công có thể tráo public key → cần PKI/CA (chương 8, Session 8).
- Không cam kết chống side-channel trong phạm vi mô phỏng.

---

## 7. Kế hoạch triển khai theo giai đoạn

Giả định thời lượng **3 tuần** (~13–15 ngày làm việc). Có thể nén xuống 2 tuần bằng cách bỏ FR-07/FR-10 và giảm GUI.

| Giai đoạn | Thời lượng | Công việc chính | Đầu ra / Điều kiện hoàn thành |
|---|---|---|---|
| **P0. Khởi tạo** | 0.5 ngày | Tạo repo, cấu trúc thư mục, `requirements.txt`, `.gitignore`, chốt format `.sig`, vẽ sơ đồ kiến trúc | Repo chạy `pytest` rỗng; tài liệu thiết kế 1 trang |
| **P1. Crypto core** | 3 ngày | `numtheory` (modexp, egcd, modinv), `primes` (Miller-Rabin), `rsa` (keygen, sign, verify, CRT), test vector Lab 2/3 | Unit test pass; keygen 2048 < 3 s; ký/verify vòng tròn đúng |
| **P2. Hash + padding** | 1.5 ngày | Hash streaming, EMSA-PKCS1-v1_5 encode/decode, test vector SHA-256 ("abc"), kiểm tra lỗi padding | Ký/verify với padding đúng chuẩn; cross-check bằng `cryptography` |
| **P3. Dịch vụ ký & package** | 2 ngày | TBS builder, `sign_service`, `verify_service`, JSON schema, atomic write, fingerprint | Ký file PDF/TXT tạo `.sig`; verify đúng/sai đúng kỳ vọng |
| **P4. CLI** | 1 ngày | `keygen`, `sign`, `verify`, `fingerprint`, `tamper` (demo) | 4 lệnh chạy được, exit code 0/1 rõ ràng |
| **P5. GUI** | 2 ngày | Tkinter tabs, chọn file, hiển thị kết quả, banner màu, log | Demo được hoàn toàn bằng chuột |
| **P6. Kiểm thử & hardening** | 2 ngày | Chạy toàn bộ test matrix, fuzz nhẹ JSON, file lớn, Unicode, đóng gói `.exe` (nếu cần) | Test matrix 100% pass; bug nghiêm trọng = 0 |
| **P7. Báo cáo & demo** | 3 ngày | Viết báo cáo, hình minh họa, slide, quay video, tập demo | Báo cáo + slide + video + biên bản test |
| **Dự phòng** | 1 ngày | Sửa lỗi phát sinh, buffer | — |

### Cột mốc kiểm tra (milestones)

- **M1 – Cuối ngày 3:** keygen + sign/verify core chạy bằng test.
- **M2 – Cuối ngày 7:** CLI ký/verify file thật, package `.sig` hoàn chỉnh.
- **M3 – Cuối ngày 10:** GUI hoàn thiện, demo 2 kịch bản.
- **M4 – Cuối ngày 13:** báo cáo + slide + video sẵn sàng.

---

## 8. Kế hoạch kiểm thử

### 8.1. Unit test

| ID | Đối tượng | Input | Kỳ vọng |
|---|---|---|---|
| UT-01 | `modexp` | `85625 mod 7` (Lab 2) | `4` |
| UT-02 | `modinv` | `65537⁻¹ mod 35256` (Lab 2) | Giá trị kiểm chứng `a·a⁻¹ ≡ 1` |
| UT-03 | Miller-Rabin | 2, 3, 17, 561, 1105, 2047 | Đúng prime/composite |
| UT-04 | RSA keygen | 2048-bit | `N` đúng 2048 bit, `e·d ≡ 1 mod φ` |
| UT-05 | RSA sign/verify | Thông điệp ngẫu nhiên | Verify `True` |
| UT-06 | SHA-256 | `"abc"` | `ba7816bf...` (NIST vector) |
| UT-07 | Padding | Digest 32 byte | Giải mã lại đúng cấu trúc; sửa 1 byte → fail |
| UT-08 | TBS | Metadata thay đổi | Digest TBS khác nhau |
| UT-09 | Package schema | JSON thiếu field | Báo `PACKAGE_MALFORMED` |
| UT-10 | Fingerprint | Cùng public key | Ổn định, khác khi đổi `e`/`N` |

### 8.2. Integration / demo scenarios

| ID | Kịch bản | Thao tác | Kỳ vọng |
|---|---|---|---|
| IT-01 | Luồng hợp lệ (Scenario 1) | Alice ký `contract.pdf`, Bob verify | `VALID`, hiện đúng signer/fingerprint |
| IT-02 | MitM sửa nội dung (Scenario 2) | Đổi `1000` → `9000` trong file, giữ `.sig` | `INVALID: HASH_MISMATCH` |
| IT-03 | Sửa 1 bit | Flip 1 bit trong file | `INVALID` |
| IT-04 | Sai khóa công khai | Dùng public key của Eve | `INVALID` |
| IT-05 | Sửa chữ ký | Flip 1 byte trong base64 | `INVALID: SIGNATURE_MALFORMED` |
| IT-06 | Sửa metadata | Đổi `signer` trong `.sig` | `INVALID: TBS_MISMATCH` |
| IT-07 | File rỗng | Ký/verify file 0 byte | `VALID` (nếu thiết kế cho phép) |
| IT-08 | File lớn | 50–100 MB | Đúng kết quả, RAM ổn định, thời gian đạt NFR |
| IT-09 | Tên file Unicode | `hợp_đồng_tiếng_việt.pdf` | Ký/verify đúng |
| IT-10 | Package hỏng | JSON rác, base64 sai | Không crash, báo lỗi rõ |
| IT-11 | Sai đường dẫn | File không tồn tại | Thông báo I/O, exit code khác 0 |
| IT-12 | Cross-check | So sánh với `cryptography` | Cùng kết quả valid/invalid |

### 8.3. Quy trình test

```bash
pytest -q                          # unit + integration
python -m src.cli keygen --name alice
python -m src.cli sign --key keys/alice_private.json --file samples/contract.pdf
python -m src.cli verify --key keys/alice_public.json --file samples/contract.pdf --sig samples/contract.pdf.sig
```

- Mỗi test phải độc lập, không dùng khóa thật; dùng fixture khóa test sinh một lần.
- Lưu kết quả test (ảnh chụp/`pytest -v` log) vào `docs/evidence/` để đưa vào báo cáo.

---

## 9. Thiết kế UI

### 9.1. CLI

```text
dsig keygen  --name alice --bits 2048 [--password]
dsig sign    --key keys/alice_private.json --file contract.pdf [--out contract.pdf.sig]
dsig verify  --key keys/alice_public.json --file contract.pdf --sig contract.pdf.sig
dsig inspect --sig contract.pdf.sig
dsig tamper  --file contract.pdf --offset 120 --out contract_tampered.pdf   # chỉ phục vụ demo
```

Exit code: `0` = VALID/thành công, `1` = INVALID, `2` = lỗi sử dụng/IO.

### 9.2. GUI (Tkinter)

- **Tab Keys:** Generate (chọn tên, độ dài khóa), Load, Export public, hiển thị fingerprint; cảnh báo khi xuất private key.
- **Tab Sign:** chọn file, hiển thị SHA-256, signer, nút Sign, chọn nơi lưu `.sig`, log.
- **Tab Verify:** chọn file + `.sig`, nút Verify, banner:
  - Xanh: `✔ CHỮ KÝ HỢP LỆ` + signer + thời gian + fingerprint.
  - Đỏ: `✘ CHỮ KÝ KHÔNG HỢP LỆ` + lý do cụ thể.
- **Tab Demo tấn công:** chọn file → “Sửa 1 byte” → lưu bản bị sửa → hướng dẫn verify để thấy kết quả đỏ.
- Trạng thái disable nút khi thiếu input; không block UI khi hash file lớn (dùng thread hoặc cập nhật progress).

---

## 10. Báo cáo, slide và demo

### 10.1. Cấu trúc báo cáo đề xuất

1. **Giới thiệu** – bài toán phê duyệt tài liệu, rủi ro MitM/giả mạo.
2. **Cơ sở lý thuyết**
   - 2.1. Mã hóa bất đối xứng & RSA (keygen, sign, verify).
   - 2.2. Hash function & 3 tính chất (preimage, second preimage, collision).
   - 2.3. Padding & forgery attack.
   - 2.4. Non-repudiation và giới hạn (vai trò của PKI).
3. **Thiết kế hệ thống** – kiến trúc, luồng, định dạng `.sig`, quyết định thiết kế.
4. **Triển khai** – các module, thuật toán, xử lý lỗi, giao diện.
5. **Kiểm thử & kết quả** – bảng test, ảnh chụp 2 kịch bản, số liệu hiệu năng.
6. **Thảo luận bảo mật** – tấn công đã chống được, chưa chống được (thay public key, side-channel, timestamp).
7. **Kết luận & hướng phát triển** – PKI/CA, CRL, TSA, multi-signature.
8. **Tài liệu tham khảo** – giáo trình, Session 7/8, RFC 8017 (PKCS#1 v2.2).

### 10.2. Hình cần chuẩn bị

- Sơ đồ kiến trúc (chương 4).
- Sơ đồ luồng ký/xác thực.
- Ảnh GUI tab Sign và tab Verify (valid + invalid).
- Biểu đồ/ bảng thời gian hash file 1 MB / 10 MB / 50 MB.
- Ảnh minh họa file bị sửa `1000 → 9000` và banner đỏ.

### 10.3. Kịch bản demo (5–7 phút)

1. Mở tab Keys → generate Alice, chỉ fingerprint.
2. Ký `contract.pdf` → mở `.sig` cho thấy digest + signature.
3. Verify → banner xanh.
4. Tab Demo → sửa nội dung hợp đồng → verify → banner đỏ, nêu `HASH_MISMATCH`.
5. Thử dùng public key của Eve → đỏ.
6. Kết luận: đã chứng minh authentication, integrity, non-repudiation; nêu giới hạn PKI.

---

## 11. Rủi ro và biện pháp giảm thiểu

| Rủi ro | Mức độ | Giảm thiểu |
|---|---|---|
| Keygen 2048-bit chậm trên máy yếu | Trung bình | Dùng Miller-Rabin tối ưu, cache khóa test, cho phép chọn 1024-bit khi demo (ghi rõ không an toàn) |
| Tự cài RSA sai toán học | Cao | Test vector Lab 2/3 + cross-check `cryptography` |
| Padding implement sai → verify fail | Cao | Test vector RFC 8017, kiểm tra từng byte cấu trúc |
| GUI Tkinter lỗi font tiếng Việt | Thấp | Dùng UTF-8, font mặc định; test trên máy demo |
| File PDF bị thay đổi khi mở/lưu | Trung bình | Ghi rõ “ký trên byte gốc”; demo dùng bản copy |
| Hết thời gian | Trung bình | Ưu tiên Must; FR-07/FR-10 cắt được; CLI trước GUI |
| Mất khóa riêng | Thấp | Hướng dẫn backup; không đưa khóa thật lên git |
| Báo cáo thiếu dẫn chứng | Trung bình | Lưu log test/ảnh ngay từ P1 |

---

## 12. Definition of Done

- [ ] Tất cả FR-01 → FR-06, FR-08, FR-09 hoạt động.
- [ ] `pytest -q` pass 100%, có ít nhất 10 unit test + 8 integration test.
- [ ] Demo 2 kịch bản trong pre-project report chạy ổn định, không cần mạng.
- [ ] Không có private key thật trong repo.
- [ ] README hướng dẫn cài đặt/chạy trong < 5 bước.
- [ ] Báo cáo đủ 8 mục, có hình, bảng test, kết quả thực nghiệm.
- [ ] Slide + video demo + biên bản test đã lưu trong `docs/`.
- [ ] Có mục “Hạn chế & hướng phát triển” nêu PKI/CA như pre-project report.

---

## 13. Hướng mở rộng (nếu còn thời gian)

1. **PKI/CA:** CA ký chứng chỉ `(ID_A, k_pub,A)`, thêm verify chain + CRL → giải quyết điểm yếu thay public key (Session 8).
2. **Timestamp Authority:** gửi digest đến TSA, nhận token thời gian thay cho `signed_at` tự khai.
3. **PDF visible signature:** nhúng chữ ký + thông tin signer vào trang PDF.
4. **Multi-signature approval workflow:** nhiều cấp phê duyệt (nhân viên → trưởng phòng → giám đốc), mỗi người ký nối tiếp.
5. **So sánh thuật toán:** cài thêm ElGamal/DSA (Session 7) và so sánh kích thước/chí phí.
6. **Audit log bất biến:** hash-chain log để phát hiện sửa lịch sử phê duyệt.
7. **PSS padding** thay PKCS#1 v1.5 (an toàn hơn, nhưng phức tạp hơn).

---

## 14. Các điểm cần xác nhận với giảng viên/bạn cùng nhóm

1. **Deadline và thời lượng chính xác** (kế hoạch đang giả định 3 tuần).
2. **Có bắt buộc tự cài đặt RSA/SHA hay được dùng thư viện?** (ảnh hưởng P1–P2).
3. **GUI hay Web?** Kế hoạch chọn Tkinter; nếu cần web có thể đổi sang Streamlit/Flask nhưng +2–3 ngày.
4. **Hình thức nộp:** báo cáo PDF + source + video, hay demo trực tiếp?
5. **Làm cá nhân hay nhóm?** Nếu nhóm, phân công: crypto core / GUI / test / báo cáo.
6. **Có yêu cầu so sánh RSA với ElGamal/DSA không?** Nếu có, thêm 1–2 ngày.

---

*Kế hoạch này bám sát pre-project report và nội dung Session 7–8; có thể điều chỉnh thời lượng sau khi chốt deadline.*
