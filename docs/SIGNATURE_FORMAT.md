# Đặc tả định dạng chữ ký DSIG/1

Tài liệu này mô tả chính xác thứ được ký, định dạng tệp `.sig`, thứ tự xác thực và các mã lỗi ổn định của dự án. Mọi thay đổi phá vỡ tương thích phải tăng phiên bản (`DSIG/2`, `RSA-PRIV-ENC/2`, …).

## 1. Tổng quan

Một chữ ký gồm hai phần:

1. **TBS** (*to-be-signed*) — chuỗi byte canonical chứa toàn bộ metadata phê duyệt.
2. **Signature** — `RSA-PKCS1v15-SHA256(private_key, SHA-256(TBS))`, dài đúng bằng modulus (256 byte với RSA-2048).

Package `.sig` là JSON UTF-8 chứa metadata, fingerprint khóa công khai và chữ ký. Chữ ký **không** ký trực tiếp nội dung JSON, mà ký TBS được dựng lại từ các trường metadata. Vì vậy thay đổi khoảng trắng/format JSON không làm hỏng chữ ký, nhưng thay đổi bất kỳ trường metadata nào cũng bị phát hiện.

## 2. TBS

### 2.1. Layout

Tất cả số nguyên dùng **big-endian**. Chuỗi dùng **UTF-8**. Mọi trường biến độ dài đều có tiền tố `u32` là độ dài tính bằng byte.

| Thứ tự | Trường | Kiểu | Ghi chú |
|---|---|---|---|
| 1 | Domain separator | `9 byte` | `b"DSIGv1\x00"` (cố định) |
| 2 | `algorithm` | `u32 len` + UTF-8 | Luôn `RSA-PKCS1v15-SHA256` ở phiên bản này |
| 3 | `signer` | `u32 len` + UTF-8 | Chuẩn hóa NFC, trim, không ký tự điều khiển |
| 4 | `original_name` | `u32 len` + UTF-8 | Basename, chuẩn hóa NFC, không `/`, `\`, `.`, `..` |
| 5 | `size` | `u64` | Kích thước tài liệu, `0 ≤ size < 2^64` |
| 6 | `signed_at` | `u32 len` + UTF-8 | ISO-8601 UTC dạng `YYYY-MM-DDTHH:MM:SSZ` |
| 7 | `file_digest` | `32 byte` | `SHA-256(document bytes)` thô |

Công thức:

```text
TBS = b"DSIGv1\x00"
   || u32(len(algorithm)) || algorithm
   || u32(len(signer))    || signer
   || u32(len(original_name)) || original_name
   || u64(size)
   || u32(len(signed_at)) || signed_at
   || SHA-256(document)
```

### 2.2. Ví dụ dựng TBS

```python
from src.services.tbs import build_tbs

tbs = build_tbs(
    algorithm="RSA-PKCS1v15-SHA256",
    signer="Nguyễn Văn A",
    original_name="contract.pdf",
    size=1234,
    signed_at="2026-11-11T10:00:00Z",
    file_digest=bytes.fromhex("d3929c36..."),
)
signature = sign_bytes(private_key, tbs)   # ký SHA-256(tbs)
```

> `sign_bytes` băm đầu vào bằng SHA-256 rồi áp dụng EMSA-PKCS1-v1_5. Không truyền `SHA-256(TBS)` vào `sign_bytes` (sẽ bị băm hai lần).

### 2.3. Vì sao dùng length-prefix và domain separator

- **Chống nhập nhằng**: nếu nối chuỗi thô, `(signer="ab", name="c")` và `(signer="a", name="bc")` cho cùng byte. Length-prefix làm hai trường hợp khác nhau.
- **Chống tái sử dụng ngữ cảnh**: `DSIGv1\0` đảm bảo TBS của giao thức này không thể trùng với dữ liệu ký ở nơi khác.
- **Tất định**: cùng metadata → cùng TBS, nên có thể kiểm tra lại ở mọi nền tảng.

### 2.4. Chuẩn hóa trước khi ký

| Trường | Quy tắc |
|---|---|
| `signer` | Unicode NFC, `strip()`, không rỗng, không ký tự `< 0x20` hoặc `0x7F` |
| `original_name` | Unicode NFC, không rỗng, là basename, không `/` `\`, không `.`/`..` |
| `signed_at` | Bắt buộc có offset; đổi về UTC, bỏ microsecond, hậu tố `Z` |
| `size` | Số nguyên thật (không `bool`), `0 ≤ size < 2^64` |
| `file_digest` | Đúng 32 byte |

Hai biểu diễn tương đương (NFC/NFD, `+07:00`/`Z`) tạo ra cùng TBS, nên chữ ký vẫn hợp lệ sau khi chuẩn hóa.

## 3. Package `.sig`

### 3.1. Schema

| Khóa | Kiểu | Bắt buộc | Ràng buộc |
|---|---|---|---|
| `format` | string | ✅ | `"DSIG/1"` |
| `algorithm` | string | ✅ | `"RSA-PKCS1v15-SHA256"` |
| `signer` | string | ✅ | Như §2.4 |
| `key_fingerprint` | string | ✅ | `sha256:` + 64 hex thường |
| `file.original_name` | string | ✅ | Như §2.4 |
| `file.size` | integer | ✅ | `0 ≤ size < 2^64` |
| `file.sha256` | string | ✅ | 64 hex thường |
| `signed_at` | string | ✅ | UTC `...Z` |
| `signature` | string | ✅ | base64url **không padding**, không rỗng |

Tệp được ghi bằng UTF-8, JSON 2-space indent, kết thúc bằng newline. Trường lạ bị bỏ qua khi đọc; trường thiếu hoặc sai kiểu bị từ chối.

### 3.2. Ví dụ đầy đủ

```json
{
  "format": "DSIG/1",
  "algorithm": "RSA-PKCS1v15-SHA256",
  "signer": "Nguyen Van A",
  "key_fingerprint": "sha256:8134b78ee866cb1e5af0fc10ff19272030cf7a5ca3089eb28d4fb800fa140183",
  "file": {
    "original_name": "contract.pdf",
    "size": 12,
    "sha256": "d3929c3656b08888f077bbe3b8276bf356dd935b7f35509f58b35b1576388672"
  },
  "signed_at": "2026-11-11T10:00:00Z",
  "signature": "eDPTE2OP-VlNG4xL4rc54YnzArNZQ1L0TZRKfilaTJLAj3o_nDNKjOZrQ45TCokBeUOw3oUrN4yZH9aKqC24urNv8_koaqaeAK6YzFxE-5CykdtvnT8gagjYvlHEtfgXhls9X14MjigGrx6ssrbZ276R0FTqdZ-VktXdEQ1JxLz7yUwjdWENps6lPDp_rrvcKO5G_yuWKAEoGoMsuwh6fPPNlzEGeEnVmY5YYkOSumaTKWeZThs-5XVoRWM4oP_ZRpFNaVRw_1badwb92oFc3z4Ee2AazHi9OB_76Ocz2mii2E0CyuHtXrI_Nlh1kiHbOgyVtYCdMKZrW5aJY4MMVQ"
}
```

Tên mặc định của package là `<tên_tài_liệu>.sig`, ví dụ `contract.pdf.sig`. Có thể chỉ định đường dẫn khác bằng `SignService.sign_file(..., output_path=...)`.

### 3.3. Không chứa gì

Package **không** chứa khóa riêng, `d`, `p`, `q`, `dp`, `dq` hay `qinv`. Chỉ fingerprint khóa công khai được công bố.

## 4. Quy trình xác thực

### 4.1. Thứ tự kiểm tra

| Bước | Kiểm tra | Mã lỗi khi thất bại |
|---|---|---|
| 1 | Đọc và parse package | `PACKAGE_NOT_FOUND`, `PACKAGE_READ_ERROR`, `PACKAGE_MALFORMED`, `UNSUPPORTED_ALGORITHM` |
| 2 | `expected_signer` (nếu có) | `SIGNER_MISMATCH` |
| 3 | Fingerprint khóa công khai | `KEY_MISMATCH` |
| 4 | Tài liệu tồn tại và là file | `FILE_NOT_FOUND`, `FILE_READ_ERROR` |
| 5 | Kích thước tài liệu | `SIZE_MISMATCH` |
| 6 | SHA-256 tài liệu | `HASH_MISMATCH` |
| 7 | Dựng lại TBS và kiểm tra chữ ký | `SIGNATURE_MALFORMED`, `PADDING_INVALID`, `TBS_MISMATCH` |
| 8 | Thành công | `VALID` |

Thứ tự này báo lỗi sớm nhất có thể và tránh thực hiện phép toán RSA khi tài liệu rõ ràng đã sai.

### 4.2. Kiểm tra chữ ký

```text
EM = RSA_public(signature)                    # phép mũ công khai
EM phải có dạng: 00 01 FF...FF 00 DigestInfo(SHA-256) digest
digest phải bằng SHA-256(TBS)
```

- Độ dài chữ ký khác kích thước modulus hoặc `signature ≥ n` → `SIGNATURE_MALFORMED`.
- Header/PS/separator/DigestInfo sai → `PADDING_INVALID`.
- Padding hợp lệ nhưng digest khác → `TBS_MISMATCH` (metadata hoặc chữ ký bị sửa).

### 4.3. Kết quả

`VerificationResult` là dataclass bất biến:

```python
VerificationResult(
    valid: bool,
    reason: VerificationReason,
    message: str,
    signer: str | None,
    original_name: str | None,
    signed_at: str | None,
    key_fingerprint: str | None,
)
```

`bool(result)` trả về `valid`; `result.as_dict()` dùng được trực tiếp cho JSON CLI/GUI.

## 5. Mã lỗi

| Mã | Lớp phát sinh | Ý nghĩa |
|---|---|---|
| `VALID` | — | Hợp lệ |
| `PACKAGE_NOT_FOUND` | `FileNotFoundError` | Không có tệp `.sig` |
| `PACKAGE_READ_ERROR` | `OSError` khác | Không đọc được (thư mục, quyền, I/O) |
| `PACKAGE_MALFORMED` | `PackageError` | JSON/UTF-8/schema sai |
| `UNSUPPORTED_ALGORITHM` | `UnsupportedAlgorithmError` | Thuật toán ký không hỗ trợ |
| `KEY_MISMATCH` | — | Sai khóa công khai |
| `SIGNER_MISMATCH` | — | Sai người ký mong đợi |
| `FILE_NOT_FOUND` | `FileNotFoundError` | Không có tài liệu |
| `FILE_READ_ERROR` | `OSError` | Không đọc được tài liệu |
| `SIZE_MISMATCH` | — | Kích thước khác metadata |
| `HASH_MISMATCH` | — | Nội dung đã đổi |
| `SIGNATURE_MALFORMED` | `SignatureFormatError`/`ValueError` | Chữ ký sai định dạng |
| `PADDING_INVALID` | `PaddingError` | EMSA-PKCS1-v1_5 hỏng |
| `TBS_MISMATCH` | — | Digest khôi phục khác `SHA-256(TBS)` |

Ánh xạ ngoại lệ → mã lỗi nằm trong `src/services/verify_service.py`; thông điệp tiếng Việt nằm trong `src/models/verification.py`.

## 6. Định dạng khóa

### 6.1. Khóa công khai — `RSA-PUB/1`

```json
{
  "format": "RSA-PUB/1",
  "n": "…thập phân…",
  "e": 65537,
  "fingerprint": "sha256:…64 hex…"
}
```

`fingerprint` được kiểm tra lại khi nạp; nếu không khớp nội dung, file bị từ chối.

### 6.2. Khóa riêng — `RSA-PRIV/1`

```json
{
  "format": "RSA-PRIV/1",
  "n": "…", "e": 65537,
  "d": "…", "p": "…", "q": "…",
  "dp": "…", "dq": "…", "qinv": "…",
  "public_fingerprint": "sha256:…"
}
```

Các tham số CRT được kiểm tra nhất quán khi nạp (`dp = d mod (p-1)`, `dq = d mod (q-1)`, `qinv = q⁻¹ mod p`).

### 6.3. Khóa riêng có mật khẩu — `RSA-PRIV-ENC/1`

```json
{
  "format": "RSA-PRIV-ENC/1",
  "kdf": "PBKDF2-HMAC-SHA256",
  "iterations": 200000,
  "salt": "…base64url…",
  "nonce": "…base64url…",
  "ciphertext": "…base64url…",
  "tag": "…base64url…",
  "public_fingerprint": "sha256:…"
}
```

- `salt` 16 byte, `nonce` 12 byte, `tag` 16 byte.
- Khóa AES-256 dài 32 byte = PBKDF2-HMAC-SHA256(password UTF-8, salt, 200.000 vòng).
- AES-256-GCM, AAD = `b"RSA-PRIV-ENC/1" || fingerprint`.
- Khi giải mã, fingerprint của khóa phải khớp `public_fingerprint`.
- Số vòng lặp hợp lệ khi nạp: `10.000 … 2.000.000`.

### 6.4. Tên khóa và quyền tệp

- Tên khóa khớp `[A-Za-z0-9][A-Za-z0-9._-]{0,63}`.
- `keys/<name>_private.json` → mode `0o600`.
- `keys/<name>_public.json` → mode `0o644`.
- Package `.sig` → mode `0o644`.
- Mọi lần ghi dùng temp file cùng thư mục + `os.replace` (atomic), có `fsync`.

## 7. Phiên bản và tương thích

- `format` và `algorithm` là một phần của TBS. Đổi một trong hai bắt buộc phát hành phiên bản mới; verifier cũ sẽ trả `PACKAGE_MALFORMED` (format lạ) hoặc `UNSUPPORTED_ALGORITHM` (thuật toán lạ) thay vì chấp nhận mù.
- Thêm trường **không** làm thay đổi TBS (ví dụ ghi chú hiển thị) là thay đổi tương thích; thêm trường **có** trong TBS là thay đổi phá vỡ.
- Không bao giờ bỏ qua lỗi padding hoặc so sánh digest không hằng thời gian.
