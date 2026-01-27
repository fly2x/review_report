# Code Review: openHiTLS/openhitls#1024
**Reviewer**: CLAUDE


## High

### Potential integer overflow when casting uint64_t to uint32_t
`apps/src/app_enc.c:647`
```
uint32_t decodedLen = (uint32_t)(readLen / HITLS_APP_ENC_HEX_CHAR_STEP);
```
**Issue**: At line 647, `readLen` is of type `uint64_t` (returned from HITLS_APP_OptReadUio). When dividing by 2 and casting to `uint32_t`, if `readLen` is larger than UINT32_MAX * 2, an integer truncation occurs. This could lead to a buffer overflow attack where a large file causes the decoded buffer to be smaller than expected, while `HITLS_APP_HexToBytes` still reads the full original data.
**Fix**:
```
if (readLen > UINT64_MAX / HITLS_APP_ENC_HEX_CHAR_STEP || (readLen / HITLS_APP_ENC_HEX_CHAR_STEP) > UINT32_MAX) {
    BSL_SAL_FREE(readBuf);
    AppPrintError("enc: Input size too large.\n");
    return HITLS_APP_ENCODE_FAIL;
}
uint32_t decodedLen = (uint32_t)(readLen / HITLS_APP_ENC_HEX_CHAR_STEP);
```

---

### Missing upper bound validation for file size when reading
`apps/src/app_enc.c:632`
```
int32_t ret = HITLS_APP_OptReadUio(encOpt->encUio->rUio, &readBuf, &readLen, UINT64_MAX);
```
**Issue**: At line 632, `HITLS_APP_OptReadUio` is called with `UINT64_MAX` as maxBufLen. For a decryption tool, this allows reading arbitrarily large files which could lead to denial of service through memory exhaustion.
**Fix**:
```
#define HITLS_APP_ENC_MAX_INPUT_SIZE (100 * 1024 * 1024)  // 100MB limit
int32_t ret = HITLS_APP_OptReadUio(encOpt->encUio->rUio, &readBuf, &readLen, HITLS_APP_ENC_MAX_INPUT_SIZE);
```

---

### Potential integer overflow when casting uint64_t to uint32_t
`apps/src/app_enc.c:638`
```
encOpt->decBufLen = (uint32_t)readLen;
```
**Issue**: At line 638, `readLen` (uint64_t) is cast to `uint32_t` without checking if it exceeds UINT32_MAX. On 32-bit systems or with large files, this truncation could lead to buffer overflows.
**Fix**:
```
if (readLen > UINT32_MAX) {
    BSL_SAL_FREE(readBuf);
    AppPrintError("enc: Input size too large.\n");
    return HITLS_APP_ENCODE_FAIL;
}
encOpt->decBufLen = (uint32_t)readLen;
```

---

### Potential integer overflow when casting uint64_t to uint32_t
`apps/src/app_enc.c:666`
```
uint32_t decodedLen = HITLS_BASE64_DECODE_LENGTH((uint32_t)readLen);
```
**Issue**: At line 666, `readLen` (uint64_t) is cast to `uint32_t` without bounds checking. The macro `HITLS_BASE64_DECODE_LENGTH` expects a uint32_t, but readLen is uint64_t.
**Fix**:
```
if (readLen > UINT32_MAX) {
    BSL_SAL_FREE(readBuf);
    AppPrintError("enc: Input size too large.\n");
    return HITLS_APP_ENCODE_FAIL;
}
uint32_t decodedLen = HITLS_BASE64_DECODE_LENGTH((uint32_t)readLen);
```

---


## Medium

### Memory leak when BSL_BASE64_EncodeInit fails
`apps/src/app_enc.c:189`
```
if (BSL_BASE64_EncodeInit(encOpt->b64EncCtx) != BSL_SUCCESS) {
    return HITLS_APP_ENCODE_FAIL;
}
```
**Issue**: At line 189, if `BSL_BASE64_EncodeInit` fails, the function returns an error but `encOpt->b64EncCtx` is not freed. The context was allocated at line 184 and will leak.
**Fix**:
```
if (BSL_BASE64_EncodeInit(encOpt->b64EncCtx) != BSL_SUCCESS) {
    BSL_BASE64_CtxFree(encOpt->b64EncCtx);
    encOpt->b64EncCtx = NULL;
    return HITLS_APP_ENCODE_FAIL;
}
```

---

### Assignment of potentially freed pointer
`apps/src/app_enc.c:638`
```
if (encOpt->format == HITLS_APP_FORMAT_BINARY) {
    encOpt->decBuf = readBuf;
    encOpt->decBufLen = (uint32_t)readLen;
    return HITLS_APP_SUCCESS;
}
...
encOpt->cipherBuf = encOpt->decBuf + offset;  // line 762
```
**Issue**: When `encOpt->format == HITLS_APP_FORMAT_BINARY`, `readBuf` is directly assigned to `encOpt->decBuf` at line 637. However, in `FreeEnc()`, `decBuf` is freed using `BSL_SAL_FREE()` while `cipherBuf` is set to NULL without freeing. The `cipherBuf` at line 762 points to an offset within `decBuf`, so this creates a dangling pointer issue.
**Fix**:
```
// In FreeEnc(), set cipherBuf to NULL before freeing decBuf:
if (encOpt->decBuf != NULL) {
    encOpt->cipherBuf = NULL;  // Clear before freeing
    encOpt->cipherBufLen = 0;
    BSL_SAL_FREE(encOpt->decBuf);
    encOpt->decBuf = NULL;
}
```

---
