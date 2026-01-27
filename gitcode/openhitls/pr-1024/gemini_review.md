# Code Review: openHiTLS/openhitls#1024
**Reviewer**: GEMINI


## Critical

### Breaking change in file format without version increment
`apps/src/app_enc.c:597`
```
#define HITLS_APP_ENC_VERSION 1
// ...
static void WriteUint32Be(uint8_t *buf, uint32_t value)
{
    buf[HITLS_APP_ENC_U32_IDX_0] = (uint8_t)((value >> HITLS_APP_ENC_SHIFT_24) & 0xFFU);
// ...
}
```
**Issue**: The encryption file format has changed from ASCII hex strings to big-endian binary integers (and optionally encoded body), but `HITLS_APP_ENC_VERSION` remains `1`. This breaks backward compatibility: new tools cannot decrypt old files (header parsing will fail or produce garbage), and old tools cannot decrypt new files.
**Fix**:
```
// Increment version to distinguish from legacy format
#define HITLS_APP_ENC_VERSION 2
```

---


## High

### Integer truncation and potential buffer overflow in DecodeInputForDec
`apps/src/app_enc.c:631`
```
if (encOpt->format == HITLS_APP_FORMAT_HEX) {
        if ((readLen % HITLS_APP_ENC_HEX_CHAR_STEP) != 0) {
            BSL_SAL_FREE(readBuf);
            AppPrintError("enc: Invalid hex string length, must be even.\n");
            return HITLS_APP_ENCODE_FAIL;
        }
        uint32_t decodedLen = (uint32_t)(readLen / HITLS_APP_ENC_HEX_CHAR_STEP);
        uint8_t *decoded = (uint8_t *)BSL_SAL_Calloc(decodedLen + 1, 1);
```
**Issue**: `readLen` (uint64_t) is cast to `uint32_t` without checking if it exceeds `UINT32_MAX`. If the input file is larger than 4GB, `readLen` will be truncated, leading to incorrect buffer allocation sizes (e.g., `decodedLen`) and subsequent memory corruption or logic errors. This effectively breaks support for large files and introduces security risks.
**Fix**:
```
if (encOpt->format == HITLS_APP_FORMAT_HEX) {
        if (readLen > UINT32_MAX || (readLen % HITLS_APP_ENC_HEX_CHAR_STEP) != 0) {
            BSL_SAL_FREE(readBuf);
            AppPrintError("enc: Invalid hex string length or file too large.\n");
            return HITLS_APP_ENCODE_FAIL;
        }
        uint32_t decodedLen = (uint32_t)(readLen / HITLS_APP_ENC_HEX_CHAR_STEP);
```

---

### Integer truncation in base64 decoding length calculation
`apps/src/app_enc.c:663`
```
if (encOpt->format == HITLS_APP_FORMAT_BASE64) {
        uint32_t decodedLen = HITLS_BASE64_DECODE_LENGTH((uint32_t)readLen);
        uint8_t *decoded = (uint8_t *)BSL_SAL_Calloc(decodedLen + 1, 1);
```
**Issue**: Similar to the hex case, `readLen` is cast to `uint32_t` before calculating the base64 decode length. If `readLen` exceeds `UINT32_MAX`, the length is truncated, leading to insufficient memory allocation and potential heap corruption during decoding.
**Fix**:
```
if (encOpt->format == HITLS_APP_FORMAT_BASE64) {
        if (readLen > UINT32_MAX) {
            BSL_SAL_FREE(readBuf);
            return HITLS_APP_ENCODE_FAIL;
        }
        uint32_t decodedLen = HITLS_BASE64_DECODE_LENGTH((uint32_t)readLen);
```

---

### Integer overflow in buffer allocation causing heap overflow
`apps/src/app_enc.c:1076`
```
uint32_t outLen = encOpt->cipherBufLen + encOpt->keySet->blockSize;
    uint8_t *resBuf = (uint8_t *)BSL_SAL_Malloc(outLen);
    if (resBuf == NULL) {
```
**Issue**: `outLen` calculation `encOpt->cipherBufLen + encOpt->keySet->blockSize` can overflow if `cipherBufLen` is close to `UINT32_MAX`. This would result in `BSL_SAL_Malloc` allocating a small buffer, while `CRYPT_EAL_CipherUpdate` writes the full decrypted output, causing a heap buffer overflow.
**Fix**:
```
if (encOpt->cipherBufLen > UINT32_MAX - encOpt->keySet->blockSize) {
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    uint32_t outLen = encOpt->cipherBufLen + encOpt->keySet->blockSize;
    uint8_t *resBuf = (uint8_t *)BSL_SAL_Malloc(outLen);
```

---


## Medium

### Regression in large file support (Decryption)
`apps/src/app_enc.c:629`
```
static int32_t DecodeInputForDec(EncCmdOpt *encOpt)
{
    uint8_t *readBuf = NULL;
    uint64_t readLen = 0;
    int32_t ret = HITLS_APP_OptReadUio(encOpt->encUio->rUio, &readBuf, &readLen, UINT64_MAX);
```
**Issue**: The new decryption implementation (`DoCipherUpdateDec` relying on `DecodeInputForDec`) reads the *entire* input file into memory using `HITLS_APP_OptReadUio` (with `UINT64_MAX` limit). This causes denial of service (OOM) for large files that fit in the previous streaming implementation. Encryption (`DoCipherUpdateEnc`) still appears to support streaming.
**Fix**:
```
// Restore streaming processing for decryption, or strictly limit input size and document the limitation.
// Ideally, implement a streaming decoder for Hex/Base64 to feed the cipher update loop.
```

---


## Low

### Typo in constant name HILTS_APP_FORMAT_UNDEF
`apps/src/app_enc.c:376`
```
if (encOpt->format == HILTS_APP_FORMAT_UNDEF) {
        encOpt->format = HITLS_APP_FORMAT_BINARY;
    }
```
**Issue**: The constant `HILTS_APP_FORMAT_UNDEF` contains a typo (`HILTS` instead of `HITLS`). While this matches the definition in `apps/include/app_opt.h`, it is inconsistent with other constants like `HITLS_APP_FORMAT_HEX` and the project naming convention.
**Fix**:
```
if (encOpt->format == HITLS_APP_FORMAT_UNDEF) { // Requires fixing header definition as well
        encOpt->format = HITLS_APP_FORMAT_BINARY;
    }
```

---
