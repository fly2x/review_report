# Final Code Review Report
## openHiTLS/openhitls - PR #1024

### Summary
- **Total Issues**: 5
- **Critical**: 0
- **High**: 2
- **Medium**: 3
- **Low**: 0
- **Reviewers**: claude, gemini, codex

---


## High

### Missing bounds checks when downcasting readLen to uint32_t
`apps/src/app_enc.c:636-667`
**Reviewers**: CLAUDE, GEMINI | **置信度**: 可信
```
if (encOpt->format == HITLS_APP_FORMAT_BINARY) {
    encOpt->decBuf = readBuf;
    encOpt->decBufLen = (uint32_t)readLen;
    return HITLS_APP_SUCCESS;
}
...
uint32_t decodedLen = (uint32_t)(readLen / HITLS_APP_ENC_HEX_CHAR_STEP);
...
uint32_t decodedLen = HITLS_BASE64_DECODE_LENGTH((uint32_t)readLen);
```
**Issue**: readLen is uint64_t but is truncated to uint32_t for binary, hex, and base64 paths without validating size. This can allocate undersized buffers and lead to incorrect decoding or memory corruption when inputs exceed UINT32_MAX.
**Fix**:
```
if (readLen > UINT32_MAX) {
    BSL_SAL_FREE(readBuf);
    AppPrintError("enc: Input size too large.\n");
    return HITLS_APP_ENCODE_FAIL;
}
if (encOpt->format == HITLS_APP_FORMAT_HEX) {
    if ((readLen % HITLS_APP_ENC_HEX_CHAR_STEP) != 0 ||
        (readLen / HITLS_APP_ENC_HEX_CHAR_STEP) > UINT32_MAX) {
        BSL_SAL_FREE(readBuf);
        AppPrintError("enc: Invalid hex string length or file too large.\n");
        return HITLS_APP_ENCODE_FAIL;
    }
    uint32_t decodedLen = (uint32_t)(readLen / HITLS_APP_ENC_HEX_CHAR_STEP);
}
if (encOpt->format == HITLS_APP_FORMAT_BASE64) {
    uint32_t decodedLen = HITLS_BASE64_DECODE_LENGTH((uint32_t)readLen);
}
```

---

### Potential overflow when computing decryption output buffer size
`apps/src/app_enc.c:1076-1077`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
uint32_t outLen = encOpt->cipherBufLen + encOpt->keySet->blockSize;
uint8_t *resBuf = (uint8_t *)BSL_SAL_Malloc(outLen);
```
**Issue**: Adding blockSize to cipherBufLen can wrap uint32_t, resulting in a too-small allocation and potential heap overflow during CRYPT_EAL_CipherUpdate.
**Fix**:
```
if (encOpt->cipherBufLen > UINT32_MAX - encOpt->keySet->blockSize) {
    AppPrintError("enc: Input too large.\n");
    return HITLS_APP_UIO_FAIL;
}
uint32_t outLen = encOpt->cipherBufLen + encOpt->keySet->blockSize;
uint8_t *resBuf = (uint8_t *)BSL_SAL_Malloc(outLen);
```

---


## Medium

### Unbounded read allows memory exhaustion during decryption
`apps/src/app_enc.c:632`
**Reviewers**: CLAUDE, GEMINI | **置信度**: 可信
```
int32_t ret = HITLS_APP_OptReadUio(encOpt->encUio->rUio, &readBuf, &readLen, UINT64_MAX);
```
**Issue**: Decryption reads the entire input into memory with a UINT64_MAX cap, enabling OOM/DoS on large inputs and removing any practical size guard.
**Fix**:
```
#define HITLS_APP_ENC_MAX_INPUT_SIZE (100U * 1024U * 1024U) /* example limit */
int32_t ret = HITLS_APP_OptReadUio(encOpt->encUio->rUio, &readBuf, &readLen, HITLS_APP_ENC_MAX_INPUT_SIZE);
```

---

### Base64 encoder context leak on initialization failure
`apps/src/app_enc.c:184-190`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
encOpt->b64EncCtx = BSL_BASE64_CtxNew();
...
if (BSL_BASE64_EncodeInit(encOpt->b64EncCtx) != BSL_SUCCESS) {
    return HITLS_APP_ENCODE_FAIL;
}
```
**Issue**: If BSL_BASE64_EncodeInit fails, the allocated context is not freed, leaking memory.
**Fix**:
```
if (BSL_BASE64_EncodeInit(encOpt->b64EncCtx) != BSL_SUCCESS) {
    BSL_BASE64_CtxFree(encOpt->b64EncCtx);
    encOpt->b64EncCtx = NULL;
    return HITLS_APP_ENCODE_FAIL;
}
```

---

### Base64 output not finalized for AEAD encryption
`apps/src/app_enc.c:1119-1125`
**Reviewers**: CODEX | **置信度**: 较可信
```
if (isAeadId == 1) {
    return HITLS_APP_SUCCESS;
}
```
**Issue**: AEAD paths return early and skip EncWriteEncodedFinal, leaving buffered Base64 data unflushed and producing truncated/invalid output.
**Fix**:
```
if (isAeadId == 1) {
    if (encOpt->encTag == HITLS_APP_ENC_TAG_ENC &&
        encOpt->format == HITLS_APP_FORMAT_BASE64) {
        if (EncWriteEncodedFinal(encOpt) != HITLS_APP_SUCCESS) {
            return HITLS_APP_UIO_FAIL;
        }
    }
    return HITLS_APP_SUCCESS;
}
```

---
