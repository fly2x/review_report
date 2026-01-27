# Code Review: openHiTLS/openhitls#1024
**Reviewer**: CODEX


## Medium

### Base64 output not finalized for AEAD encryption
`apps/src/app_enc.c:1119-1126`
```
if (isAeadId == 1) {
        return HITLS_APP_SUCCESS;
    }
```
**Issue**: For AEAD ciphers, the function returns before calling `EncWriteEncodedFinal`. When `-base64` is used, the encoder still has buffered bytes that need finalization, so the output becomes truncated/invalid and decryption fails.
**Fix**:
```
if (isAeadId == 1) {
        if (encOpt->encTag == HITLS_APP_ENC_TAG_ENC && encOpt->format == HITLS_APP_FORMAT_BASE64) {
            int32_t wret = EncWriteEncodedFinal(encOpt);
            if (wret != HITLS_APP_SUCCESS) {
                return HITLS_APP_UIO_FAIL;
            }
        }
        return HITLS_APP_SUCCESS;
    }
```

---

### Output buffer size can overflow in decryption
`apps/src/app_enc.c:1076-1078`
```
uint32_t outLen = encOpt->cipherBufLen + encOpt->keySet->blockSize;
    uint8_t *resBuf = (uint8_t *)BSL_SAL_Malloc(outLen);
```
**Issue**: `cipherBufLen` is derived from user input; adding `blockSize` without a bounds check can wrap `uint32_t` and allocate a too-small buffer. This risks incorrect decryption or memory corruption if the cipher API writes more than `outLen`.
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
