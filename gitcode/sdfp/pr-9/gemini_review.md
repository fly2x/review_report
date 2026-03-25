# Code Review: openHiTLS/sdfp#9
**Reviewer**: GEMINI


## Critical

### Buffer overflow in SM4-GCM encryption finalization
`src/sm4/sm4_gcm.c:221-225`
```
if (*outLen < tagOutLen) {
            return CRYPT_INVALID_ARG;
        }
        /* AuthEncFinal outputs remaining ciphertext bytes into [out, tmpLen) */
        ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
```
**Issue**: When calling `SDF_DL_AuthEncFinal`, `tmpLen` is initialized to the full buffer capacity (`*outLen`). The hardware might write up to `tmpLen` bytes into the `out` buffer. The code then appends `tagOutLen` bytes (the GCM authentication tag) starting at `out + tmpLen`. If the total written length plus the tag length exceeds `*outLen`, a buffer overflow occurs. The available capacity for `AuthEncFinal` must be reduced by `tagOutLen`.
**Fix**:
```
if (*outLen < tagOutLen) {
            return CRYPT_INVALID_ARG;
        }
        tmpLen = *outLen - tagOutLen;
        /* AuthEncFinal outputs remaining ciphertext bytes into [out, tmpLen) */
        ret = SDF_DL_AuthEncFinal(ctx->hSessionHandle, out, &tmpLen, ctx->tag, &tagOutLen);
```

---


## Medium

### Resource leak of temporary key handle during DEK generation
`src/sm4/sm4_cipher.c:266-269`
```
void *hTmpKey = NULL;
            ret = SDF_DL_GenerateKeyWithKEK(hTmpSession, 128, SGD_SM4_ECB,
                ctx->kekIndex, wrapBuf, &wrapLen, &hTmpKey);
            (void)SDF_DL_CloseSession(hTmpSession);
```
**Issue**: The code calls `SDF_DL_GenerateKeyWithKEK` to create a new session key, which yields a hardware key handle (`hTmpKey`). It then immediately closes `hTmpSession` without explicitly destroying the generated key handle via `SDF_DL_DestroyKey`. Although closing the session might implicitly drop session resources in some implementations, it can cause memory or resource leaks inside the HSM or driver on strict SDF device implementations. The key handle must be destroyed properly.
**Fix**:
```
void *hTmpKey = NULL;
            ret = SDF_DL_GenerateKeyWithKEK(hTmpSession, 128, SGD_SM4_ECB,
                ctx->kekIndex, wrapBuf, &wrapLen, &hTmpKey);
            if (ret == SDR_OK && hTmpKey != NULL) {
                (void)SDF_DL_DestroyKey(hTmpSession, hTmpKey);
            }
            (void)SDF_DL_CloseSession(hTmpSession);
```

---
