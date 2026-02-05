# Code Review: openHiTLS/openhitls#992
**Reviewer**: GEMINI


## Critical

### Ignored return value of LmsHash in LmOtsGeneratePublicKey
`crypto/lms/src/lms_ots.c:135`
```
LmsHash(publicKey, buffer, LMS_PBLC_PREFIX_LEN + params.p * params.n);
    BSL_SAL_FREE(buffer);

    return CRYPT_SUCCESS;
```
**Issue**: The return value of `LmsHash` is ignored. If the hash calculation fails (e.g., due to hardware failure or resource exhaustion), the function returns `CRYPT_SUCCESS` but the `publicKey` buffer will contain uninitialized or partial data, leading to a compromised key.
**Fix**:
```
ret = LmsHash(publicKey, buffer, LMS_PBLC_PREFIX_LEN + params.p * params.n);
    BSL_SAL_FREE(buffer);

    return ret;
```

---


## High

### Ignored return value of LmsHash in LmOtsComputeQ
`crypto/lms/src/lms_ots.c:171`
```
LmsHash(Q, prefix, LMS_MESG_PREFIX_LEN(ctx->n) + messageLen);
    BSL_SAL_FREE(prefix);

    LmsPutBigendian(&Q[ctx->n], LmOtsComputeChecksum(Q, ctx->n, ctx->w, ctx->ls), LMS_CHECKSUM_LEN);
    return CRYPT_SUCCESS;
```
**Issue**: The return value of `LmsHash` is ignored when computing the message digest `Q`. Failure to compute the hash correctly will result in an invalid signature or verification failure, but the function proceeds as if successful.
**Fix**:
```
int32_t ret = LmsHash(Q, prefix, LMS_MESG_PREFIX_LEN(ctx->n) + messageLen);
    BSL_SAL_FREE(prefix);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    LmsPutBigendian(&Q[ctx->n], LmOtsComputeChecksum(Q, ctx->n, ctx->w, ctx->ls), LMS_CHECKSUM_LEN);
    return CRYPT_SUCCESS;
```

---

### Ignored return value of LmsHash in LmOtsSignChains
`crypto/lms/src/lms_ots.c:197`
```
(void)memcpy_s(iterBuf + LMS_ITER_PREV_OFFSET, ctx->n, tmp, ctx->n);
            LmsHash(tmp, iterBuf, LMS_ITER_LEN(ctx->n));
        }

        (void)memcpy_s(&signature[LMS_TYPE_LEN + ctx->n + ctx->n * i], ctx->n, tmp, ctx->n);
```
**Issue**: `LmsHash` return value is ignored inside the signature chain generation loop. If any hash step fails, the resulting signature chain `tmp` will be invalid, creating a broken signature.
**Fix**:
```
(void)memcpy_s(iterBuf + LMS_ITER_PREV_OFFSET, ctx->n, tmp, ctx->n);
            if (LmsHash(tmp, iterBuf, LMS_ITER_LEN(ctx->n)) != CRYPT_SUCCESS) {
                return CRYPT_LMS_HASH_FAIL;
            }
        }

        (void)memcpy_s(&signature[LMS_TYPE_LEN + ctx->n + ctx->n * i], ctx->n, tmp, ctx->n);
```

---

### Ignored return value of LmsHash in LmOtsValidateChains
`crypto/lms/src/lms_ots.c:289`
```
(void)memcpy_s(iterBuf + LMS_ITER_PREV_OFFSET, ctx->n, tmp, ctx->n);
            LmsHash(tmp, iterBuf, LMS_ITER_LEN(ctx->n));
        }

        (void)memcpy_s(finalBuf + LMS_PBLC_PREFIX_LEN + i * ctx->n, ctx->n, tmp, ctx->n);
```
**Issue**: `LmsHash` return value is ignored during signature validation chain recomputation. This can lead to incorrect validation results (false positives or false negatives) if the hash function fails.
**Fix**:
```
(void)memcpy_s(iterBuf + LMS_ITER_PREV_OFFSET, ctx->n, tmp, ctx->n);
            if (LmsHash(tmp, iterBuf, LMS_ITER_LEN(ctx->n)) != CRYPT_SUCCESS) {
                return CRYPT_LMS_HASH_FAIL;
            }
        }

        (void)memcpy_s(finalBuf + LMS_PBLC_PREFIX_LEN + i * ctx->n, ctx->n, tmp, ctx->n);
```

---

### Ignored return value of LmsHash in LmOtsValidateSignature
`crypto/lms/src/lms_ots.c:333`
```
LmsHash(computedPubKey, finalBuf, LMS_PBLC_PREFIX_LEN + params.p * params.n);

    LmsZeroize(Q, sizeof(Q));
    BSL_SAL_FREE(finalBuf);

    return CRYPT_SUCCESS;
```
**Issue**: The final hash step to compute the public key candidate in `LmOtsValidateSignature` ignores the return value of `LmsHash`.
**Fix**:
```
int32_t ret2 = LmsHash(computedPubKey, finalBuf, LMS_PBLC_PREFIX_LEN + params.p * params.n);

    LmsZeroize(Q, sizeof(Q));
    BSL_SAL_FREE(finalBuf);

    return ret2;
```

---


## Medium

### Incorrect memory free macro BSL_SAL_Free
`crypto/lms/src/hss_core.c:188`
```
ret = HssSignChildPubKey(&parentOutput, signCtx, parent, childPubKey, cache);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(parentSig);
        return ret;
    }

    (void)memcpy_s(output->data, *output->len, parentSig, parentSigLen);
    (void)memcpy_s(output->data + parentSigLen, *output->len - parentSigLen, childPubKey, LMS_PUBKEY_LEN);
    *output->len = parentSigLen + LMS_PUBKEY_LEN;

    BSL_SAL_Free(parentSig);
    return CRYPT_SUCCESS;
}
```
**Issue**: The code uses `BSL_SAL_Free` (mixed case) instead of `BSL_SAL_FREE` (screaming snake case), which is used consistently elsewhere in the project and in `lms_core.c`. This is likely a compilation or linking error if the mixed-case alias doesn't exist.
**Fix**:
```
ret = HssSignChildPubKey(&parentOutput, signCtx, parent, childPubKey, cache);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_FREE(parentSig);
        return ret;
    }

    (void)memcpy_s(output->data, *output->len, parentSig, parentSigLen);
    (void)memcpy_s(output->data + parentSigLen, *output->len - parentSigLen, childPubKey, LMS_PUBKEY_LEN);
    *output->len = parentSigLen + LMS_PUBKEY_LEN;

    BSL_SAL_FREE(parentSig);
    return CRYPT_SUCCESS;
}
```

---

### Incorrect memory free macro BSL_SAL_Free
`crypto/lms/src/hss_api.c:36`
```
ctx->para = (HSS_Para *)BSL_SAL_Calloc(1, sizeof(HSS_Para));
    if (ctx->para == NULL) {
        BSL_SAL_Free(ctx);
        return NULL;
    }
```
**Issue**: `BSL_SAL_Free` is used instead of the standard `BSL_SAL_FREE`. This occurs multiple times in this file.
**Fix**:
```
ctx->para = (HSS_Para *)BSL_SAL_Calloc(1, sizeof(HSS_Para));
    if (ctx->para == NULL) {
        BSL_SAL_FREE(ctx);
        return NULL;
    }
```

---

### Incorrect memory free macro BSL_SAL_Free in CRYPT_HSS_NewCtx
`crypto/lms/src/hss_api.c:46`
```
if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
        if (ctx->publicKey != NULL) {
            BSL_SAL_Free(ctx->publicKey);
        }
        if (ctx->privateKey != NULL) {
            BSL_SAL_Free(ctx->privateKey);
        }
        BSL_SAL_Free(ctx->para);
        BSL_SAL_Free(ctx);
        return NULL;
    }
```
**Issue**: `BSL_SAL_Free` is used instead of `BSL_SAL_FREE`.
**Fix**:
```
if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
        if (ctx->publicKey != NULL) {
            BSL_SAL_FREE(ctx->publicKey);
        }
        if (ctx->privateKey != NULL) {
            BSL_SAL_FREE(ctx->privateKey);
        }
        BSL_SAL_FREE(ctx->para);
        BSL_SAL_FREE(ctx);
        return NULL;
    }
```

---

### Incorrect memory free macro BSL_SAL_Free in CRYPT_HSS_FreeCtx
`crypto/lms/src/hss_api.c:87`
```
if (ctx->privateKey != NULL) {
        LmsZeroize(ctx->privateKey, HSS_PRVKEY_LEN);
        BSL_SAL_Free(ctx->privateKey);
    }

    if (ctx->publicKey != NULL) {
        BSL_SAL_Free(ctx->publicKey);
    }

    if (ctx->para != NULL) {
        LmsZeroize(ctx->para, sizeof(HSS_Para));
        BSL_SAL_Free(ctx->para);
    }

    // Free cached trees
    for (uint32_t i = 0; i < HSS_MAX_LEVELS; i++) {
        if (ctx->cachedTrees[i] != NULL) {
            LmsZeroize(ctx->cachedTrees[i], ctx->cachedTreeSizes[i]);
            BSL_SAL_Free(ctx->cachedTrees[i]);
        }
    }

    BSL_SAL_Free(ctx);
```
**Issue**: `BSL_SAL_Free` is used consistently throughout `CRYPT_HSS_FreeCtx`.
**Fix**:
```
if (ctx->privateKey != NULL) {
        LmsZeroize(ctx->privateKey, HSS_PRVKEY_LEN);
        BSL_SAL_FREE(ctx->privateKey);
    }

    if (ctx->publicKey != NULL) {
        BSL_SAL_FREE(ctx->publicKey);
    }

    if (ctx->para != NULL) {
        LmsZeroize(ctx->para, sizeof(HSS_Para));
        BSL_SAL_FREE(ctx->para);
    }

    // Free cached trees
    for (uint32_t i = 0; i < HSS_MAX_LEVELS; i++) {
        if (ctx->cachedTrees[i] != NULL) {
            LmsZeroize(ctx->cachedTrees[i], ctx->cachedTreeSizes[i]);
            BSL_SAL_FREE(ctx->cachedTrees[i]);
        }
    }

    BSL_SAL_FREE(ctx);
```

---
