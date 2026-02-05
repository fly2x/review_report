# Final Code Review Report
## openHiTLS/openhitls - PR #992

### Summary
- **Total Issues**: 11
- **Critical**: 1
- **High**: 5
- **Medium**: 2
- **Low**: 3
- **Reviewers**: claude, gemini, codex

---


## Critical

### Ignored return value of LmsHash in LmOtsGeneratePublicKey
`crypto/lms/src/lms_ots.c:136`
**Reviewers**: GEMINI | **置信度**: 可信
```
LmsHash(publicKey, buffer, LMS_PBLC_PREFIX_LEN + params.p * params.n);
BSL_SAL_FREE(buffer);

return CRYPT_SUCCESS;
```
**Issue**: The return value of `LmsHash` is ignored when generating the public key. If the hash calculation fails (e.g., due to hardware failure or resource exhaustion), the function returns `CRYPT_SUCCESS` but the `publicKey` buffer will contain uninitialized or partial data, leading to a compromised key.
**Fix**:
```
ret = LmsHash(publicKey, buffer, LMS_PBLC_PREFIX_LEN + params.p * params.n);
BSL_SAL_FREE(buffer);

return ret;
```

---


## High

### Ignored return value of LmsHash in LmOtsComputeQ
`crypto/lms/src/lms_ots.c:172`
**Reviewers**: GEMINI | **置信度**: 可信
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
`crypto/lms/src/lms_ots.c:198`
**Reviewers**: GEMINI | **置信度**: 可信
```
(void)memcpy_s(iterBuf + LMS_ITER_PREV_OFFSET, ctx->n, tmp, ctx->n);
LmsHash(tmp, iterBuf, LMS_ITER_LEN(ctx->n));
```
**Issue**: `LmsHash` return value is ignored inside the signature chain generation loop. If any hash step fails, the resulting signature chain `tmp` will be invalid, creating a broken signature.
**Fix**:
```
(void)memcpy_s(iterBuf + LMS_ITER_PREV_OFFSET, ctx->n, tmp, ctx->n);
if (LmsHash(tmp, iterBuf, LMS_ITER_LEN(ctx->n)) != CRYPT_SUCCESS) {
    return CRYPT_LMS_HASH_FAIL;
}
```

---

### Ignored return value of LmsHash in LmOtsValidateChains
`crypto/lms/src/lms_ots.c:288`
**Reviewers**: GEMINI | **置信度**: 可信
```
(void)memcpy_s(iterBuf + LMS_ITER_PREV_OFFSET, ctx->n, tmp, ctx->n);
LmsHash(tmp, iterBuf, LMS_ITER_LEN(ctx->n));
```
**Issue**: `LmsHash` return value is ignored during signature validation chain recomputation. This can lead to incorrect validation results (false positives or false negatives) if the hash function fails.
**Fix**:
```
(void)memcpy_s(iterBuf + LMS_ITER_PREV_OFFSET, ctx->n, tmp, ctx->n);
if (LmsHash(tmp, iterBuf, LMS_ITER_LEN(ctx->n)) != CRYPT_SUCCESS) {
    return CRYPT_LMS_HASH_FAIL;
}
```

---

### Ignored return value of LmsHash in LmOtsValidateSignature
`crypto/lms/src/lms_ots.c:333`
**Reviewers**: GEMINI | **置信度**: 可信
```
LmsHash(computedPubKey, finalBuf, LMS_PBLC_PREFIX_LEN + params.p * params.n);

LmsZeroize(Q, sizeof(Q));
BSL_SAL_FREE(finalBuf);

return CRYPT_SUCCESS;
```
**Issue**: The final hash step to compute the public key candidate in `LmOtsValidateSignature` ignores the return value of `LmsHash`. This can cause incorrect signature validation if the hash fails.
**Fix**:
```
int32_t ret2 = LmsHash(computedPubKey, finalBuf, LMS_PBLC_PREFIX_LEN + params.p * params.n);

LmsZeroize(Q, sizeof(Q));
BSL_SAL_FREE(finalBuf);

return ret2;
```

---

### Wrong height used for HSS tree index calculation
`crypto/lms/src/hss_utils.c:360-362`
**Reviewers**: CODEX | **置信度**: 可信
```
for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
    uint32_t childHeight = para->levelPara[i + 1].height;
    sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << childHeight);
}
```
**Issue**: The loop uses the child height (`para->levelPara[i + 1].height`) instead of the current level height when computing `sigsPerTree[i]`. This miscomputes `treeIndex`/`leafIndex` for non-uniform hierarchies, which can cause LM-OTS key reuse and incorrect capacity tracking. It also lacks overflow checks.
**Fix**:
```
for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
    uint32_t height = para->levelPara[i].height;
    if (height > 63 || sigsPerTree[i + 1] > (UINT64_MAX >> height)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << height);
}
```

---


## Medium

### HSS private-key load leaves stale tree cache
`crypto/lms/src/hss_api.c:373-378`
**Reviewers**: CODEX | **置信度**: 可信
```
int32_t ret = HssDecompressParamSet(ctx->para, compressed);
if (ret != CRYPT_SUCCESS) {
    return ret;
}

return CRYPT_SUCCESS;
```
**Issue**: After loading a new private key via `CRYPT_HSS_SetPrvKey`, cached Merkle trees from the previous key remain marked valid, so signing can reuse stale trees and produce invalid signatures or key reuse.
**Fix**:
```
int32_t ret = HssDecompressParamSet(ctx->para, compressed);
if (ret != CRYPT_SUCCESS) {
    return ret;
}

for (uint32_t i = 0; i < HSS_MAX_LEVELS; i++) {
    if (ctx->cachedTrees[i] != NULL) {
        LmsZeroize(ctx->cachedTrees[i], ctx->cachedTreeSizes[i]);
        BSL_SAL_Free(ctx->cachedTrees[i]);
        ctx->cachedTrees[i] = NULL;
        ctx->cachedTreeSizes[i] = 0;
    }
    ctx->treeCacheValid[i] = false;
}

return CRYPT_SUCCESS;
```

---

### Levels accepted that key format cannot encode
`crypto/lms/src/hss_api.c:191-195`
**Reviewers**: CODEX | **置信度**: 可信
```
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}
ctx->para->levels = levels;
```
**Issue**: The control API allows up to 8 levels (`HSS_MAX_LEVELS`), but the compressed parameter set in the private key only supports 3 levels (`HSS_MAX_COMPRESSED_LEVELS`), so valid configuration can still fail later in keygen or SetPrvKey.
**Fix**:
```
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS || levels > HSS_MAX_COMPRESSED_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}
ctx->para->levels = levels;
```

---


## Low

### Master seed not cleared on root-seed hash failure
`crypto/lms/src/hss_utils.c:284-286`
**Reviewers**: CODEX | **置信度**: 可信
```
int32_t ret = LmsHash(hash, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
if (ret != CRYPT_SUCCESS) {
    return CRYPT_HSS_SEED_DERIVE_FAIL;
}
```
**Issue**: On hash failure, the stack buffer containing `masterSeed` is returned without zeroization, leaving sensitive material in memory.
**Fix**:
```
int32_t ret = LmsHash(hash, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
if (ret != CRYPT_SUCCESS) {
    LmsZeroize(buffer, sizeof(buffer));
    LmsZeroize(hash, sizeof(hash));
    return CRYPT_HSS_SEED_DERIVE_FAIL;
}
```

---

### Master seed not cleared on second hash failure
`crypto/lms/src/hss_utils.c:294-296`
**Reviewers**: CODEX | **置信度**: 可信
```
ret = LmsHash(rootSeed, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
if (ret != CRYPT_SUCCESS) {
    return CRYPT_HSS_SEED_DERIVE_FAIL;
}
```
**Issue**: On the second hash failure in `HssGenerateRootSeed`, the stack buffer containing `masterSeed` is returned without zeroization, leaving sensitive material in memory.
**Fix**:
```
ret = LmsHash(rootSeed, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
if (ret != CRYPT_SUCCESS) {
    LmsZeroize(buffer, sizeof(buffer));
    LmsZeroize(hash, sizeof(hash));
    return CRYPT_HSS_SEED_DERIVE_FAIL;
}
```

---

### HSS compare ignores private seed
`crypto/lms/src/hss_api.c:173-177`
**Reviewers**: CODEX | **置信度**: 可信
```
if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
    // Only compare the counter and parameters, not the secret seed
    if (memcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_SEED_OFFSET) != 0) {
        return CRYPT_HSS_CMP_FALSE;
    }
}
```
**Issue**: Two different private keys with different master seeds can compare equal if public keys are not set, which can lead to incorrect key matching/caching. The comparison only checks the counter and parameters, not the secret seed.
**Fix**:
```
if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
    if (memcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_LEN) != 0) {
        return CRYPT_HSS_CMP_FALSE;
    }
}
```

---
