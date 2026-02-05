# Code Review: openHiTLS/openhitls#992
**Reviewer**: CODEX


## High

### Wrong Height Used For HSS Tree Index Calculation
`crypto/lms/src/hss_utils.c:355-362`
```
for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
    uint32_t childHeight = para->levelPara[i + 1].height;
    sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << childHeight);
}
```
**Issue**: I can see why you computed `sigsPerTree` this way, but using the child height here miscomputes `treeIndex`/`leafIndex` for non-uniform hierarchies, which can cause LM-OTS key reuse and incorrect capacity tracking; it also lacks overflow checks.
**Fix**:
```
uint32_t bottomHeight = para->levelPara[para->levels - 1].height;
if (bottomHeight > LMS_MAX_SAFE_HEIGHT_FOR_UINT64) {
    return CRYPT_HSS_INVALID_PARAM;
}
sigsPerTree[para->levels - 1] = 1ULL << bottomHeight;

for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
    uint32_t height = para->levelPara[i].height;
    if (height > LMS_MAX_SAFE_HEIGHT_FOR_UINT64 || sigsPerTree[i + 1] > (UINT64_MAX >> height)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << height);
}
```

---


## Medium

### HSS Private-Key Load Leaves Stale Tree Cache
`crypto/lms/src/hss_api.c:363-377`
```
int32_t ret = HssDecompressParamSet(ctx->para, compressed);
if (ret != CRYPT_SUCCESS) {
    return ret;
}

return CRYPT_SUCCESS;
```
**Issue**: After loading a new private key, cached Merkle trees from the previous key remain marked valid, so signing can reuse stale trees and produce invalid signatures or key reuse.
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

### Levels Accepted That Key Format Cannot Encode
`crypto/lms/src/hss_api.c:185-195`
```
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}
ctx->para->levels = levels;
```
**Issue**: The control API allows up to 8 levels, but the compressed parameter set in the private key only supports 3 levels, so valid configuration can still fail later in keygen or SetPrvKey.
**Fix**:
```
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS || levels > HSS_MAX_COMPRESSED_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}
ctx->para->levels = levels;
```

---


## Low

### Master Seed Not Cleared On Root-Seed Hash Failure
`crypto/lms/src/hss_utils.c:283-296`
```
int32_t ret = LmsHash(hash, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
if (ret != CRYPT_SUCCESS) {
    return CRYPT_HSS_SEED_DERIVE_FAIL;
}
...
ret = LmsHash(rootSeed, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
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
...
ret = LmsHash(rootSeed, buffer, HSS_ROOT_SEED_DERIVE_BUF_LEN);
if (ret != CRYPT_SUCCESS) {
    LmsZeroize(buffer, sizeof(buffer));
    LmsZeroize(hash, sizeof(hash));
    return CRYPT_HSS_SEED_DERIVE_FAIL;
}
```

---

### HSS Compare Ignores Private Seed
`crypto/lms/src/hss_api.c:172-176`
```
if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
    // Only compare the counter and parameters, not the secret seed
    if (memcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_SEED_OFFSET) != 0) {
        return CRYPT_HSS_CMP_FALSE;
    }
}
```
**Issue**: Two different private keys with different master seeds can compare equal if public keys are not set, which can lead to incorrect key matching/caching.
**Fix**:
```
if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
    if (memcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_LEN) != 0) {
        return CRYPT_HSS_CMP_FALSE;
    }
}
```

---
