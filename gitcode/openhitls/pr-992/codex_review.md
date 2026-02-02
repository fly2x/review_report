# Code Review: openhitls/openhitls#992
**Reviewer**: CODEX


## Critical

### Unsigned loop underflow in internal node computation
`crypto/lms/src/lms_core.c:140-151`
```
for (uint32_t r = numLeaves - LMS_ROOT_NODE_INDEX; r >= LMS_ROOT_NODE_INDEX; r--) {
    uint32_t leftChild = LMS_LEFT_CHILD_MULTIPLIER * r;
    uint32_t rightChild = LMS_LEFT_CHILD_MULTIPLIER * r + LMS_RIGHT_CHILD_OFFSET;

    LmsInternalHashCtx ctx = {I, r, &tree[leftChild * n], &tree[rightChild * n], n};
    int32_t ret = LmsComputeInternalHash(&tree[r * n], &ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
}
```
**Issue**: The loop decrements a uint32_t while checking `r >= 1`. When r reaches 0 it wraps to UINT32_MAX, causing an infinite loop and out-of-bounds tree indexing during root/auth-path computation.
**Fix**:
```
for (uint32_t r = numLeaves - LMS_ROOT_NODE_INDEX; r > 0; r--) {
    uint32_t leftChild = LMS_LEFT_CHILD_MULTIPLIER * r;
    uint32_t rightChild = LMS_LEFT_CHILD_MULTIPLIER * r + LMS_RIGHT_CHILD_OFFSET;

    LmsInternalHashCtx ctx = {I, r, &tree[leftChild * n], &tree[rightChild * n], n};
    int32_t ret = LmsComputeInternalHash(&tree[r * n], &ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
}
```

---


## High

### Missing overflow checks can cause division by zero in tree index calculation
`crypto/lms/src/hss_utils.c:355-369`
```
uint64_t sigsPerTree[HSS_MAX_LEVELS];
sigsPerTree[para->levels - 1] = 1ULL << para->levelPara[para->levels - 1].height;

for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
    uint32_t childHeight = para->levelPara[i + 1].height;
    sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << childHeight);
}

...
treeIndex[i] = globalIndex / sigsPerTree[i];
```
**Issue**: `sigsPerTree[i]` is computed by multiplying powers of two without overflow checks. For larger levels/heights this can wrap to 0, and the later `globalIndex / sigsPerTree[i]` division can crash or compute wrong indices.
**Fix**:
```
uint64_t sigsPerTree[HSS_MAX_LEVELS];
sigsPerTree[para->levels - 1] = 1ULL << para->levelPara[para->levels - 1].height;

for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
    uint32_t childHeight = para->levelPara[i + 1].height;
    uint64_t factor = 1ULL << childHeight;
    if (sigsPerTree[i + 1] > (UINT64_MAX / factor)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    sigsPerTree[i] = sigsPerTree[i + 1] * factor;
}

...
if (sigsPerTree[i] == 0) {
    return CRYPT_HSS_INVALID_PARAM;
}
treeIndex[i] = globalIndex / sigsPerTree[i];
```

---


## Medium

### Levels accepted beyond what private-key compression supports
`crypto/lms/src/hss_utils.c:32-34`
```
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}
```
**Issue**: `HssParaInit` accepts up to `HSS_MAX_LEVELS` (8), but the private key stores a compressed parameter set that only supports `HSS_MAX_COMPRESSED_LEVELS` (3). Keys with 4–8 levels will fail in `HssCompressParamSet`/`CRYPT_HSS_Gen` and cannot be imported via `CRYPT_HSS_SetPrvKey`.
**Fix**:
```
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS || levels > HSS_MAX_COMPRESSED_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}
```

---

### Parameter sets H20/H25 are advertised but always rejected
`crypto/lms/src/lms_hash.c:274-276`
```
// Validate height to prevent DoS via full tree regeneration on each signature
if (para->height > LMS_MAX_PRACTICAL_HEIGHT) {
    return CRYPT_LMS_INVALID_PARAM;
}
```
**Issue**: The PR adds LMS/HSS parameter IDs for heights 20/25, but `LmsParaInit` rejects any height > 15, so those algorithm IDs can never be used (keygen/verify fails with CRYPT_LMS_INVALID_PARAM). This is inconsistent with the public enums/config.
**Fix**:
```
if (para->height > LMS_MAX_HEIGHT) {
    return CRYPT_LMS_INVALID_PARAM;
}
```

---

### Seed derivation ignores hash failure
`crypto/lms/src/lms_hash.c:151-167`
```
LmsHash(seed, buffer, LMS_PRG_LEN);
LmsZeroize(buffer, LMS_PRG_LEN);

if (incrementJ) {
    derive->j += 1;
}
return CRYPT_SUCCESS;
```
**Issue**: `LmsSeedDerive` discards the return value of `LmsHash` and always returns success, so a hash failure leaves `seed` uninitialized and still advances `j`, producing invalid signatures/keys.
**Fix**:
```
int32_t ret = LmsHash(seed, buffer, LMS_PRG_LEN);
LmsZeroize(buffer, LMS_PRG_LEN);
if (ret != CRYPT_SUCCESS) {
    return CRYPT_LMS_HASH_FAIL;
}

if (incrementJ) {
    derive->j += 1;
}
return CRYPT_SUCCESS;
```

---

### LM-OTS Q computation ignores hash failure
`crypto/lms/src/lms_ots.c:161-176`
```
LmsHash(Q, prefix, LMS_MESG_PREFIX_LEN(ctx->n) + messageLen);
BSL_SAL_FREE(prefix);

LmsPutBigendian(&Q[ctx->n], LmOtsComputeChecksum(Q, ctx->n, ctx->w, ctx->ls), LMS_CHECKSUM_LEN);
return CRYPT_SUCCESS;
```
**Issue**: `LmOtsComputeQ` does not check the return of `LmsHash`, so a hash failure results in an invalid Q/checksum being used while still returning success.
**Fix**:
```
int32_t ret = LmsHash(Q, prefix, LMS_MESG_PREFIX_LEN(ctx->n) + messageLen);
BSL_SAL_FREE(prefix);
if (ret != CRYPT_SUCCESS) {
    return CRYPT_LMS_HASH_FAIL;
}

LmsPutBigendian(&Q[ctx->n], LmOtsComputeChecksum(Q, ctx->n, ctx->w, ctx->ls), LMS_CHECKSUM_LEN);
return CRYPT_SUCCESS;
```

---
