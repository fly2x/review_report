# Code Review: openHiTLS/openhitls#992
**Reviewer**: CLAUDE


## High

### Integer overflow in chain iteration loop
`crypto/hbs/lms/src/lms_ots.c:83`
```
/* Iterate the hash function 'steps' times starting from 'start' */
    for (uint32_t j = start; j < start + steps; j++) {
        int32_t ret = ctx->hashFuncs->chainHash(&otsCtx, k, j, buffer, buffer);
```
**Issue**: The loop condition `j < start + steps` could overflow if both `start` and `steps` are large values, causing an infinite loop or buffer overflow. While the typical values are bounded by the Winternitz parameter (2^w-1), the code should explicitly validate this.
**Fix**:
```
/* Iterate the hash function 'steps' times starting from 'start' */
    uint32_t maxSteps = (1U << ctx->w) - 1;
    if (start > maxSteps || start + steps < start || start + steps > maxSteps + 1) {
        return CRYPT_LMS_INVALID_PARAM;
    }
    for (uint32_t j = start; j < start + steps; j++) {
        int32_t ret = ctx->hashFuncs->chainHash(&otsCtx, k, j, buffer, buffer);
```

---


## Medium

### Timing side-channel vulnerability in root hash comparison
`crypto/hbs/lms/src/lms_core.c:545`
```
if (memcmp(currentHash, info.expectedRoot, info.n) == 0) {
        return CRYPT_SUCCESS;
    }
```
**Issue**: The final root hash comparison uses memcmp() which is not constant-time. This could leak information about the expected root hash through timing differences, potentially allowing an attacker to forge signatures by observing verification timing.
**Fix**:
```
/* Use constant-time comparison to prevent timing side-channel */
    uint8_t diff = 0;
    for (size_t i = 0; i < info.n; i++) {
        diff |= currentHash[i] ^ info.expectedRoot[i];
    }
    if (diff == 0) {
        return CRYPT_SUCCESS;
    }
```

---

### Missing upper bound validation for levels parameter
`crypto/hbs/hss/src/hss_api.c:498`
```
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_COMPRESSED_LEVELS) {
        return CRYPT_HSS_INVALID_PARAM;
    }
```
**Issue**: The validation only checks against HSS_MAX_COMPRESSED_LEVELS (3) but not against HSS_MAX_LEVELS. An attacker could potentially craft a public key with levels value that passes this check but causes issues later. The comment in hss_params.h clearly states HSS_MAX_LEVELS (3) should be used for API validation.
**Fix**:
```
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
        return CRYPT_HSS_INVALID_PARAM;
    }
```

---

### Unbounded recursion could cause stack overflow
`crypto/hbs/common/hbs_tree.c:94-98`
```
ret = HbsTree_ComputeNode(leftNode, 2 * idx, height - 1, adrs, ctx, authPath, leafIdx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = HbsTree_ComputeNode(rightNode, 2 * idx + 1, height - 1, adrs, ctx, authPath, leafIdx);
```
**Issue**: The HbsTree_ComputeNode function uses recursive calls without any depth limit. For large tree heights (e.g., height=20 or 25), this could cause stack overflow. While LMS limits height to 25, HSS could theoretically have multiple levels.
**Fix**:
```
/* Add depth limit to prevent stack overflow */
    if (height > MAX_TREE_RECURSION_DEPTH) {
        return CRYPT_INVALID_ARG;
    }
    ret = HbsTree_ComputeNode(leftNode, 2 * idx, height - 1, adrs, ctx, authPath, leafIdx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = HbsTree_ComputeNode(rightNode, 2 * idx + 1, height - 1, adrs, ctx, authPath, leafIdx);
```

---

### Missing validation of remainingSigLen in signature parsing
`crypto/hbs/hss/src/hss_core.c:199-210`
```
/* After q + otsSig, need lmsType(4) */
    if (remaining < LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN) {
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }
```
**Issue**: The signature parsing function parses signature data without properly validating the remainingSigLen between operations, which could lead to out-of-bounds reads if the signature is malformed.
**Fix**:
```
/* After q + otsSig, need lmsType(4) */
    if (remaining < LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN) {
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }
    /* Validate we have enough for auth path too */
    if (otsSigLen < LMS_TYPE_LEN) {
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }
```

---

### Unvalidated loop iteration over levels array
`crypto/hbs/hss/src/hss_api.c:60-72`
```
/* Key buffers are allocated on demand (keygen / import), not here. */
    ctx->publicKey = NULL;
    ctx->privateKey = NULL;

    ctx->signatureIndex = 0;
    ctx->libCtx = NULL;

    // Initialize cache arrays
    for (uint32_t i = 0; i < HSS_LEVELS_ARRAY_SIZE; i++) {
        ctx->cachedTrees[i] = NULL;
```
**Issue**: The CRYPT_HSS_NewCtx function initializes cache arrays without checking the levels value, potentially using uninitialized loop bounds if levels is later set to an invalid value.
**Fix**:
```
/* Key buffers are allocated on demand (keygen / import), not here. */
    ctx->publicKey = NULL;
    ctx->privateKey = NULL;

    ctx->signatureIndex = 0;
    ctx->libCtx = NULL;
    ctx->para->levels = 0;  /* Initialize to 0 to ensure bounds are valid */

    // Initialize cache arrays
    for (uint32_t i = 0; i < HSS_LEVELS_ARRAY_SIZE; i++) {
        ctx->cachedTrees[i] = NULL;
```

---

### HssGetMaxSignatures lacks overflow validation
`crypto/hbs/hss/src/hss_utils.c:240-270`
```
if (height > LMS_MAX_SAFE_HEIGHT_FOR_UINT64 || total > (UINT64_MAX >> height)) {
            return 0;  // Return 0 to indicate overflow/unsupported configuration
        }

        total *= (1ULL << height);
    }

    return total;
```
**Issue**: While there's overflow checking, the function returns 0 on overflow which is ambiguous - it could also mean no signatures available. This could cause issues if the caller doesn't distinguish between "overflow" and "empty".
**Fix**:
```
if (height > LMS_MAX_SAFE_HEIGHT_FOR_UINT64 || total > (UINT64_MAX >> height)) {
            return 0;  /* TODO: Should return distinct error code for overflow */
        }

        total *= (1ULL << height);
    }

    if (total == 0) {
        return 0;  /* Indicates error - should be documented */
    }
    return total;
```

---


## Low

### Missing input length validation in base conversion
`crypto/hbs/common/hbs_wots.c:77-100`
```
static void HbsWots_MsgToBaseW(const HbsWotsCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint32_t *out)
{
    uint32_t n = ctx->n;
    uint32_t len1 = 2 * n;
    uint32_t len2 = 3;

    /* Convert message bytes to base-W */
    BaseB(msg, msgLen, 4, out, len1); /* log2(16) = 4 */
```
**Issue**: The HbsWots_MsgToBaseW function uses the msgLen parameter without validating it matches ctx->n. If an attacker provides a different length, it could read out of bounds.
**Fix**:
```
static void HbsWots_MsgToBaseW(const HbsWotsCtx *ctx, const uint8_t *msg, uint32_t msgLen, uint32_t *out)
{
    uint32_t n = ctx->n;
    if (msgLen != n) {
        return; /* or handle error appropriately */
    }
    uint32_t len1 = 2 * n;
    uint32_t len2 = 3;

    /* Convert message bytes to base-W */
    BaseB(msg, msgLen, 4, out, len1); /* log2(16) = 4 */
```

---

### Constant-time comparison uses uint8_t accumulator
`crypto/hbs/lms/src/lms_api.c:35-42`
```
static int32_t LmsConstTimeMemCmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (int32_t)diff;
}
```
**Issue**: The LmsConstTimeMemCmp function uses a uint8_t accumulator which could saturate and wrap around to 0 for long buffers, potentially causing two different buffers to compare as equal.
**Fix**:
```
static int32_t LmsConstTimeMemCmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    /* Use != 0 instead of implicit conversion to ensure non-zero result */
    return (diff != 0) ? 1 : 0;
}
```

---

### Missing NULL check before BSL_SAL_CleanseData
`crypto/hbs/lms/src/lms_api.c:161-170`
```
if (ctx->cachedTree != NULL) {
        BSL_SAL_CleanseData(ctx->cachedTree, ctx->cachedTreeSize);
        BSL_SAL_FREE(ctx->cachedTree);
    }
```
**Issue**: The CRYPT_LMS_FreeCtx function calls BSL_SAL_CleanseData on ctx->cachedTree using ctx->cachedTreeSize, but if ctx->cachedTree is NULL while cachedTreeSize is non-zero, this could cause issues.
**Fix**:
```
if (ctx->cachedTree != NULL && ctx->cachedTreeSize > 0) {
        BSL_SAL_CleanseData(ctx->cachedTree, ctx->cachedTreeSize);
        BSL_SAL_FREE(ctx->cachedTree);
    }
```

---

### BaseB function may read uninitialized bytes
`crypto/hbs/common/hbs_wots.c:46-67`
```
for (uint32_t i = 0; i < outLen; i++) {
        while (bit < b && xi < xLen) {
            o = (o << BYTE_BITS) + x[xi];
            bit += 8;
            xi++;
        }
```
**Issue**: The BaseB function reads x[xi] without ensuring xi stays within xLen bounds in all cases. While the loop condition should prevent this, the complex bit manipulation logic makes it hard to verify.
**Fix**:
```
for (uint32_t i = 0; i < outLen; i++) {
        while (bit < b && xi < xLen) {
            o = (o << BYTE_BITS) + x[xi];
            bit += 8;
            xi++;
        }
        if (xi >= xLen && bit < b) {
            /* Not enough input bytes - return error */
            return;
        }
```

---
