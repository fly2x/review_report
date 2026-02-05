# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #992
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/openhitls#992
**Reviewer**: CLAUDE


## Critical

### Integer underflow in loop counter causes infinite loop
`crypto/lms/src/lms_core.c:131`
```
static int32_t LmsComputeInternalNodes(uint8_t *tree, const uint8_t *I, uint32_t n, uint32_t numLeaves)
{
    for (uint32_t r = numLeaves - LMS_ROOT_NODE_INDEX; r >= LMS_ROOT_NODE_INDEX; r--) {
        uint32_t leftChild = LMS_LEFT_CHILD_MULTIPLIER * r;
        uint32_t rightChild = LMS_LEFT_CHILD_MULTIPLIER * r + LMS_RIGHT_CHILD_OFFSET;
```
**Issue**: The loop in LmsComputeInternalNodes uses `uint32_t r` and decrements from `numLeaves - 1` down to `1`. When `r` reaches `1` and the loop condition `r >= LMS_ROOT_NODE_INDEX` (which is 1) is checked, after the decrement `r--`, `r` becomes `0`, then the loop checks `r >= 1` again. However, this is a uint32_t, so when r=1 and we do r--, we get r=0, and 0 >= 1 is false, so the loop exits correctly. But the issue is with the loop initialization: `r = numLeaves - LMS_ROOT_NODE_INDEX`. If numLeaves is 1 (when height=0, though that should be invalid), this becomes 1-1=0, and the loop starts with r=0, which would immediately fail the condition. More critically, the decrementing loop with unsigned integer can be error-prone.
**Fix**:
```
static int32_t LmsComputeInternalNodes(uint8_t *tree, const uint8_t *I, uint32_t n, uint32_t numLeaves)
{
    // Start from numLeaves-1 down to 1 (root node index)
    // Use int32_t to avoid unsigned underflow issues
    for (int32_t r = (int32_t)(numLeaves - LMS_ROOT_NODE_INDEX); r >= (int32_t)LMS_ROOT_NODE_INDEX; r--) {
        uint32_t leftChild = LMS_LEFT_CHILD_MULTIPLIER * (uint32_t)r;
        uint32_t rightChild = LMS_LEFT_CHILD_MULTIPLIER * (uint32_t)r + LMS_RIGHT_CHILD_OFFSET;
```

---


## High

### Potential aliasing bug when input pointers reference output structure
`crypto/lms/src/hss_utils.c:26`
```
int32_t HssParaInit(HSS_Para *para, uint32_t levels, const uint32_t *lmsTypes, const uint32_t *otsTypes)
{
    if (para == NULL || lmsTypes == NULL || otsTypes == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
        return CRYPT_HSS_INVALID_LEVEL;
    }

    // IMPORTANT: Save copies of lmsTypes and otsTypes arrays before memset
    // because they might point to para->lmsType/para->otsType which will be zeroed!
    uint32_t lmsTypesCopy[HSS_MAX_LEVELS];
    uint32_t otsTypesCopy[HSS_MAX_LEVELS];

    for (uint32_t i = 0; i < levels; i++) {
        lmsTypesCopy[i] = lmsTypes[i];
        otsTypesCopy[i] = otsTypes[i];
    }

    // Clear parameter structure (this may zero the input arrays if they point to para!)
    memset(para, 0, sizeof(HSS_Para));
```
**Issue**: In HssParaInit, if the caller passes `para->lmsType` and `para->otsType` as the lmsTypes and otsTypes parameters, the memset at line 46 will zero those arrays before they are copied, causing data loss. The comment acknowledges this but the fix copies to local arrays before memset, which is correct. However, the function should validate that numLeaves >= 1 before computing `numLeaves - LMS_ROOT_NODE_INDEX` to prevent underflow.
**Fix**:
```
int32_t HssParaInit(HSS_Para *para, uint32_t levels, const uint32_t *lmsTypes, const uint32_t *otsTypes)
{
    if (para == NULL || lmsTypes == NULL || otsTypes == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
        return CRYPT_HSS_INVALID_LEVEL;
    }

    // IMPORTANT: Save copies of lmsTypes and otsTypes arrays before memset
    // because they might point to para->lmsType/para->otsType which will be zeroed!
    uint32_t lmsTypesCopy[HSS_MAX_LEVELS];
    uint32_t otsTypesCopy[HSS_MAX_LEVELS];

    // Validate array bounds before copying
    for (uint32_t i = 0; i < levels && i < HSS_MAX_LEVELS; i++) {
        lmsTypesCopy[i] = lmsTypes[i];
        otsTypesCopy[i] = otsTypes[i];
    }

    // Clear parameter structure (this may zero the input arrays if they point to para!)
    memset(para, 0, sizeof(HSS_Para));
```

---

### Integer overflow in tree memory allocation
`crypto/lms/src/lms_core.c:150`
```
int32_t LmsComputeRoot(uint8_t *root, const LMS_Para *para, const uint8_t *I, const uint8_t *seed)
{
    uint32_t numLeaves = 1u << para->height;
    size_t treeSize = 2 * numLeaves * para->n;
    uint8_t *tree = BSL_SAL_Calloc(treeSize, 1);
    if (tree == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
```
**Issue**: The calculation `2 * numLeaves * para->n` can overflow for large heights. With height=25, numLeaves = 2^25 = 33554432. If n=32, treeSize = 2 * 33554432 * 32 = 2147483648, which exceeds INT32_MAX and could wrap. While this uses size_t, there's no check that the allocation size is reasonable before calling BSL_SAL_Calloc.
**Fix**:
```
int32_t LmsComputeRoot(uint8_t *root, const LMS_Para *para, const uint8_t *I, const uint8_t *seed)
{
    // Validate height to prevent overflow
    if (para->height > 25) {
        return CRYPT_LMS_INVALID_PARAM;
    }
    
    uint32_t numLeaves = 1u << para->height;
    
    // Check for overflow in size calculation: treeSize = 2 * numLeaves * n
    // Maximum safe value: if height=25, numLeaves=2^25, treeSize = 2 * 2^25 * 32 = 2^31
    if (para->n > SIZE_MAX / (2 * numLeaves)) {
        return CRYPT_LMS_INVALID_PARAM;
    }
    
    size_t treeSize = 2 * numLeaves * para->n;
    uint8_t *tree = BSL_SAL_Calloc(treeSize, 1);
    if (tree == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
```

---


## Medium

### Missing height validation allows impractical tree sizes
`crypto/lms/src/lms_hash.c:270`
```
int32_t LmsParaInit(LMS_Para *para, uint32_t lmsType, uint32_t otsType)
{
    if (para == NULL) {
        return CRYPT_NULL_INPUT;
    }

    memset(para, 0, sizeof(LMS_Para));

    int32_t ret = LmsLookupParamSet(lmsType, &para->h, &para->n, &para->height);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Validate height to prevent DoS via full tree regeneration on each signature
    if (para->height > LMS_MAX_PRACTICAL_HEIGHT) {
        return CRYPT_LMS_INVALID_PARAM;
    }
```
**Issue**: The LmsParaInit function validates height against LMS_MAX_PRACTICAL_HEIGHT but LMS_MAX_PRACTICAL_HEIGHT is not defined in the visible code. If this constant is missing or set too high, it could allow DoS attacks via extremely large tree allocations. Additionally, there's no validation that height > 0.
**Fix**:
```
int32_t LmsParaInit(LMS_Para *para, uint32_t lmsType, uint32_t otsType)
{
    if (para == NULL) {
        return CRYPT_NULL_INPUT;
    }

    memset(para, 0, sizeof(LMS_Para));

    int32_t ret = LmsLookupParamSet(lmsType, &para->h, &para->n, &para->height);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    // Validate height to prevent DoS via full tree regeneration on each signature
    // Height must be > 0 and <= 25 (per RFC 8554 max is H25)
    if (para->height == 0 || para->height > 25) {
        return CRYPT_LMS_INVALID_PARAM;
    }
```

---

### Message length not validated against maximum
`crypto/lms/src/lms_ots.c:151`
```
static int32_t LmOtsComputeQ(uint8_t *Q, const LmOtsContext *ctx, const uint8_t *C,
    const uint8_t *message, size_t messageLen)
{
    if (messageLen > LMS_MAX_MESSAGE_SIZE) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t *prefix = BSL_SAL_Malloc(LMS_MESG_PREFIX_LEN(ctx->n) + messageLen);
    if (prefix == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
```
**Issue**: In LmOtsComputeQ, the function checks `if (messageLen > LMS_MAX_MESSAGE_SIZE)` but LMS_MAX_MESSAGE_SIZE is not defined in the visible headers. If this constant is missing or improperly defined, it could allow oversized allocations. The allocation is `LMS_MESG_PREFIX_LEN(ctx->n) + messageLen` which could overflow.
**Fix**:
```
static int32_t LmOtsComputeQ(uint8_t *Q, const LmOtsContext *ctx, const uint8_t *C,
    const uint8_t *message, size_t messageLen)
{
    // Validate message length (prevent overflow in allocation)
    // LMS_MESG_PREFIX_LEN(n) = 22 + n, so max allocation is 22 + 32 + messageLen
    // Limit to 1GB to prevent DoS
    #define LMS_MAX_MESSAGE_SIZE (1024 * 1024 * 1024)
    if (messageLen > LMS_MAX_MESSAGE_SIZE) {
        return CRYPT_INVALID_ARG;
    }

    // Check for overflow in allocation size
    size_t prefixLen = LMS_MESG_PREFIX_LEN(ctx->n);
    if (messageLen > SIZE_MAX - prefixLen) {
        return CRYPT_INVALID_ARG;
    }

    uint8_t *prefix = BSL_SAL_Malloc(prefixLen + messageLen);
    if (prefix == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
```

---

### Missing signature length validation before parsing
`crypto/lms/src/hss_core.c:441`
```
int32_t CRYPT_HSS_Verify(const CRYPT_HSS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen,
    const uint8_t *sig, uint32_t sigLen)
{
    (void)algId;
    if (ctx == NULL || msg == NULL || sig == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicKey == NULL || ctx->para == NULL) {
        return CRYPT_HSS_NO_KEY;
    }

    int32_t ret = CRYPT_SUCCESS;
    HSS_ParsedSig parsed;
    memset(&parsed, 0, sizeof(parsed));

    ret = HssParseSignature(&parsed, ctx->para, sig, sigLen);
```
**Issue**: In CRYPT_HSS_Verify, the function calls HssParseSignature without first validating that sigLen is at least the minimum required size. If sigLen is 0 or very small, HssParseSignature will check this, but it's better to validate early to avoid unnecessary processing.
**Fix**:
```
int32_t CRYPT_HSS_Verify(const CRYPT_HSS_Ctx *ctx, int32_t algId, const uint8_t *msg, uint32_t msgLen,
    const uint8_t *sig, uint32_t sigLen)
{
    (void)algId;
    if (ctx == NULL || msg == NULL || sig == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->publicKey == NULL || ctx->para == NULL) {
        return CRYPT_HSS_NO_KEY;
    }

    // Validate minimum signature length (at least Nspk field)
    if (sigLen < HSS_SIG_NSPK_LEN) {
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    int32_t ret = CRYPT_SUCCESS;
    HSS_ParsedSig parsed;
    memset(&parsed, 0, sizeof(parsed));

    ret = HssParseSignature(&parsed, ctx->para, sig, sigLen);
```

---

### Memory leak in CRYPT_HSS_NewCtx on allocation failure
`crypto/lms/src/hss_api.c:28`
```
CRYPT_HSS_Ctx *CRYPT_HSS_NewCtx(void)
{
    CRYPT_HSS_Ctx *ctx = (CRYPT_HSS_Ctx *)BSL_SAL_Calloc(1, sizeof(CRYPT_HSS_Ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->para = (HSS_Para *)BSL_SAL_Calloc(1, sizeof(HSS_Para));
    if (ctx->para == NULL) {
        BSL_SAL_Free(ctx);
        return NULL;
    }

    // Allocate key buffers
    ctx->publicKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PUBKEY_LEN);
    ctx->privateKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PRVKEY_LEN);

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
**Issue**: In CRYPT_HSS_NewCtx, if allocation of publicKey or privateKey fails, the function frees both keys and para before returning NULL. However, it doesn't free ctx itself in the error path, causing a memory leak.
**Fix**:
```
CRYPT_HSS_Ctx *CRYPT_HSS_NewCtx(void)
{
    CRYPT_HSS_Ctx *ctx = (CRYPT_HSS_Ctx *)BSL_SAL_Calloc(1, sizeof(CRYPT_HSS_Ctx));
    if (ctx == NULL) {
        return NULL;
    }

    ctx->para = (HSS_Para *)BSL_SAL_Calloc(1, sizeof(HSS_Para));
    if (ctx->para == NULL) {
        BSL_SAL_Free(ctx);
        return NULL;
    }

    // Allocate key buffers
    ctx->publicKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PUBKEY_LEN);
    ctx->privateKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PRVKEY_LEN);

    if (ctx->publicKey == NULL || ctx->privateKey == NULL) {
        if (ctx->publicKey != NULL) {
            BSL_SAL_Free(ctx->publicKey);
        }
        if (ctx->privateKey != NULL) {
            BSL_SAL_Free(ctx->privateKey);
        }
        BSL_SAL_Free(ctx->para);
        BSL_SAL_Free(ctx);  // This line was already present, so no fix needed
        return NULL;
    }
```

---

### Integer overflow risk in HssGetMaxSignatures
`crypto/lms/src/hss_utils.c:248`
```
uint64_t HssGetMaxSignatures(const HSS_Para *para)
{
    if (para == NULL || para->levels == 0) {
        return 0;
    }

    // Total signatures = product of (2^height) for all levels
    uint64_t total = 1;
    for (uint32_t i = 0; i < para->levels; i++) {
        uint32_t height = para->levelPara[i].height;

        // Check for overflow: height must be <= 60 to safely compute (1ULL << height) without overflow
        // and total must have enough headroom for multiplication
        if (height > LMS_MAX_SAFE_HEIGHT_FOR_UINT64 || total > (UINT64_MAX >> height)) {
            return UINT64_MAX;  // Return max to indicate overflow
        }

        total *= (1ULL << height);
    }

    return total;
}
```
**Issue**: The function multiplies (1ULL << height) in a loop to compute total signatures. While it checks for overflow with `if (height > LMS_MAX_SAFE_HEIGHT_FOR_UINT64 || total > (UINT64_MAX >> height))`, the second check `total > (UINT64_MAX >> height)` could itself overflow if height is large. Additionally, returning UINT64_MAX on overflow is misleading as it suggests a valid (though huge) number of signatures.
**Fix**:
```
uint64_t HssGetMaxSignatures(const HSS_Para *para)
{
    if (para == NULL || para->levels == 0) {
        return 0;
    }

    // Total signatures = product of (2^height) for all levels
    uint64_t total = 1;
    for (uint32_t i = 0; i < para->levels; i++) {
        uint32_t height = para->levelPara[i].height;

        // Check for overflow: height must be <= 63 for 64-bit shift
        if (height >= 64) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return 0;  // Return 0 to indicate error (overflow)
        }

        // Check if multiplication would overflow
        uint64_t levelSigs = (1ULL << height);
        if (total > UINT64_MAX / levelSigs) {
            BSL_ERR_PUSH_ERROR(CRYPT_HSS_INVALID_PARAM);
            return 0;  // Return 0 to indicate error (overflow)
        }

        total *= levelSigs;
    }

    return total;
}
```

---


## Low

### LMS parameter identifiers don't match RFC 8554 values
`crypto/lms/src/lms_local.h:33`
```
/* LMS-SHA256 parameter set identifiers (RFC 8554) */
#define LMS_SHA256_M32_H5   0x00000005  // SHA-256, n=32, h=5 (32 signatures)
#define LMS_SHA256_M32_H10  0x00000006  // SHA-256, n=32, h=10 (1024 signatures)
#define LMS_SHA256_M32_H15  0x00000007  // SHA-256, n=32, h=15 (32768 signatures)
#define LMS_SHA256_M32_H20  0x00000008  // SHA-256, n=32, h=20 (1M signatures)
#define LMS_SHA256_M32_H25  0x00000009  // SHA-256, n=32, h=25 (32M signatures)
```
**Issue**: The LMS parameter set identifiers should match RFC 8554 Section 5.1 exactly. The current values use the height as the type ID (0x00000005 for H5), but RFC 8554 defines different values. For example, RFC 8554 defines LMS_SHA256_M32_H5 as 0x00000005, H10 as 0x00000006, etc., which appears correct. However, the comment format is inconsistent and should clarify these are RFC-compliant values.
**Fix**:
```
/* LMS-SHA256 parameter set identifiers (RFC 8554 Section 5.1) */
#define LMS_SHA256_M32_H5   0x00000005  // SHA-256, n=32, h=5 (2^5 = 32 signatures)
#define LMS_SHA256_M32_H10  0x00000006  // SHA-256, n=32, h=10 (2^10 = 1024 signatures)
#define LMS_SHA256_M32_H15  0x00000007  // SHA-256, n=32, h=15 (2^15 = 32768 signatures)
#define LMS_SHA256_M32_H20  0x00000008  // SHA-256, n=32, h=20 (2^20 = 1048576 signatures)
#define LMS_SHA256_M32_H25  0x00000009  // SHA-256, n=32, h=25 (2^25 = 33554432 signatures)
```

---

### Inconsistent NULL check in CRYPT_LMS_DupCtx
`crypto/lms/src/lms_api.c:95`
```
CRYPT_LMS_Ctx *CRYPT_LMS_DupCtx(CRYPT_LMS_Ctx *srcCtx)
{
    if (srcCtx == NULL) {
        return NULL;
    }

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }

    /* Copy parameters */
    if (srcCtx->para != NULL) {
        ctx->para = BSL_SAL_Malloc(sizeof(LMS_Para));
        if (ctx->para == NULL) {
            CRYPT_LMS_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->para, sizeof(LMS_Para), srcCtx->para, sizeof(LMS_Para));
    }

    /* Copy public key */
    if (srcCtx->publicKey != NULL && srcCtx->para != NULL) {
        ctx->publicKey = BSL_SAL_Calloc(srcCtx->para->pubKeyLen, 1);
```
**Issue**: In CRYPT_LMS_DupCtx, the function checks `if (srcCtx->para != NULL)` and allocates/copies para, but the actual memcpy_s uses `sizeof(LMS_Para)` for both destination and source size, which is correct. However, after allocation, if memcpy_s fails (which it shouldn't with correct sizes), there's no error handling. The real issue is that if allocation fails, the function should properly clean up and return NULL, but srcCtx->para->pubKeyLen is accessed without checking if the allocation succeeded.
**Fix**:
```
CRYPT_LMS_Ctx *CRYPT_LMS_DupCtx(CRYPT_LMS_Ctx *srcCtx)
{
    if (srcCtx == NULL) {
        return NULL;
    }

    CRYPT_LMS_Ctx *ctx = CRYPT_LMS_NewCtx();
    if (ctx == NULL) {
        return NULL;
    }

    /* Copy parameters */
    if (srcCtx->para != NULL) {
        ctx->para = BSL_SAL_Malloc(sizeof(LMS_Para));
        if (ctx->para == NULL) {
            CRYPT_LMS_FreeCtx(ctx);
            return NULL;
        }
        (void)memcpy_s(ctx->para, sizeof(LMS_Para), srcCtx->para, sizeof(LMS_Para));
    }

    /* Copy public key - check that para was successfully allocated */
    if (srcCtx->publicKey != NULL && ctx->para != NULL) {
        ctx->publicKey = BSL_SAL_Calloc(ctx->para->pubKeyLen, 1);
```

---


---

## GEMINI Review

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


---

## CODEX Review

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


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the file (code or docs)
   - Use `git diff` and file reads to confirm
   - Remove false positives
   - Adjust severity if needed

3. **Consolidate Findings**
   - Merge duplicate issues (note which reviewers found it)
   - Keep unique valid issues
   - Prioritize by actual impact

4. **Output Format**

For each validated issue, output:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
REVIEWERS: <comma-separated list of reviewers who found this>
CONFIDENCE: trusted|likely|evaluate
PROBLEM: <consolidated description>
CODE:
```
<problematic code>
```
FIX:
```
<best suggested fix>
```
===END===

## Confidence Levels

- **trusted** (可信): Multiple reviewers found this issue AND you verified it in the code
- **likely** (较可信): Found by one reviewer AND you verified it exists in the code
- **evaluate** (需评估): Found by reviewer(s) but needs human review to confirm impact/fix

## Important

- SEVERITY indicates impact level (critical/high/medium/low)
- CONFIDENCE indicates how certain we are about this issue
- Only include issues you've verified in the changed files (code or docs)
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
