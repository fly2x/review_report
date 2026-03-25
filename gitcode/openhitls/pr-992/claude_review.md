# Code Review: openHiTLS/openhitls#992
**Reviewer**: CLAUDE


## High

### Integer overflow in tree size allocation
`crypto/hbs/common/hbs_tree.c:331`
```
size_t treeSize = 2u * numLeaves * n;
    uint8_t *tree = (uint8_t *)BSL_SAL_Calloc(treeSize, 1);
```
**Issue**: The tree size calculation `treeSize = 2u * numLeaves * n` could overflow on 32-bit systems for large trees. While LMS_MAX_HEIGHT is 25, the practical limit check (LMS_MAX_PRACTICAL_HEIGHT=15) might not be enforced in all code paths reaching HbsLmsTree_GenerateAuthPath.
**Fix**:
```
/* Check for overflow before calculating tree size */
    if (numLeaves > (SIZE_MAX / (2 * n))) {
        return CRYPT_LMS_INVALID_PARAM;
    }
    size_t treeSize = 2u * numLeaves * n;
    uint8_t *tree = (uint8_t *)BSL_SAL_Calloc(treeSize, 1);
```

---

### Integer overflow in tree size allocation
`crypto/hbs/lms/src/lms_tree.c:156`
```
uint32_t numLeaves = 1u << ctx->height;
    size_t treeSize = 2 * numLeaves * ctx->n;
    uint8_t *tree = BSL_SAL_Calloc(treeSize, 1);
```
**Issue**: The tree size calculation `treeSize = 2 * numLeaves * ctx->n` could overflow on 32-bit systems. While there's a height limit check in LmsParaInit, direct calls to LmsTree_ComputeRoot might bypass this validation.
**Fix**:
```
uint32_t numLeaves = 1u << ctx->height;
    
    /* Check for overflow: treeSize = 2 * numLeaves * n */
    if (numLeaves > (SIZE_MAX / (2 * ctx->n))) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    size_t treeSize = 2 * numLeaves * ctx->n;
    uint8_t *tree = BSL_SAL_Calloc(treeSize, 1);
```

---

### Division by zero vulnerability with unchecked w parameter
`crypto/hbs/lms/src/lms_ots.c:143-149`
```
int32_t LmOtsSign(uint32_t otsType, LMS_SeedDerive *seed, const LmsFamilyHashFuncs *hashFuncs,
    const LMS_InputBuffer *message, LMS_OutputBuffer *signature)
{
    LmOtsParams params;
    int32_t ret = LmOtsLookupParamSet(otsType, &params);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (params.w == 0) {
        return CRYPT_LMS_DIVISION_BY_ZERO;
    }
```
**Issue**: LmOtsLookupParamSet validates w != 0 for known parameter sets, but if an attacker can supply a custom parameter set or if validation is bypassed, the division by later code could crash.
**Fix**:
```
if (params.w == 0 || params.p == 0) {
        return CRYPT_LMS_DIVISION_BY_ZERO;
    }
    
    if (params.w != 1 && params.w != 2 && params.w != 4 && params.w != 8) {
        return CRYPT_LMS_INVALID_PARAM;
    }
```

---

### Integer overflow in HssGetMaxSignatures
`crypto/hbs/hss/src/hss_utils.c:275-285`
```
for (uint32_t i = 0; i < para->levels; i++) {
        uint32_t height = para->levelPara[i].height;

        // Check for overflow: height must be <= 60 to safely compute (1ULL << height) without overflow
        // and total must have enough headroom for multiplication
        if (height > LMS_MAX_SAFE_HEIGHT_FOR_UINT64 || total > (UINT64_MAX >> height)) {
            return UINT64_MAX;  // Return max to indicate overflow
        }

        total *= (1ULL << height);
    }
```
**Issue**: The function calculates total signatures as product of (1<<height) for all levels but doesn't properly handle overflow. It returns UINT64_MAX on overflow, but callers might not check for this sentinel value.
**Fix**:
```
for (uint32_t i = 0; i < para->levels; i++) {
        uint32_t height = para->levelPara[i].height;

        // Check for overflow: height must be <= 60 to safely compute (1ULL << height) without overflow
        if (height > LMS_MAX_SAFE_HEIGHT_FOR_UINT64) {
            return 0;  // Invalid - indicates no signatures available
        }
        
        uint64_t signaturesAtLevel = 1ULL << height;
        
        // Check if multiplication would overflow
        if (total > UINT64_MAX / signaturesAtLevel) {
            return 0;  // Overflow - indicates no signatures available
        }

        total *= signaturesAtLevel;
    }
```

---


## Medium

### BaseB function has potential integer overflow
`crypto/hbs/common/hbs_wots.c:41-50`
```
static void BaseB(const uint8_t *x, uint32_t xLen, uint32_t b, uint32_t *out, uint32_t outLen)
{
    uint32_t bit = 0;
    uint32_t o = 0;
    uint32_t xi = 0;
    for (uint32_t i = 0; i < outLen; i++) {
        while (bit < b && xi < xLen) {
            o = (o << BYTE_BITS) + x[xi];
            bit += 8;
            xi++;
        }
```
**Issue**: The BaseB function can overflow the `o` variable when processing input data. The calculation `o = (o << BYTE_BITS) + x[xi]` can overflow if `b` is large and multiple bytes are processed. For W=16 (4-bit chunks), this is unlikely to be an issue, but the function doesn't validate its inputs.
**Fix**:
```
static void BaseB(const uint8_t *x, uint32_t xLen, uint32_t b, uint32_t *out, uint32_t outLen)
{
    uint32_t bit = 0;
    uint32_t o = 0;
    uint32_t xi = 0;
    
    /* Validate input: b must be <= 16 (for W=16) to prevent overflow */
    if (b > 16 || outLen == 0) {
        return;
    }
    
    for (uint32_t i = 0; i < outLen; i++) {
        while (bit < b && xi < xLen) {
            /* Use 64-bit intermediate to prevent overflow */
            uint64_t temp = ((uint64_t)o << BYTE_BITS) + x[xi];
            if (temp > UINT32_MAX) {
                /* Handle overflow - should not happen with valid inputs */
                return;
            }
            o = (uint32_t)temp;
            bit += 8;
            xi++;
        }
```

---

### Non-constant-time private key comparison
`crypto/hbs/lms/src/lms_api.c:4598`
```
if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
        if (memcmp(ctx1->privateKey, ctx2->privateKey, ctx1->para->prvKeyLen) != 0) {
            return CRYPT_LMS_CMP_FALSE;
        }
    }
```
**Issue**: The CRYPT_LMS_Cmp function uses memcmp to compare private keys. While the comparison is limited to non-secret portions (counter and parameters), the use of memcmp can still leak timing information about private key state.
**Fix**:
```
if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
        /* Use constant-time comparison for private keys */
        if (ctx1->para->prvKeyLen != ctx2->para->prvKeyLen) {
            return CRYPT_LMS_CMP_FALSE;
        }
        int result = CRYPT_Memcmp(ctx1->privateKey, ctx2->privateKey, ctx1->para->prvKeyLen);
        if (result != 0) {
            return CRYPT_LMS_CMP_FALSE;
        }
    }
```

---

### Non-constant-time private key metadata comparison
`crypto/hbs/hss/src/hss_api.c:175`
```
// Only compare the counter and parameters, not the secret seed
    if (memcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_SEED_OFFSET) != 0) {
        return CRYPT_HSS_CMP_FALSE;
    }
```
**Issue**: The memcmp comparison of private key metadata (counter + params) could leak timing information. While the secret seed is not compared, timing variations could still leak information about the key state.
**Fix**:
```
// Only compare the counter and parameters, not the secret seed
    // Use constant-time comparison to prevent timing leaks
    if (CRYPT_Memcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_SEED_OFFSET) != 0) {
        return CRYPT_HSS_CMP_FALSE;
    }
```

---

### Inconsistent height validation allows bypass
`crypto/hbs/lms/src/lms_hash.c:438-454`
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
**Issue**: LmsParaInit validates height against LMS_MAX_PRACTICAL_HEIGHT (15), but the LMS parameter lookup (LmsLookupParamSet) accepts heights up to 25. If LmsParaInit is bypassed, large trees could be allocated, causing potential DoS.
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
    // This check MUST happen before any tree operations
    if (para->height > LMS_MAX_PRACTICAL_HEIGHT) {
        return CRYPT_LMS_INVALID_PARAM;
    }
    
    // Add additional check: for tree operations, also verify against LMS_MAX_HEIGHT
    if (para->height > LMS_MAX_HEIGHT) {
        return CRYPT_LMS_INVALID_PARAM;
    }
```

---

### Missing bounds check in HssCtrlSetLmsType
`crypto/hbs/hss/src/hss_api.c:71-87`
```
if (levelIdx >= ctx->para->levels) {
        return CRYPT_HSS_LEVEL_OUT_OF_RANGE;
    }

    if (lmsType < LMS_SHA256_M32_H5 || lmsType > LMS_SHA256_M32_H25) {
        return CRYPT_HSS_INVALID_PARAM;
    }
```
**Issue**: The function validates that levelIdx < ctx->para->levels, but doesn't validate that lmsType is within valid bounds before using it to index arrays.
**Fix**:
```
if (levelIdx >= ctx->para->levels || levelIdx >= HSS_MAX_LEVELS) {
        return CRYPT_HSS_LEVEL_OUT_OF_RANGE;
    }

    // Validate against all supported LMS types
    if (lmsType < LMS_SHA256_M32_H5 || lmsType > LMS_SHA256_M32_H25) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    
    // Additional validation: ensure the type lookup succeeds
    uint32_t h, n, height;
    if (LmsLookupParamSet(lmsType, &h, &n, &height) != CRYPT_SUCCESS) {
        return CRYPT_HSS_INVALID_PARAM;
    }
```

---


## Low

### Missing NULL pointer dereference check
`crypto/hbs/common/hbs_tree.c:90-92`
```
int32_t HbsTree_ComputeNode(uint8_t *node, uint32_t idx, uint32_t height, void *adrs, const HbsTreeCtx *ctx,
    uint8_t *authPath, uint32_t leafIdx)
{
    int32_t ret;
    uint32_t n = ctx->n;
    uint32_t hp = ctx->hp;

    if (node == NULL || adrs == NULL || ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
```
**Issue**: In HbsTree_ComputeNode, there's a check for NULL pointers (node, adrs, ctx) but authPath can be NULL, which is handled correctly. However, there's no validation that ctx->hashFuncs.xmss is non-NULL before dereferencing it.
**Fix**:
```
if (node == NULL || adrs == NULL || ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    /* Validate function pointers are set */
    if (HBS_IS_XMSS(ctx)) {
        if (ctx->hashFuncs.xmss == NULL || ctx->hashFuncs.xmss->nodeHash == NULL) {
            return CRYPT_NULL_INPUT;
        }
    } else if (ctx->hashFuncs.lms == NULL) {
        return CRYPT_NULL_INPUT;
    }
```

---
