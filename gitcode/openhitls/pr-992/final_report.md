# Final Code Review Report
## openHiTLS/openhitls - PR #992

### Summary
- **Total Issues**: 8
- **Critical**: 1
- **High**: 2
- **Medium**: 4
- **Low**: 1
- **Reviewers**: claude, gemini, codex

---


## Critical

### Unhandled LmsHash failure leads to uninitialized key material usage
`crypto/hbs/lms/src/lms_hash.c:316-332`
**Reviewers**: GEMINI, CODEX | **置信度**: 可信
```
int32_t LmsSeedDerive(uint8_t *seed, LMS_SeedDerive *derive, bool incrementJ)
{
    uint8_t buffer[LMS_PRG_LEN];

    (void)memcpy_s(buffer + LMS_PRG_I_OFFSET, LMS_I_LEN, derive->I, LMS_I_LEN);
    LmsPutBigendian(buffer + LMS_PRG_Q_OFFSET, derive->q, LMS_Q_LEN);
    LmsPutBigendian(buffer + LMS_PRG_J_OFFSET, derive->j, LMS_K_LEN);
    buffer[LMS_PRG_FF_OFFSET] = LMS_PRG_FF_VALUE;
    (void)memcpy_s(buffer + LMS_PRG_SEED_OFFSET, LMS_SEED_LEN, derive->masterSeed, LMS_SEED_LEN);

    LmsHash(seed, buffer, LMS_PRG_LEN);
    BSL_SAL_CleanseData(buffer, LMS_PRG_LEN);

    if (incrementJ) {
        derive->j += 1;
    }
    return CRYPT_SUCCESS;
}
```
**Issue**: LmsSeedDerive() ignores the return value from LmsHash() and always returns CRYPT_SUCCESS. If the underlying hash operation fails (e.g., due to failed memory allocation or hardware error), the seed buffer remains uninitialized. Callers in lms_ots.c immediately use the derived tmp/randomizer buffers in chains and signatures without error checking, causing silent use of uninitialized stack data that can produce invalid signatures and leak stack bytes.
**Fix**:
```
int32_t LmsSeedDerive(uint8_t *seed, LMS_SeedDerive *derive, bool incrementJ)
{
    uint8_t buffer[LMS_PRG_LEN];

    (void)memcpy_s(buffer + LMS_PRG_I_OFFSET, LMS_I_LEN, derive->I, LMS_I_LEN);
    LmsPutBigendian(buffer + LMS_PRG_Q_OFFSET, derive->q, LMS_Q_LEN);
    LmsPutBigendian(buffer + LMS_PRG_J_OFFSET, derive->j, LMS_K_LEN);
    buffer[LMS_PRG_FF_OFFSET] = LMS_PRG_FF_VALUE;
    (void)memcpy_s(buffer + LMS_PRG_SEED_OFFSET, LMS_SEED_LEN, derive->masterSeed, LMS_SEED_LEN);

    int32_t ret = LmsHash(seed, buffer, LMS_PRG_LEN);
    BSL_SAL_CleanseData(buffer, LMS_PRG_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (incrementJ) {
        derive->j += 1;
    }
    return CRYPT_SUCCESS;
}
```

---


## High

### HSS control command IDs collide with generic EAL controls
`crypto/hbs/include/crypt_hss.h:47-55`
**Reviewers**: CODEX | **置信度**: 可信
```
/* HSS control commands */
#define CRYPT_CTRL_HSS_SET_LEVELS        1  /**< Set hierarchy levels (1-8) */
#define CRYPT_CTRL_HSS_SET_LMS_TYPE      2  /**< Set LMS type for level */
#define CRYPT_CTRL_HSS_SET_OTS_TYPE      3  /**< Set OTS type for level */
#define CRYPT_CTRL_HSS_GET_PUBKEY_LEN    4  /**< Get public key length */
#define CRYPT_CTRL_HSS_GET_PRVKEY_LEN    5  /**< Get private key length */
#define CRYPT_CTRL_HSS_GET_SIG_LEN       6  /**< Get signature length */
#define CRYPT_CTRL_HSS_GET_REMAINING     7  /**< Get remaining signatures */
#define CRYPT_CTRL_HSS_GET_LEVELS        8  /**< Get number of levels */
```
**Issue**: The HSS getter macros reuse low numeric values (4-8) that already exist in the global CRYPT_CTRL_* enum. CRYPT_HSS_Ctrl() dispatches on those raw numbers, so generic helpers are misrouted: CRYPT_CTRL_GET_BITS hits HSS public-key-length branch, CRYPT_CTRL_GET_SIGNLEN hits private-key-length branch. This causes CRYPT_EAL_PkeyGetKeyLen() to report 8 bytes instead of 60, and CRYPT_EAL_PkeyGetSignLen() to report 48 instead of the correct signature length.
**Fix**:
```
#include "crypt_types.h"

/* HSS control commands */
#define CRYPT_CTRL_HSS_SET_LEVELS        1
#define CRYPT_CTRL_HSS_SET_LMS_TYPE      2
#define CRYPT_CTRL_HSS_SET_OTS_TYPE      3

/* Reuse the common EAL getter IDs so generic helpers work. */
#define CRYPT_CTRL_HSS_GET_PUBKEY_LEN    CRYPT_CTRL_GET_PUBKEY_LEN
#define CRYPT_CTRL_HSS_GET_PRVKEY_LEN    CRYPT_CTRL_GET_PRVKEY_LEN
#define CRYPT_CTRL_HSS_GET_SIG_LEN       CRYPT_CTRL_GET_SIGNLEN

/* Keep HSS-only queries out of the shared control range. */
#define CRYPT_CTRL_HSS_GET_REMAINING     0x1001
#define CRYPT_CTRL_HSS_GET_LEVELS        0x1002
```

---

### Incorrect sigsPerTree calculation causes divide-by-zero
`crypto/hbs/hss/src/hss_utils.c:388-396`
**Reviewers**: GEMINI | **置信度**: 可信
```
for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
    uint32_t childHeight = para->levelPara[i + 1].height;
    sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << childHeight);
}

// Calculate tree and leaf indices for each level
for (uint32_t i = 0; i < para->levels; i++) {
    // Tree index at level i = globalIndex / sigsPerTree[i]
    treeIndex[i] = globalIndex / sigsPerTree[i];
```
**Issue**: HssCalculateTreeIndices incorrectly calculates sigsPerTree[i] using childHeight instead of the current tree's height. The erroneous multiplication sigsPerTree[i+1] * (1ULL << childHeight) can exceed 2^64 and wrap to exactly 0, causing a hardware divide-by-zero exception (SIGFPE) at globalIndex / sigsPerTree[i]. Additionally, the calculated treeIndex and leafIndex are entirely unused by CRYPT_HSS_Sign, which recomputes them correctly via HssTree_CalculateIndices.
**Fix**:
```
for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
    uint32_t currentHeight = para->levelPara[i].height;
    sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << currentHeight);
}

// Calculate tree and leaf indices for each level
for (uint32_t i = 0; i < para->levels; i++) {
    if (sigsPerTree[i] == 0) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    // Tree index at level i = globalIndex / sigsPerTree[i]
    treeIndex[i] = globalIndex / sigsPerTree[i];
```

---


## Medium

### Timing side-channel vulnerability in root hash comparison
`crypto/hbs/lms/src/lms_core.c:545-548`
**Reviewers**: CLAUDE | **置信度**: 可信
```
if (memcmp(currentHash, info.expectedRoot, info.n) == 0) {
    return CRYPT_SUCCESS;
}
return CRYPT_LMS_VERIFY_FAIL;
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
    return CRYPT_LMS_VERIFY_FAIL;
```

---

### Failed HSS private-key imports leave the context mutated
`crypto/hbs/hss/src/hss_api.c:440-461`
**Reviewers**: CODEX | **置信度**: 可信
```
// Allocate private key buffer on first import
if (ctx->privateKey == NULL) {
    ctx->privateKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PRVKEY_LEN);
    if (ctx->privateKey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
}

// Copy private key
(void)memcpy_s(ctx->privateKey, HSS_PRVKEY_LEN, prvKeyParam->value, HSS_PRVKEY_LEN);

// Extract and cache signature counter
ctx->signatureIndex = LmsGetBigendian(ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET, HSS_PRVKEY_COUNTER_LEN);

// Decompress and validate parameters
uint8_t compressed[8];
(void)memcpy_s(compressed, sizeof(compressed), ctx->privateKey + HSS_PRVKEY_PARAMS_OFFSET, HSS_PRVKEY_PARAMS_LEN);

int32_t ret = HssDecompressParamSet(ctx->para, compressed);
if (ret != CRYPT_SUCCESS) {
    return ret;
}
```
**Issue**: CRYPT_HSS_SetPrvKey() copies the incoming private key into ctx->privateKey and updates ctx->signatureIndex before validating the compressed parameter block with HssDecompressParamSet(). If validation fails, the function returns an error but the context now holds attacker-supplied key bytes and a new counter value. Reusing the same context after a failed import can mix old parameter state with invalid new key material.
**Fix**:
```
uint8_t tmpPrv[HSS_PRVKEY_LEN];
HSS_Para tmpPara;

(void)memcpy_s(tmpPrv, sizeof(tmpPrv), prvKeyParam->value, HSS_PRVKEY_LEN);
(void)memcpy_s(&tmpPara, sizeof(tmpPara), ctx->para, sizeof(tmpPara));

uint8_t compressed[HSS_COMPRESSED_PARAMS_LEN];
(void)memcpy_s(compressed, sizeof(compressed),
    tmpPrv + HSS_PRVKEY_PARAMS_OFFSET, HSS_PRVKEY_PARAMS_LEN);

int32_t ret = HssDecompressParamSet(&tmpPara, compressed);
if (ret != CRYPT_SUCCESS) {
    BSL_SAL_CleanseData(tmpPrv, sizeof(tmpPrv));
    return ret;
}

if (ctx->privateKey == NULL) {
    ctx->privateKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PRVKEY_LEN);
    if (ctx->privateKey == NULL) {
        BSL_SAL_CleanseData(tmpPrv, sizeof(tmpPrv));
        return CRYPT_MEM_ALLOC_FAIL;
    }
}

(void)memcpy_s(ctx->privateKey, HSS_PRVKEY_LEN, tmpPrv, HSS_PRVKEY_LEN);
(void)memcpy_s(ctx->para, sizeof(*ctx->para), &tmpPara, sizeof(tmpPara));
ctx->signatureIndex = LmsGetBigendian(ctx->privateKey + HSS_PRVKEY_COUNTER_OFFSET, HSS_PRVKEY_COUNTER_LEN);
BSL_SAL_CleanseData(tmpPrv, sizeof(tmpPrv));
return CRYPT_SUCCESS;
```

---

### Missing memory cleanse for sensitive keys in HSSKeyPairCheck
`crypto/hbs/hss/src/hss_api.c:641-651`
**Reviewers**: GEMINI | **置信度**: 可信
```
uint8_t masterSeed[LMS_SEED_LEN];
(void)memcpy_s(masterSeed, sizeof(masterSeed), prvKey->privateKey + HSS_PRVKEY_SEED_OFFSET, HSS_PRVKEY_SEED_LEN);

uint8_t rootI[LMS_I_LEN];
uint8_t rootSeed[LMS_SEED_LEN];
ret = HssGenerateRootSeed(rootI, rootSeed, masterSeed);
if (ret != CRYPT_SUCCESS) {
    return ret;
}

return HSSVerifyRootHash(pubKey, prvKey, rootI, rootSeed);
```
**Issue**: masterSeed (extracted from the private key) and rootSeed are sensitive cryptographic materials used to derive all HSS subkeys. They are copied/generated on the stack in HSSKeyPairCheck but are not cleansed before the function returns, potentially leading to side-channel leakage or sensitive data exposure through uninitialized stack memory reuse.
**Fix**:
```
uint8_t masterSeed[LMS_SEED_LEN];
(void)memcpy_s(masterSeed, sizeof(masterSeed), prvKey->privateKey + HSS_PRVKEY_SEED_OFFSET, HSS_PRVKEY_SEED_LEN);

uint8_t rootI[LMS_I_LEN];
uint8_t rootSeed[LMS_SEED_LEN];
ret = HssGenerateRootSeed(rootI, rootSeed, masterSeed);

BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));

if (ret != CRYPT_SUCCESS) {
    BSL_SAL_CleanseData(rootSeed, sizeof(rootSeed));
    return ret;
}

ret = HSSVerifyRootHash(pubKey, prvKey, rootI, rootSeed);
BSL_SAL_CleanseData(rootSeed, sizeof(rootSeed));

return ret;
```

---

### LMS getter command IDs overlap the shared EAL control namespace
`crypto/hbs/include/crypt_lms.h:46-52`
**Reviewers**: CODEX | **置信度**: 可信
```
/* LMS control commands */
#define CRYPT_CTRL_LMS_SET_TYPE        1  /**< Set LMS tree type */
#define CRYPT_CTRL_LMS_SET_OTS_TYPE    2  /**< Set LM-OTS type */
#define CRYPT_CTRL_LMS_GET_PUBKEY_LEN  3  /**< Get public key length */
#define CRYPT_CTRL_LMS_GET_PRVKEY_LEN  4  /**< Get private key length */
#define CRYPT_CTRL_LMS_GET_SIG_LEN     5  /**< Get signature length */
#define CRYPT_CTRL_LMS_GET_REMAINING   6  /**< Get remaining signatures */
```
**Issue**: The LMS getter macros reuse low control numbers that already mean something else to the generic EAL layer. For example, CRYPT_CTRL_LMS_GET_PRVKEY_LEN is 4, which collides with CRYPT_CTRL_GET_BITS. As a result, CRYPT_EAL_PkeyGetKeyLen() interprets the 64-byte private-key length as a bit count and reports 8 bytes. Generic public/private-key-length queries are likewise unreachable through the standard control IDs.
**Fix**:
```
#include "crypt_types.h"

/* LMS control commands */
#define CRYPT_CTRL_LMS_SET_TYPE        1
#define CRYPT_CTRL_LMS_SET_OTS_TYPE    2

/* Reuse the common EAL getter IDs so generic helpers work. */
#define CRYPT_CTRL_LMS_GET_PUBKEY_LEN  CRYPT_CTRL_GET_PUBKEY_LEN
#define CRYPT_CTRL_LMS_GET_PRVKEY_LEN  CRYPT_CTRL_GET_PRVKEY_LEN
#define CRYPT_CTRL_LMS_GET_SIG_LEN     CRYPT_CTRL_GET_SIGNLEN

/* Keep the LMS-only query out of the shared control range. */
#define CRYPT_CTRL_LMS_GET_REMAINING   0x1001
```

---


## Low

### Constant-time comparison uses uint8_t accumulator that can saturate
`crypto/hbs/lms/src/lms_api.c:35-42`
**Reviewers**: CLAUDE | **置信度**: 可信
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
**Issue**: The LmsConstTimeMemCmp function uses a uint8_t accumulator which could saturate and wrap around to 0 for long buffers, potentially causing two different buffers to compare as equal. While LMS keys have bounded lengths (n=32 bytes, private keys=48 bytes, public keys=56 bytes), this is still a potential issue.
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
