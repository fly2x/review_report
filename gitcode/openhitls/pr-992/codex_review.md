# Code Review: openHiTLS/openhitls#992
**Reviewer**: CODEX


## High

### HSS getter command IDs collide with generic EAL controls
`crypto/hbs/include/crypt_hss.h:47-55`
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
**Issue**: The new HSS getter macros reuse low numeric values that are already assigned in the global `CRYPT_CTRL_*` enum. `CRYPT_HSS_Ctrl()` dispatches on those raw numbers, so generic helpers are misrouted: `CRYPT_CTRL_GET_BITS` hits the HSS public-key-length branch, `CRYPT_CTRL_GET_SIGNLEN` hits the private-key-length branch, and `CRYPT_CTRL_GET_PUBKEY_LEN` hits `GET_LEVELS`. In practice that makes `CRYPT_EAL_PkeyGetKeyLen()` report `8` bytes, `CRYPT_EAL_PkeyGetSignLen()` report `48`, and the new HSS CMVP self-test allocates an undersized signature buffer.
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

### Seed derivation suppresses hash failures and lets callers use uninitialized output
`crypto/hbs/lms/src/lms_hash.c:316-332`
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
**Issue**: `LmsSeedDerive()` ignores the return value from `LmsHash()` and always reports success. Its LM-OTS callers immediately copy the derived `tmp`/`randomizer` buffers into chains and signatures, so a hash backend failure turns into silent use of uninitialized stack data. That can produce invalid signatures and leak stack bytes into the output.
**Fix**:
```
/* lms_hash.c */
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

/* lms_ots.c: every call site must check the return before using tmp/randomizer */
ret = LmsSeedDerive(tmp, seed, (i < ctx->p - 1));
if (ret != CRYPT_SUCCESS) {
    BSL_SAL_CleanseData(tmp, sizeof(tmp));
    return ret;
}

ret = LmsSeedDerive(randomizer, seed, false);
if (ret != CRYPT_SUCCESS) {
    BSL_SAL_CleanseData(randomizer, sizeof(randomizer));
    return ret;
}
```

---


## Medium

### LMS getter command IDs overlap the shared EAL control namespace
`crypto/hbs/include/crypt_lms.h:46-52`
```
/* LMS control commands */
#define CRYPT_CTRL_LMS_SET_TYPE        1  /**< Set LMS tree type */
#define CRYPT_CTRL_LMS_SET_OTS_TYPE    2  /**< Set LM-OTS type */
#define CRYPT_CTRL_LMS_GET_PUBKEY_LEN  3  /**< Get public key length */
#define CRYPT_CTRL_LMS_GET_PRVKEY_LEN  4  /**< Get private key length */
#define CRYPT_CTRL_LMS_GET_SIG_LEN     5  /**< Get signature length */
#define CRYPT_CTRL_LMS_GET_REMAINING   6  /**< Get remaining signatures */
```
**Issue**: The LMS getter macros also reuse low control numbers that already mean something else to the generic EAL layer. For example, `CRYPT_CTRL_LMS_GET_PRVKEY_LEN` is `4`, which collides with `CRYPT_CTRL_GET_BITS`; as a result `CRYPT_EAL_PkeyGetKeyLen()` interprets the 64-byte private-key length as a bit count and reports `8` bytes. Generic public/private-key-length queries are likewise unreachable through the standard control IDs.
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

### Failed HSS private-key imports leave the context mutated
`crypto/hbs/hss/src/hss_api.c:440-460`
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
**Issue**: `CRYPT_HSS_SetPrvKey()` copies the incoming private key into `ctx->privateKey` and updates `ctx->signatureIndex` before validating the compressed parameter block with `HssDecompressParamSet()`. If validation fails, the function returns an error but the context now holds attacker-supplied key bytes and a new counter value. Reusing the same context after a failed import can therefore mix old parameter state with invalid new key material.
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
