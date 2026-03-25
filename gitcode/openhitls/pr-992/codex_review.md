# Code Review: openHiTLS/openhitls#992
**Reviewer**: CODEX


## High

### HSS key export returns uninitialized buffers and writable aliases to internal key state
`crypto/hbs/hss/src/hss_api.c:27-53`
```
// Allocate key buffers
ctx->publicKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PUBKEY_LEN);
ctx->privateKey = (uint8_t *)BSL_SAL_Calloc(1, HSS_PRVKEY_LEN);

...

if (ctx->privateKey == NULL) {
    return CRYPT_HSS_NO_KEY;
}

// Set private key parameter
BSL_PARAM_InitValue(param, CRYPT_PARAM_HSS_PRVKEY, BSL_PARAM_TYPE_OCTETS, ctx->privateKey, HSS_PRVKEY_LEN);

...

if (ctx->publicKey == NULL) {
    return CRYPT_HSS_NO_KEY;
}

// Set public key parameter
BSL_PARAM_InitValue(param, CRYPT_PARAM_HSS_PUBKEY, BSL_PARAM_TYPE_OCTETS, ctx->publicKey, HSS_PUBKEY_LEN);
```
**Issue**: `CRYPT_HSS_NewCtx()` allocates zero-filled key buffers before any key is generated or imported, and the export APIs only check for `NULL`. A fresh context can therefore "export" an all-zero key. Worse, `CRYPT_HSS_GetPrvKey()` and `CRYPT_HSS_GetPubKey()` use `BSL_PARAM_InitValue()` to point the caller at `ctx->privateKey`/`ctx->publicKey` instead of copying into caller-owned memory, so the caller can mutate the live key material in place.
**Fix**:
```
/* NewCtx: do not preallocate key buffers. */
ctx->publicKey = NULL;
ctx->privateKey = NULL;

int32_t CRYPT_HSS_GetPrvKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL || ctx->privateKey == NULL) {
        return (ctx == NULL || param == NULL) ? CRYPT_NULL_INPUT : CRYPT_HSS_NO_KEY;
    }

    BSL_Param *prv = BSL_PARAM_FindParam(param, CRYPT_PARAM_HSS_PRVKEY);
    if (prv == NULL || prv->value == NULL || prv->valueLen < HSS_PRVKEY_LEN) {
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    (void)memcpy_s(prv->value, prv->valueLen, ctx->privateKey, HSS_PRVKEY_LEN);
    prv->useLen = HSS_PRVKEY_LEN;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_HSS_GetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL || ctx->publicKey == NULL) {
        return (ctx == NULL || param == NULL) ? CRYPT_NULL_INPUT : CRYPT_HSS_NO_KEY;
    }

    BSL_Param *pub = BSL_PARAM_FindParam(param, CRYPT_PARAM_HSS_PUBKEY);
    if (pub == NULL || pub->value == NULL || pub->valueLen < HSS_PUBKEY_LEN) {
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    (void)memcpy_s(pub->value, pub->valueLen, ctx->publicKey, HSS_PUBKEY_LEN);
    pub->useLen = HSS_PUBKEY_LEN;
    return CRYPT_SUCCESS;
}
```

---

### Multi-level HSS verification depends on hidden caller-supplied parameters
`crypto/hbs/hss/src/hss_tree.c:266-299`
```
int32_t ret = HssParseSignature(&parsed, para, signature, signatureLen);
if (ret != CRYPT_SUCCESS) {
    return ret;
}

...

size_t lmsSigLen = para->levelPara[i].sigLen;
const uint8_t *lmsSig = signedPubKey;
const uint8_t *childPubKey = signedPubKey + lmsSigLen;

...

ret = LmsValidateSignature(currentPubKey, message, messageLen, parsed.bottomSig, parsed.bottomSigLen);
```
**Issue**: Verification parses each LMS sub-signature using `para->levelPara[i].sigLen` and `para->levelPara[bottomLevel].sigLen`. But `CRYPT_HSS_SetPubKey()` only records level 0 from the public key, so a verifier that imports a public key alone cannot validate a multi-level signature unless the caller separately replays every lower-level LMS/LMOTS parameter out of band. The signature already contains the type words needed to derive each LMS signature length dynamically.
**Fix**:
```
static int32_t HssGetLmsSigLenFromSig(const uint8_t *sig, size_t remaining, size_t *lmsSigLen)
{
    LmOtsParams ots;
    uint32_t h, n, height;

    if (remaining < LMS_Q_LEN + LMS_TYPE_LEN) {
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    uint32_t otsType = (uint32_t)LmsGetBigendian(sig + LMS_Q_LEN, LMS_TYPE_LEN);
    if (LmOtsLookupParamSet(otsType, &ots) != CRYPT_SUCCESS) {
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    size_t otsSigLen = LMS_TYPE_LEN + ots.n + ots.p * ots.n;
    if (remaining < LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN) {
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    uint32_t lmsType = (uint32_t)LmsGetBigendian(sig + LMS_Q_LEN + otsSigLen, LMS_TYPE_LEN);
    if (LmsLookupParamSet(lmsType, &h, &n, &height) != CRYPT_SUCCESS) {
        return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
    }

    *lmsSigLen = LMS_Q_LEN + otsSigLen + LMS_TYPE_LEN + height * n;
    return (*lmsSigLen <= remaining) ? CRYPT_SUCCESS : CRYPT_HSS_SIGNATURE_PARSE_FAIL;
}

/* In HssTree_Verify(): walk the signature with HssGetLmsSigLenFromSig()
 * instead of para->levelPara[i].sigLen / para->levelPara[bottomLevel].sigLen. */
```

---


## Medium

### HSS context comparison ignores the master seed
`crypto/hbs/hss/src/hss_api.c:172-176`
```
// Compare private keys if both present (compare signature counter only, not seed)
if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
    // Only compare the counter and parameters, not the secret seed
    if (memcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_SEED_OFFSET) != 0) {
        return CRYPT_HSS_CMP_FALSE;
    }
}
```
**Issue**: `CRYPT_HSS_Cmp()` compares only the counter and compressed-parameter prefix of the private key and explicitly skips the 32-byte master seed. Two distinct HSS private keys with the same counter therefore compare equal, which makes `CRYPT_EAL_PkeyCmp()` report false positives.
**Fix**:
```
/* Compare the full serialized private key. */
if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
    if (memcmp(ctx1->privateKey, ctx2->privateKey, HSS_PRVKEY_LEN) != 0) {
        return CRYPT_HSS_CMP_FALSE;
    }
}
```

---

### Public HSS level limit exceeds what the private-key format can encode
`crypto/hbs/hss/src/hss_params.h:31-65`
```
#define HSS_MAX_LEVELS 8  // Maximum hierarchy levels (RFC 8554)
#define HSS_MIN_LEVELS 1  // Minimum hierarchy levels (1 = equivalent to LMS)

...

#define HSS_COMPRESSED_PARAMS_LEN    8     // Compressed parameter set length (8 bytes)
#define HSS_MAX_COMPRESSED_LEVELS    3     // Maximum levels that fit in compressed format
```
**Issue**: The new API advertises `HSS_MAX_LEVELS` as 8, but the serialized private key stores the whole hierarchy in an 8-byte compressed parameter block and `HSS_MAX_COMPRESSED_LEVELS` is only 3. Levels 4-8 are accepted by control setup and then fail later during key generation/import, which is a broken contract.
**Fix**:
```
/* Until the private-key encoding is widened, keep the public limit aligned
 * with what the serialized key can actually carry. */
#define HSS_MAX_LEVELS 3
#define HSS_MIN_LEVELS 1

#define HSS_COMPRESSED_PARAMS_LEN    8
#define HSS_MAX_COMPRESSED_LEVELS    HSS_MAX_LEVELS
```

---

### Newly published LMS/HSS parameter IDs cannot be instantiated
`include/crypto/crypt_algid.h:364-378`
```
CRYPT_LMS_SHA256_H15_W4 = BSL_CID_LMS_SHA256_H15_W4,
CRYPT_LMS_SHA256_H20_W4 = BSL_CID_LMS_SHA256_H20_W4,
CRYPT_LMS_SHA256_H25_W4 = BSL_CID_LMS_SHA256_H25_W4,
...
CRYPT_LMS_SHA256_H15_W8 = BSL_CID_LMS_SHA256_H15_W8,
CRYPT_LMS_SHA256_H20_W8 = BSL_CID_LMS_SHA256_H20_W8,
CRYPT_HSS_SHA256_L2_H10_H10 = BSL_CID_HSS_SHA256_L2_H10_H10,
CRYPT_HSS_SHA256_L2_H15_H15 = BSL_CID_HSS_SHA256_L2_H15_H15,
CRYPT_HSS_SHA256_L2_H20_H20 = BSL_CID_HSS_SHA256_L2_H20_H20,
CRYPT_HSS_SHA256_L3_H10_H10_H10 = BSL_CID_HSS_SHA256_L3_H10_H10_H10,
```
**Issue**: This PR exports `H20`, `H25`, and `HSS ... H20 ...` parameter IDs as supported public enums, but `LmsParaInit()` in the same change rejects every LMS tree height above 15. Callers can now select official-looking algorithm IDs that the implementation will always reject at runtime.
**Fix**:
```
/* Only publish parameter sets that the current implementation accepts. */
CRYPT_LMS_SHA256_H5_W4 = BSL_CID_LMS_SHA256_H5_W4,
CRYPT_LMS_SHA256_H10_W4 = BSL_CID_LMS_SHA256_H10_W4,
CRYPT_LMS_SHA256_H15_W4 = BSL_CID_LMS_SHA256_H15_W4,
CRYPT_LMS_SHA256_H10_W2 = BSL_CID_LMS_SHA256_H10_W2,
CRYPT_LMS_SHA256_H15_W2 = BSL_CID_LMS_SHA256_H15_W2,
CRYPT_LMS_SHA256_H10_W8 = BSL_CID_LMS_SHA256_H10_W8,
CRYPT_LMS_SHA256_H15_W8 = BSL_CID_LMS_SHA256_H15_W8,
CRYPT_HSS_SHA256_L2_H10_H10 = BSL_CID_HSS_SHA256_L2_H10_H10,
CRYPT_HSS_SHA256_L2_H15_H15 = BSL_CID_HSS_SHA256_L2_H15_H15,
CRYPT_HSS_SHA256_L3_H10_H10_H10 = BSL_CID_HSS_SHA256_L3_H10_H10_H10,
```

---
