# Code Review: openHiTLS/openhitls#992
**Reviewer**: CLAUDE


## High

### NULL pointer dereference in HssCtrlGetLevels
`crypto/lms/src/hss_api.c:291-297`
```
static int32_t HssCtrlGetLevels(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < sizeof(uint32_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    *(uint32_t *)val = ctx->para->levels;  // NULL pointer dereference if ctx->para is NULL
    return CRYPT_SUCCESS;
}
```
**Issue**: The function HssCtrlGetLevels dereferences ctx->para without checking if it's NULL. Since ctx->para is allocated separately in NewCtx and could potentially be NULL in error conditions or if memory allocation failed partially, this could cause a NULL pointer dereference.
**Fix**:
```
static int32_t HssCtrlGetLevels(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < sizeof(uint32_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (ctx->para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    *(uint32_t *)val = ctx->para->levels;
    return CRYPT_SUCCESS;
}
```

---

### NULL pointer dereference in HssCtrlGetSigLen
`crypto/lms/src/hss_api.c:245-264`
```
static int32_t HssCtrlGetSigLen(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < sizeof(uint32_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }

    if (ctx->para->pubKeyLen == 0) {  // NULL pointer dereference
        int32_t ret = HssParaInit(ctx->para, ctx->para->levels, ctx->para->lmsType, ctx->para->otsType);
```
**Issue**: The function HssCtrlGetSigLen dereferences ctx->para without checking if it's NULL. This could cause a crash when called on a context with uninitialized or freed para.
**Fix**:
```
static int32_t HssCtrlGetSigLen(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < sizeof(uint32_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }

    if (ctx->para == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->para->pubKeyLen == 0) {
        int32_t ret = HssParaInit(ctx->para, ctx->para->levels, ctx->para->lmsType, ctx->para->otsType);
```

---

### NULL pointer dereference in HssCtrlGetRemaining
`crypto/lms/src/hss_api.c:267-288`
```
static int32_t HssCtrlGetRemaining(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < sizeof(uint64_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }

    if (ctx->para->pubKeyLen == 0) {  // NULL pointer dereference
```
**Issue**: The function HssCtrlGetRemaining dereferences ctx->para without checking if it's NULL.
**Fix**:
```
static int32_t HssCtrlGetRemaining(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < sizeof(uint64_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }

    if (ctx->para == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (ctx->para->pubKeyLen == 0) {
```

---

### NULL pointer dereference in HssCtrlSetLmsType
`crypto/lms/src/hss_api.c:185-203`
```
static int32_t HssCtrlSetLmsType(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < 2 * sizeof(uint32_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    uint32_t *params = (uint32_t *)val;
    uint32_t levelIdx = params[0];
    uint32_t lmsType = params[1];

    if (levelIdx >= ctx->para->levels) {  // NULL pointer dereference
```
**Issue**: The function HssCtrlSetLmsType dereferences ctx->para without checking if it's NULL before accessing ctx->para->levels.
**Fix**:
```
static int32_t HssCtrlSetLmsType(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < 2 * sizeof(uint32_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (ctx->para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t *params = (uint32_t *)val;
    uint32_t levelIdx = params[0];
    uint32_t lmsType = params[1];

    if (levelIdx >= ctx->para->levels) {
```

---

### NULL pointer dereference in HssCtrlSetOtsType
`crypto/lms/src/hss_api.c:206-224`
```
static int32_t HssCtrlSetOtsType(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < 2 * sizeof(uint32_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    uint32_t *params = (uint32_t *)val;
    uint32_t levelIdx = params[0];
    uint32_t otsType = params[1];

    if (levelIdx >= ctx->para->levels) {  // NULL pointer dereference
```
**Issue**: The function HssCtrlSetOtsType dereferences ctx->para without checking if it's NULL before accessing ctx->para->levels.
**Fix**:
```
static int32_t HssCtrlSetOtsType(CRYPT_HSS_Ctx *ctx, void *val, uint32_t valLen)
{
    if (valLen < 2 * sizeof(uint32_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    if (ctx->para == NULL) {
        return CRYPT_NULL_INPUT;
    }
    uint32_t *params = (uint32_t *)val;
    uint32_t levelIdx = params[0];
    uint32_t otsType = params[1];

    if (levelIdx >= ctx->para->levels) {
```

---

### NULL pointer dereference in CRYPT_HSS_SetPubKey
`crypto/lms/src/hss_api.c:360-395`
```
int32_t CRYPT_HSS_SetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }

    // Find public key parameter
    const BSL_Param *pubKeyParam = BSL_PARAM_FindConstParam(param, CRYPT_PARAM_HSS_PUBKEY);
    if (pubKeyParam == NULL || pubKeyParam->value == NULL) {
        return CRYPT_HSS_NO_KEY;
    }

    if (pubKeyParam->valueLen != HSS_PUBKEY_LEN) {
        return CRYPT_HSS_INVALID_KEY_LEN;
    }

    // Copy public key
    (void)memcpy_s(ctx->publicKey, HSS_PUBKEY_LEN, pubKeyParam->value, HSS_PUBKEY_LEN);

    // Extract and validate parameters from public key
    uint32_t levels = (uint32_t)LmsGetBigendian(ctx->publicKey + HSS_PUBKEY_LEVELS_OFFSET, LMS_TYPE_LEN);
    uint32_t lmsType = (uint32_t)LmsGetBigendian(ctx->publicKey + HSS_PUBKEY_LMS_TYPE_OFFSET, LMS_TYPE_LEN);
    uint32_t otsType = (uint32_t)LmsGetBigendian(ctx->publicKey + HSS_PUBKEY_OTS_TYPE_OFFSET, LMS_TYPE_LEN);

    if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
        return CRYPT_HSS_INVALID_PARAM;
    }

    // Store top-level parameters
    ctx->para->levels = levels;  // NULL pointer dereference
    ctx->para->lmsType[0] = lmsType;
    ctx->para->otsType[0] = otsType;
```
**Issue**: The function CRYPT_HSS_SetPubKey dereferences ctx->para without checking if it's NULL before storing the levels and type values.
**Fix**:
```
int32_t CRYPT_HSS_SetPubKey(CRYPT_HSS_Ctx *ctx, BSL_Param *param)
{
    if (ctx == NULL || ctx->para == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
```

---


## Medium

### Unnecessary memory zeroization after freeing members in CRYPT_HSS_FreeCtx
`crypto/lms/src/hss_api.c:72-95`
```
int32_t CRYPT_HSS_FreeCtx(CRYPT_HSS_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_SUCCESS;
    }

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

    LmsZeroize(ctx, sizeof(CRYPT_HSS_Ctx));  // Unnecessary - ctx will be freed immediately
    BSL_SAL_Free(ctx);
    return CRYPT_SUCCESS;
}
```
**Issue**: The function calls LmsZeroize(ctx, sizeof(CRYPT_HSS_Ctx)) after freeing ctx->privateKey, ctx->publicKey, and ctx->para. Since ctx is about to be freed, zeroizing the context structure itself is unnecessary. Additionally, the code reads the just-freed pointer values (though not dereferenced) which is poor practice.
**Fix**:
```
int32_t CRYPT_HSS_FreeCtx(CRYPT_HSS_Ctx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_SUCCESS;
    }

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

    BSL_SAL_Free(ctx);
    return CRYPT_SUCCESS;
}
```

---


## Low

### Missing NULL ctx check in HssCtrlGetPubKeyLen
`crypto/lms/src/hss_api.c:227-234`
```
static int32_t HssCtrlGetPubKeyLen(void *val, uint32_t valLen)
{
    if (valLen < sizeof(uint32_t)) {
        return CRYPT_HSS_INVALID_PARAM;
    }
    *(uint32_t *)val = HSS_PUBKEY_LEN;
    return CRYPT_SUCCESS;
}
```
**Issue**: While HssCtrlGetPubKeyLen doesn't dereference ctx (it only returns a constant), the function signature accepts CRYPT_HSS_Ctx *ctx but doesn't validate it. This is inconsistent with other ctrl functions and could lead to confusion.

---
