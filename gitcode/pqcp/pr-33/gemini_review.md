# Code Review: openHiTLS/pqcp#33
**Reviewer**: GEMINI


## High

### Missing NULL Check for Input Parameter
`src/composite_sign/src/crypt_composite_sign.c:228`
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYLEN_ERROR);
        return PQCP_COMPOSITE_KEYLEN_ERROR;
    }
    if (ctx->ctxInfo != NULL) {
```
**Issue**: The function `CRYPT_CompositeSetctxInfo` does not check if `val` is NULL before passing it to `BSL_SAL_Dump` (which presumably copies from it). If `len > 0` but `val` is NULL, this will likely cause a segmentation fault.
**Fix**:
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(PQCP_COMPOSITE_KEYLEN_ERROR);
        return PQCP_COMPOSITE_KEYLEN_ERROR;
    }
    if (val == NULL && len > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (ctx->ctxInfo != NULL) {
```

---

### Ignored Return Value of Secure Memory Copy
`src/composite_sign/src/crypt_composite_sign.c:541-546`
```
(void)memcpy_s(ptr, msg->len, PREFIX, prefixLen);
    ptr += prefixLen;
    (void)memcpy_s(ptr, msg->len - prefixLen, label, labelLen);
    ptr += labelLen;
    *ptr = ctx->ctxLen;
    ptr++;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        (void)memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1), ctx->ctxInfo, ctx->ctxLen);
        ptr += ctx->ctxLen;
    }
```
**Issue**: The return value of `memcpy_s` is explicitly ignored (`(void)memcpy_s(...)`) in `CompositeMsgEncode`. If `memcpy_s` fails (e.g., due to invalid overlap or size parameters), the destination buffer `msg->data` will contain uninitialized or partial data. The function then returns `CRYPT_SUCCESS`, causing the caller to sign/verify this invalid data.
**Fix**:
```
if (memcpy_s(ptr, msg->len, PREFIX, prefixLen) != EOK) {
        BSL_SAL_FREE(msg->data);
        return CRYPT_MEM_CPY_FAIL;
    }
    ptr += prefixLen;
    if (memcpy_s(ptr, msg->len - prefixLen, label, labelLen) != EOK) {
        BSL_SAL_FREE(msg->data);
        return CRYPT_MEM_CPY_FAIL;
    }
    ptr += labelLen;
    *ptr = ctx->ctxLen;
    ptr++;
    if (ctx->ctxInfo != NULL && ctx->ctxLen > 0) {
        if (memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1), ctx->ctxInfo, ctx->ctxLen) != EOK) {
            BSL_SAL_FREE(msg->data);
            return CRYPT_MEM_CPY_FAIL;
        }
        ptr += ctx->ctxLen;
    }
```

---

### Breaking API Change in Parameter IDs
`include/pqcp_types.h:22-42`
```
#define PQCP_PARAM_BASE 5000
#define PQCP_PARAM_SCLOUDPLUS_BASE (PQCP_PARAM_BASE + 100)
// ...
#define PQCP_PARAM_FRODOKEM_BASE (PQCP_PARAM_BASE + 200)
```
**Issue**: The parameter ID base values have changed significantly (e.g., `CRYPT_PARAM_SCLOUDPLUS_BASE` 900 -> `PQCP_PARAM_SCLOUDPLUS_BASE` 5100). This is a binary and source incompatibility for any external application relying on the old values. While the rename suggests an API refactor, changing the underlying integer values breaks ABI with existing compiled code.
**Fix**:
```
/* Ensure these values align with external expectations or version the API explicitly. 
   If backward compatibility is required, restore original values: */
#define PQCP_PARAM_BASE 900 // Adjusted base if necessary
// Or map specific bases back to 900, 1000, 1100, 1200 as before.
```

---


## Medium

### Incomplete Public Key Length Validation
`src/composite_sign/src/crypt_composite_sign.c:366`
```
RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);

    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
```
**Issue**: `CRYPT_COMPOSITE_SetPubKey` checks if `pub->len` is greater than `pqcPubkeyLen`, but it does not check if `pub->len` exactly matches the expected composite public key length (`ctx->info->compPubKeyLen`). Excessively large `pub->len` will result in a larger-than-expected `tradPub` buffer being passed to the traditional method, relying on that method's validation which may be insufficient.
**Fix**:
```
RETURN_RET_IF(pub->len != ctx->info->compPubKeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);

    BSL_Buffer pqcPub = {pub->data, ctx->info->pqcPubkeyLen};
    BSL_Buffer tradPub = {pub->data + ctx->info->pqcPubkeyLen, pub->len - ctx->info->pqcPubkeyLen};
```

---

### Incomplete Private Key Length Validation
`src/composite_sign/src/crypt_composite_sign.c:351`
```
RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```
**Issue**: `CRYPT_COMPOSITE_SetPrvKey` checks if `prv->len` is greater than `pqcPrvkeyLen`, but does not enforce that `prv->len` matches `ctx->info->compPrvKeyLen`. This allows passing arbitrarily large buffers as the private key, potentially causing issues in the underlying traditional key setter.
**Fix**:
```
RETURN_RET_IF(prv->len != ctx->info->compPrvKeyLen, PQCP_COMPOSITE_KEYLEN_ERROR);
    BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```

---


## Low

### Commented Out Error Handling
`src/provider/pqcp_pkey.c:51`
```
if (pkeyCtx == NULL) {
        // BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
```
**Issue**: The error reporting macro `BSL_ERR_PUSH_ERROR` is commented out. If context creation fails (e.g., unsupported algorithm), the function returns NULL without pushing an error code to the stack, making diagnostics difficult.
**Fix**:
```
if (pkeyCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return NULL;
    }
```

---
