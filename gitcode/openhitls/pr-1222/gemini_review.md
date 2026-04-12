# Code Review: openHiTLS/openhitls#1222
**Reviewer**: GEMINI


## Critical

### Integer Overflow in Polyval Buffer Allocation Leading to Heap Overflow
`crypto/modes/src/modes_gcm_siv.c:154`
```
static int32_t BuildPolyInput(struct ModesGcmSivCtx *ctx, const uint8_t *plaintext, uint32_t ptLen,
    uint8_t **polyBuf, uint32_t *polyLen)
{
    uint32_t padAad = Pad16Len(ctx->aadLen);
    uint32_t padPt = Pad16Len(ptLen);
    uint32_t total = padAad + padPt + GCM_BLOCKSIZE;
    uint8_t *buf = BSL_SAL_Malloc(total);
```
**Issue**: When calculating `total` length for the polyval input buffer, `padAad + padPt + GCM_BLOCKSIZE` can overflow if `ctx->aadLen` and `ptLen` are large, particularly because `Pad16Len` can wrap around if the length is close to `UINT32_MAX`. This causes `BSL_SAL_Malloc` to allocate a small buffer. Subsequent `memcpy_s` operations will use wrapped `destMax` values and write out of bounds, leading to a massive heap buffer overflow.
**Fix**:
```
static int32_t BuildPolyInput(struct ModesGcmSivCtx *ctx, const uint8_t *plaintext, uint32_t ptLen,
    uint8_t **polyBuf, uint32_t *polyLen)
{
    uint32_t padAad = Pad16Len(ctx->aadLen);
    uint32_t padPt = Pad16Len(ptLen);
    if (padAad < ctx->aadLen || padPt < ptLen || (UINT32_MAX - padAad - GCM_BLOCKSIZE) < padPt) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint32_t total = padAad + padPt + GCM_BLOCKSIZE;
    uint8_t *buf = BSL_SAL_Malloc(total);
```

---

### AES-GCM-SIV DupCtx Output Pointer Alias Causes Heap Buffer Overflow
`crypto/modes/src/modes_gcm_siv.c:622`
```
MODES_GCM_SIV_Ctx *MODES_GCM_SIV_DupCtx(const MODES_GCM_SIV_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return NULL;
    }
    const struct ModesGcmSivCtx *src = modeCtx;
    struct ModesGcmSivCtx *ctx = BSL_SAL_Dump(src, sizeof(struct ModesGcmSivCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->aadBuf = NULL;
    ctx->msgBuf = NULL;
```
**Issue**: `MODES_GCM_SIV_DupCtx` performs a shallow copy of the source context using `BSL_SAL_Dump`, which includes copying `src->outPtr`. Because `outPtr` acts as the persistent destination for the entire buffered ciphertext, if the duplicate context receives additional data via `Update`, it will write its expanded combined ciphertext to the original `outPtr` buffer upon finalization. This results in an out-of-bounds write since the original `outPtr` buffer was likely allocated only for the original message length. The duplicate context must clear `outPtr` so a new, appropriately sized output buffer can be provided.
**Fix**:
```
MODES_GCM_SIV_Ctx *MODES_GCM_SIV_DupCtx(const MODES_GCM_SIV_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return NULL;
    }
    const struct ModesGcmSivCtx *src = modeCtx;
    struct ModesGcmSivCtx *ctx = BSL_SAL_Dump(src, sizeof(struct ModesGcmSivCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->aadBuf = NULL;
    ctx->msgBuf = NULL;
    ctx->outPtr = NULL;
```

---


## High

### Integer Overflow in MODES_GCM_SIV_Update msgLen Causes Heap Overflow
`crypto/modes/src/modes_gcm_siv.c:462`
```
if (inLen == 0) {
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    uint8_t *nbuf = BSL_SAL_Realloc(modeCtx->msgBuf, modeCtx->msgLen + inLen, modeCtx->msgLen);
```
**Issue**: In `MODES_GCM_SIV_Update`, the sum `modeCtx->msgLen + inLen` can overflow if a large amount of data is updated across multiple calls. This leads to `BSL_SAL_Realloc` allocating a smaller buffer than required, and the subsequent `memcpy_s` copying data out of bounds, resulting in a heap buffer overflow.
**Fix**:
```
if (inLen == 0) {
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    if (UINT32_MAX - modeCtx->msgLen < inLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    uint8_t *nbuf = BSL_SAL_Realloc(modeCtx->msgBuf, modeCtx->msgLen + inLen, modeCtx->msgLen);
```

---


## Medium

### AES-GCM-SIV Fails for Zero-Length Messages
`crypto/modes/src/modes_gcm_siv.c:242`
```
if (ctx->outPtr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
```
**Issue**: In `GcmSivEncryptFinish`, the code unconditionally checks `if (ctx->outPtr == NULL)` and returns an error. For zero-length plaintexts (e.g. when an application uses AES-GCM-SIV strictly for authenticating AAD), it is completely valid and common for the output pointer to be `NULL` since there is no ciphertext to write.
**Fix**:
```
if (ctx->msgLen > 0 && ctx->outPtr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
```

---

### AES-GCM-SIV Decryption Fails for Empty Ciphertext
`crypto/modes/src/modes_gcm_siv.c:295`
```
if (ctx->outPtr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
```
**Issue**: Similar to the encryption path, `GcmSivDecryptFinish` rejects a `NULL` `outPtr` even when the ciphertext length (`ctLen`) is zero. This prevents verification of empty payloads.
**Fix**:
```
if (ctLen > 0 && ctx->outPtr == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }
```

---

### CstTimeTagCmp returns HPKE-specific error code
`crypto/modes/src/modes_gcm_siv.c:233`
```
return (d == 0) ? CRYPT_SUCCESS : CRYPT_HPKE_ERR_AEAD_TAG;
```
**Issue**: The `CstTimeTagCmp` function incorrectly returns `CRYPT_HPKE_ERR_AEAD_TAG` when tag verification fails. This mixes module boundaries by propagating an HPKE-specific error out of a generic AES mode component, which breaks generic EAL error handling logic. It should return a generic invalid argument or state error.
**Fix**:
```
return (d == 0) ? CRYPT_SUCCESS : CRYPT_INVALID_ARG;
```

---
