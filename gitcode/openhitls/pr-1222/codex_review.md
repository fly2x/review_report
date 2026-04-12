# Code Review: openHiTLS/openhitls#1222
**Reviewer**: CODEX


## High

### Deferred output writes can overflow or corrupt caller buffers
`crypto/modes/src/modes_gcm_siv.c:236-319`
```
if (out != NULL && modeCtx->outPtr == NULL) {
    modeCtx->outPtr = out;
}
...
*outLen = 0;
...
if (ctx->msgLen > 0) {
    ret = AesCtrGcmSiv(encKey, encKeyLen, ctr, ctx->msgBuf, ctx->msgLen, ctx->outPtr);
}
...
if (ctLen > 0) {
    ...
    if (ctLen > 0 && plain != NULL) {
        (void)memcpy_s(ctx->outPtr, ctLen, plain, ctLen);
    }
}
```
**Issue**: `MODES_GCM_SIV_Update()` buffers all input, forces `*outLen = 0`, and only remembers the first `out` pointer. `GET_TAG` later writes the entire buffered message to that raw pointer without checking how much space the caller actually advertised, and without validating later `Update()` calls use the same contiguous buffer. A caller can therefore pass a tiny first buffer or different per-chunk buffers and trigger an out-of-bounds write when `GET_TAG` runs.
**Fix**:
```
/* add to ModesGcmSivCtx */
uint32_t outCap;

int32_t MODES_GCM_SIV_Update(struct ModesGcmSivCtx *modeCtx, const uint8_t *in, uint32_t inLen,
    uint8_t *out, uint32_t *outLen)
{
    ...
    if (inLen == 0) {
        *outLen = 0;
        return CRYPT_SUCCESS;
    }
    if (out == NULL || *outLen < inLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }

    if (modeCtx->outPtr == NULL) {
        modeCtx->outPtr = out;
        modeCtx->outCap = *outLen;
    } else {
        if (out != modeCtx->outPtr + modeCtx->msgLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
            return CRYPT_EAL_ERR_STATE;
        }
        if (modeCtx->outCap < modeCtx->msgLen + *outLen) {
            modeCtx->outCap = modeCtx->msgLen + *outLen;
        }
    }

    ...
    *outLen = 0;
    return CRYPT_SUCCESS;
}

static int32_t GcmSivEncryptFinish(struct ModesGcmSivCtx *ctx, uint8_t *tagBuf, uint32_t tagLen)
{
    ...
    if (ctx->msgLen > ctx->outCap) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    ...
}

static int32_t GcmSivDecryptFinish(struct ModesGcmSivCtx *ctx, uint8_t *tagOut, uint32_t tagLen)
{
    ...
    if (ctLen > ctx->outCap) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODE_BUFF_LEN_NOT_ENOUGH);
        return CRYPT_MODE_BUFF_LEN_NOT_ENOUGH;
    }
    ...
}
```

---


## Medium

### Buffered message length can wrap on repeated Update calls
`crypto/modes/src/modes_gcm_siv.c:462-469`
```
uint8_t *nbuf = BSL_SAL_Realloc(modeCtx->msgBuf, modeCtx->msgLen + inLen, modeCtx->msgLen);
if (nbuf == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
    return CRYPT_MEM_ALLOC_FAIL;
}
modeCtx->msgBuf = nbuf;
(void)memcpy_s(modeCtx->msgBuf + modeCtx->msgLen, inLen, in, inLen);
modeCtx->msgLen += inLen;
```
**Issue**: `modeCtx->msgLen + inLen` is computed in `uint32_t` with no overflow check before `BSL_SAL_Realloc()`. After enough `Update()` calls, the addition wraps, a too-small buffer is allocated, and the subsequent `memcpy_s()` / `msgLen += inLen` operate on an invalid logical size.
**Fix**:
```
if (modeCtx->msgLen > UINT32_MAX - inLen) {
    BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
    return CRYPT_MODES_CRYPTLEN_OVERFLOW;
}

uint32_t newLen = modeCtx->msgLen + inLen;
uint8_t *nbuf = BSL_SAL_Realloc(modeCtx->msgBuf, newLen, modeCtx->msgLen);
if (nbuf == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
    return CRYPT_MEM_ALLOC_FAIL;
}
modeCtx->msgBuf = nbuf;
(void)memcpy_s(modeCtx->msgBuf + modeCtx->msgLen, newLen - modeCtx->msgLen, in, inLen);
modeCtx->msgLen = newLen;
```

---

### POLYVAL input size arithmetic can under-allocate for large inputs
`crypto/modes/src/modes_gcm_siv.c:166-176`
```
static uint32_t Pad16Len(uint32_t len)
{
    return (len + GCM_BLOCKSIZE - 1u) & ~(GCM_BLOCKSIZE - 1u);
}
...
uint32_t padAad = Pad16Len(ctx->aadLen);
uint32_t padPt = Pad16Len(ptLen);
uint32_t total = padAad + padPt + GCM_BLOCKSIZE;
uint8_t *buf = BSL_SAL_Malloc(total);
```
**Issue**: `Pad16Len()` and `total = padAad + padPt + GCM_BLOCKSIZE` both use unchecked 32-bit arithmetic. Large AAD or plaintext lengths can wrap during padding/total-size calculation, causing `BSL_SAL_Malloc(total)` to allocate too little memory and making the later `memcpy_s()` writes inconsistent with the logical input sizes.
**Fix**:
```
static int32_t Pad16Len(uint32_t len, uint32_t *padded)
{
    if (len > UINT32_MAX - (GCM_BLOCKSIZE - 1u)) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }
    *padded = (len + GCM_BLOCKSIZE - 1u) & ~(GCM_BLOCKSIZE - 1u);
    return CRYPT_SUCCESS;
}

static int32_t BuildPolyInput(struct ModesGcmSivCtx *ctx, const uint8_t *plaintext, uint32_t ptLen,
    uint8_t **polyBuf, uint32_t *polyLen)
{
    uint32_t padAad;
    uint32_t padPt;
    int32_t ret = Pad16Len(ctx->aadLen, &padAad);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = Pad16Len(ptLen, &padPt);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (padAad > UINT32_MAX - padPt - GCM_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_CRYPTLEN_OVERFLOW);
        return CRYPT_MODES_CRYPTLEN_OVERFLOW;
    }

    uint32_t total = padAad + padPt + GCM_BLOCKSIZE;
    ...
}
```

---

### DupCtx clones a caller-owned output pointer into the new context
`crypto/modes/src/modes_gcm_siv.c:615-634`
```
const struct ModesGcmSivCtx *src = modeCtx;
struct ModesGcmSivCtx *ctx = BSL_SAL_Dump(src, sizeof(struct ModesGcmSivCtx));
if (ctx == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
    return NULL;
}
ctx->aadBuf = NULL;
ctx->msgBuf = NULL;
...
return ctx;
```
**Issue**: `BSL_SAL_Dump(src, sizeof(struct ModesGcmSivCtx))` copies the entire struct, including `outPtr`, which points into caller memory rather than internal state. If the context is duplicated after `Update()`, the duplicate will later write ciphertext/plaintext into the original caller buffer on `GET_TAG`, corrupting memory and violating `CopyCtx`/`DupCtx` semantics.
**Fix**:
```
MODES_GCM_SIV_Ctx *MODES_GCM_SIV_DupCtx(const MODES_GCM_SIV_Ctx *modeCtx)
{
    if (modeCtx == NULL) {
        return NULL;
    }
    const struct ModesGcmSivCtx *src = modeCtx;

    /* Safe immediate fix: do not duplicate an in-progress context that depends on caller buffers. */
    if (src->msgLen != 0 || src->outPtr != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return NULL;
    }

    struct ModesGcmSivCtx *ctx = BSL_SAL_Dump(src, sizeof(struct ModesGcmSivCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->outPtr = NULL;
    ctx->aadBuf = NULL;
    ctx->msgBuf = NULL;
    ...
}
```

---

### GCM-SIV decryption breaks the existing AEAD API contract
`crypto/modes/src/modes_gcm_siv.c:286-299`
```
if (ctx->msgLen < GCM_BLOCKSIZE) {
    BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
    return CRYPT_INVALID_ARG;
}
uint32_t ctLen = ctx->msgLen - GCM_BLOCKSIZE;
...
const uint8_t *recvTag = ctx->msgBuf + ctLen;
...
ret = AesCtrGcmSiv(encKey, encKeyLen, ctr, ctx->msgBuf, ctLen, plain);
```
**Issue**: The implementation treats the last 16 bytes passed to `Update()` as the authentication tag. That is not how the existing `CRYPT_EAL_Cipher*` AEAD API works for GCM/CCM/ChaCha20-Poly1305, where `Update()` consumes ciphertext and `CipherCtrl(GET_TAG)` handles the tag separately. As written, generic AEAD callers cannot use AES-GCM-SIV correctly without a hidden `ciphertext || tag` special case.
**Fix**:
```
/* add to ModesGcmSivCtx */
uint8_t expectedTag[GCM_BLOCKSIZE];
bool hasExpectedTag;

static int32_t SetExpectedTag(struct ModesGcmSivCtx *ctx, const uint8_t *tag, uint32_t len)
{
    if (tag == NULL || len != GCM_BLOCKSIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_MODES_TAGLEN_ERROR);
        return CRYPT_MODES_TAGLEN_ERROR;
    }
    (void)memcpy_s(ctx->expectedTag, sizeof(ctx->expectedTag), tag, len);
    ctx->hasExpectedTag = true;
    return CRYPT_SUCCESS;
}

int32_t MODES_GCM_SIV_Ctrl(MODES_GCM_SIV_Ctx *modeCtx, int32_t cmd, void *val, uint32_t len)
{
    ...
    case CRYPT_CTRL_SET_TAG:
        return SetExpectedTag(ctx, val, len);
    case CRYPT_CTRL_GET_TAG:
        return ctx->enc ? GcmSivEncryptFinish(ctx, val, len) : GcmSivDecryptFinish(ctx, val, len);
    ...
}

static int32_t GcmSivDecryptFinish(struct ModesGcmSivCtx *ctx, uint8_t *tagOut, uint32_t tagLen)
{
    if (!ctx->hasExpectedTag) {
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_STATE);
        return CRYPT_EAL_ERR_STATE;
    }

    const uint8_t *recvTag = ctx->expectedTag;
    uint32_t ctLen = ctx->msgLen;
    ...
}
```

---
