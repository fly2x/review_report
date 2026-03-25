# Code Review: openHiTLS/sdfp#9
**Reviewer**: CLAUDE


## High

### String literal passed as non-const pointer may cause undefined behavior
`src/rsa/rsa_sign.c:117-119`
```
ret = SDF_DL_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex,
        ctx->pass != NULL ? ctx->pass : (unsigned char *)DEFAULT_PASS,
        ctx->pass != NULL ? ctx->passLen : DEFAULT_PASS_LEN);
```
**Issue**: When ctx->pass == NULL, the code passes (unsigned char *)DEFAULT_PASS to SDF_DL_GetPrivateKeyAccessRight. DEFAULT_PASS is a string literal defined in provider.h as "#define DEFAULT_PASS "12345678"", which is stored in read-only memory. The cast to unsigned char * removes the const qualifier. If the SDF SDK modifies the password buffer, it will cause undefined behavior (segmentation fault or memory corruption).

This is inconsistent with provider.c which properly allocates a heap buffer and copies the default password (lines 209-220).
**Fix**:
```
/* Use a static writable buffer for the default password */
static uint8_t g_defaultPassBuffer[] = "12345678";
ret = SDF_DL_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex,
        ctx->pass != NULL ? ctx->pass : g_defaultPassBuffer,
        ctx->pass != NULL ? ctx->passLen : sizeof(g_defaultPassBuffer) - 1);
```

---

### String literal passed as non-const pointer may cause undefined behavior
`src/rsa/rsa_pkeycipher.c:159-160`
```
ret = SDF_DL_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex,
        ctx->pass != NULL ? ctx->pass : (unsigned char *)DEFAULT_PASS,
        ctx->pass != NULL ? ctx->passLen : DEFAULT_PASS_LEN);
```
**Issue**: When ctx->pass == NULL, the code passes (unsigned char *)DEFAULT_PASS to SDF_DL_GetPrivateKeyAccessRight. DEFAULT_PASS is a string literal stored in read-only memory. The cast to unsigned char * removes the const qualifier. If the SDF SDK modifies the password buffer, it will cause undefined behavior.
**Fix**:
```
/* Use a static writable buffer for the default password */
static uint8_t g_defaultPassBuffer[] = "12345678";
ret = SDF_DL_GetPrivateKeyAccessRight(ctx->hSessionHandle, ctx->keyIndex,
        ctx->pass != NULL ? ctx->pass : g_defaultPassBuffer,
        ctx->pass != NULL ? ctx->passLen : sizeof(g_defaultPassBuffer) - 1);
```

---
