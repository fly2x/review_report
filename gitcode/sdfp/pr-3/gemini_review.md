# Code Review: openHiTLS/sdfp#3
**Reviewer**: GEMINI


## Critical

### Unsafe library unloading (Use-After-Free/Unload)
`src/sdf_dl.c:93-167`
```
static void *g_sdfLibHandle = NULL;

// ...

int32_t SDF_DL_Load(const char *libPath)
{
    if (libPath == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return -1;
    }

    if (g_sdfLibHandle != NULL) {
        return 0;
    }

// ...

void SDF_DL_Unload(void)
{
    if (g_sdfLibHandle != NULL) {
        dlclose(g_sdfLibHandle);
        g_sdfLibHandle = NULL;
    }
    (void)memset(&g_sdfFunc, 0, sizeof(g_sdfFunc));
}
```
**Issue**: The `SDF_DL_Load` function checks if `g_sdfLibHandle` is non-NULL to avoid reloading, but it does not increment a reference count. Conversely, `SDF_DL_Unload` unconditionally closes the library handle and clears function pointers. If multiple provider contexts are initialized (sharing the global library handle) and one is freed, it will unload the library, causing the remaining active contexts to crash or behave undefinedly when they try to use SDF functions.
**Fix**:
```
static void *g_sdfLibHandle = NULL;
static int g_loadCount = 0;

// ...

int32_t SDF_DL_Load(const char *libPath)
{
    if (libPath == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_NULL_INPUT);
        return -1;
    }

    if (g_sdfLibHandle != NULL) {
        g_loadCount++;
        return 0;
    }

    g_sdfLibHandle = dlopen(libPath, RTLD_NOW | RTLD_LOCAL);
    if (g_sdfLibHandle == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_INTERNAL_EXCEPTION);
        return -1;
    }
    g_loadCount = 1;

// ...

void SDF_DL_Unload(void)
{
    if (g_loadCount > 0) {
        g_loadCount--;
    }
    if (g_loadCount == 0 && g_sdfLibHandle != NULL) {
        dlclose(g_sdfLibHandle);
        g_sdfLibHandle = NULL;
        (void)memset(&g_sdfFunc, 0, sizeof(g_sdfFunc));
    }
}
```

---


## High

### Thread safety race condition in library loading
`src/sdf_dl.c:111-118`
```
if (g_sdfLibHandle != NULL) {
        return 0;
    }

    g_sdfLibHandle = dlopen(libPath, RTLD_NOW | RTLD_LOCAL);
```
**Issue**: `SDF_DL_Load` accesses and modifies the global `g_sdfLibHandle` without any locking. If two threads attempt to initialize the provider simultaneously, they may both check `g_sdfLibHandle == NULL`, and both proceed to call `dlopen` and overwrite `g_sdfLibHandle`, or one might use partially initialized function pointers.
**Fix**:
```
/* Note: Ideally use pthread_mutex or similar, but for a simple fix assuming single-threaded init or external sync: */
    /* If external synchronization isn't guaranteed, a mutex is required here. */
    /* Since we cannot easily add pthreads here without seeing build flags, we assume the caller synchronizes or we add a TODO */
    /* Example fix using GCC atomic builtins if available, or just flagging it */
    
    /* Better fix involves a mutex. Since I can't add a mutex variable easily to the global scope without includes: */
    /* Suggest adding a static mutex and locking around the load/unload logic. */
```

---


## Medium

### Hardcoded static library extension
`CMakeLists.txt:39-44`
```
find_library(HITLS_BSL_LIB libhitls_bsl.a
    PATHS ${HITLS_LIB_DIR}
    REQUIRED
)

find_library(HITLS_CRYPTO_LIB libhitls_crypto.a
    PATHS ${HITLS_LIB_DIR}
    REQUIRED
)
```
**Issue**: The build script hardcodes `.a` extension (`libhitls_bsl.a`, `libhitls_crypto.a`). This reduces portability across systems that might use different naming conventions or where only shared libraries are available.
**Fix**:
```
find_library(HITLS_BSL_LIB NAMES hitls_bsl libhitls_bsl
    PATHS ${HITLS_LIB_DIR}
    REQUIRED
)

find_library(HITLS_CRYPTO_LIB NAMES hitls_crypto libhitls_crypto
    PATHS ${HITLS_LIB_DIR}
    REQUIRED
)
```

---

### Memory leak in Key Exchange generation
`src/sm2_keymgmt.c:104`
```
ret = SDF_DL_GenerateAgreementDataWithECC(ctx->hSessionHandle, ctx->KeyIndex,
                    128, ctx->userId, ctx->userIdLen,
                    &sdfSelfPub, &sdfTmpPub, &ctx->hAgreementHandle);
```
**Issue**: In `CRYPT_SM2_Gen` (Key Exchange mode), if `ctx->tmpPubKey` is already allocated (e.g. from a previous call), it is freed. However, `ctx->hAgreementHandle` is unconditionally overwritten. If the SDF implementation allocates resources for this handle, they are leaked. Additionally, `CRYPT_SM2_FreeCtx` sets `hAgreementHandle` to NULL without closing it, potentially leaking resources if the session close doesn't handle it.
**Fix**:
```
/* Ensure previous handle is not overwritten/leaked if re-used */
            if (ctx->hAgreementHandle != NULL) {
                 /* Assuming handle is session-bound or opaque, strictly we can't close it without an API.
                  * But we should error if it's already active to prevent misuse. */
                 return CRYPT_INVALID_ARG; 
            }
            ret = SDF_DL_GenerateAgreementDataWithECC(ctx->hSessionHandle, ctx->KeyIndex,
                    128, ctx->userId, ctx->userIdLen,
                    &sdfSelfPub, &sdfTmpPub, &ctx->hAgreementHandle);
```

---


## Low

### Incorrect error code pushed
`src/provider.c:128`
```
if (sdfLibPath == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        return CRYPT_INVALID_ARG;
    }
```
**Issue**: When `sdfLibPath` is NULL (because the parameter was missing), the code pushes `ret` to the error stack. However, `ret` holds the result of previous operations (likely `CRYPT_SUCCESS` / 0), which is not a valid error code to push.
**Fix**:
```
if (sdfLibPath == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
```

---
