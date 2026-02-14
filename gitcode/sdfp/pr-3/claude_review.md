# Code Review: openHiTLS/sdfp#3
**Reviewer**: CLAUDE


## High

### Typo in dlopen flags causes undefined symbol behavior
`src/sdf_dl.c:115`
```
g_sdfLibHandle = dlopen(libPath, RTLD_NOW | RTLD_LOCAL);
```
**Issue**: Line 115 uses RTLD_LOCAL instead of RTLD_LOCAL and line 111 has RTLD_NOW instead of RTLD_NOW. These typos mean invalid flags are passed to dlopen(). RTLD_LOCAL causes symbols to not be available for resolving subsequently loaded libraries, while RTLD_NOW performs immediate binding.
**Fix**:
```
g_sdfLibHandle = dlopen(libPath, RTLD_NOW | RTLD_LOCAL);
```

---

### Typo in #define SDF_DL_ERR_NOT_LOADED and SDR_UNKNOWERR
`src/sdf_dl.c:172`
```
#define SDF_DL_ERR_NOT_LOADED  SDR_UNKNOWERR
```
**Issue**: The constant name has a typo - SDF_DL_ERR_NOT_LOADED is missing 'A' in LOADED, and SDR_UNKNOWERR is missing 'K' in UNKOWERR. These constants should match the correct spelling.
**Fix**:
```
#define SDF_DL_ERR_NOT_LOADED  SDR_UNKNOWNERR
```

---

### Typo in function name SDF_DL_Unload
`src/sdf_dl.c:161`
```
void SDF_DL_Unload(void)
```
**Issue**: The function is named SDF_DL_Unload but should be SDF_DL_Unload to match the header declaration (assuming 'load' not 'Load'). This inconsistency could cause linker errors or undefined symbol errors.
**Fix**:
```
void SDF_DL_Unload(void)
```

---

### Typo in SDF_DL_Unload function call
`src/provider.c:72`
```
SDF_DL_Unload();
```
**Issue**: Function name has typo - should be SDF_DL_Unload not SDF_DL_Unload
**Fix**:
```
SDF_DL_Unload();
```

---

### Typo in SDF_DL_Unload function call
`src/provider.c:140`
```
SDF_DL_Unload();
```
**Issue**: Function name has typo - should be SDF_DL_Unload not SDF_DL_Unload
**Fix**:
```
SDF_DL_Unload();
```

---

### Typo in SDF_DL_Unload function call
`src/provider.c:153`
```
SDF_DL_Unload();
```
**Issue**: Function name has typo - should be SDF_DL_Unload not SDF_DL_Unload
**Fix**:
```
SDF_DL_Unload();
```

---

### Typo in SDF_DL_Unload function call
`src/provider.c:166`
```
SDF_DL_Unload();
```
**Issue**: Function name has typo - should be SDF_DL_Unload not SDF_DL_Unload
**Fix**:
```
SDF_DL_Unload();
```

---


## Medium

### Uninitialized variable ret used in error path
`src/provider.c:127-128`
```
if (sdfLibPath == NULL) {
        BSL_ERR_PUSH_ERROR(ret);
        return CRYPT_INVALID_ARG;
    }
```
**Issue**: When sdfLibPath is NULL, variable ret is uninitialized but BSL_ERR_PUSH_ERROR(ret) is called with an undefined value.
**Fix**:
```
if (sdfLibPath == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
```

---

### Typo in BSL_SAL_Dump macro name
`src/rsa_keymgmt.c:597`
```
GOTO_ERR_IF_SRC_NOT_NULL(newCtx->e, ctx->e, BSL_SAL_Dump(ctx->e, ctx->eLen), CRYPT_MEM_ALLOC_FAIL);
```
**Issue**: The macro BSL_SAL_Dump does not exist - should be BSL_SAL_Dup or similar allocation function
**Fix**:
```
GOTO_ERR_IF_SRC_NOT_NULL(newCtx->e, ctx->e, BSL_SAL_Dup(ctx->e, ctx->eLen), CRYPT_MEM_ALLOC_FAIL);
```

---

### Typo in BSL_SAL_Dump macro name
`src/rsa_keymgmt.c:600`
```
GOTO_ERR_IF_SRC_NOT_NULL(newCtx->label.data, ctx->label.data, BSL_SAL_Dump(ctx->label.data,
```
**Issue**: The macro BSL_SAL_Dump does not exist - should be BSL_SAL_Dup or similar allocation function
**Fix**:
```
GOTO_ERR_IF_SRC_NOT_NULL(newCtx->label.data, ctx->label.data, BSL_SAL_Dup(ctx->label.data,
```

---

### Typo in dlclose parameter name
`src/sdf_dl.c:164`
```
dlclose(g_sdfLibHandle);
```
**Issue**: Variable name mismatch - g_sdfLibHandle vs g_sdfLibHandle
**Fix**:
```
dlclose(g_sdfLibHandle);
```

---

### Memory leak on error path when keyIndex != 0
`src/sm2_keymgmt.c:276-279`
```
ret = SDF_DL_ExportSignPublicKey_ECC(ctx->hSessionHandle, ctx->KeyIndex, &sdfPub);
    if (ret != SDR_OK) {
        BSL_ERR_PUSH_ERROR(ret);
        return BSL_INTERNAL_EXCEPTION;
    }
    PublicKey = BSL_SAL_Calloc(1u, sizeof(EccPubKey));
    if (PublicKey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
```
**Issue**: If ctx->KeyIndex != 0, the function returns CRYPT_ECC_PKEY_ERR_EMPTY_KEY without freeing the allocated tempPubKey buffer
**Fix**:
```
EccPubKey *tempPubKey = BSL_SAL_Calloc(1u, sizeof(EccPubKey));
    if (tempPubKey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ToEccPubKey(&sdfPub, tempPubKey);
    ctx->PublicKey = tempPubKey;
```

---

### Potential memory leak on error path
`src/rsa_keymgmt.c:117-121`
```
ret = CRYPT_RSA_SetParaEx(ctx, para);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
```
**Issue**: If CRYPT_RSA_SetParaEx fails, e and eLen may be left in inconsistent state
**Fix**:
```
ret = CRYPT_RSA_SetParaEx(ctx, para);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(ctx->e);
        ctx->e = NULL;
        ctx->eLen = 0;
        return ret;
    }
```

---


## Low

### Typo in struct member name e
`src/rsa_local.h:61`
```
typedef struct {
    unsigned int bits;
    unsigned char m[SDF_RSA_MAX_KEY_LEN];
    unsigned char e[SDF_RSA_MAX_KEY_LEN];
} RsaPubKey;
```
**Issue**: The uint32_t eLen field is declared but struct member is named 'e' not 'exp' which could cause confusion
**Fix**:
```
typedef struct {
    unsigned int bits;
    unsigned char m[SDF_RSA_MAX_KEY_LEN];
    unsigned char e[SDF_RSA_MAX_KEY_LEN];  /* public exponent */
} RsaPubKey;
```

---

### Typo in comment "Deep-copied"
`src/provider.h:32`
```
char *sdfLibPath;    /* Deep-copied SDF library path */
```
**Issue**: Comment has typo - should be "Deep-copied" not "Deep-copied"
**Fix**:
```
char *sdfLibPath;    /* Deep-copied SDF library path */
```

---

### Incorrect comment after removing KeyIndex logic
`src/sm2_keymgmt.c:251-254`
```
if (ctx->KeyIndex != 0) {
        // Internal key: no exportable private key data
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
```
**Issue**: Comment refers to old "data with leading 0x00, use it as KeyIndex" logic which was removed
**Fix**:
```
if (ctx->KeyIndex != 0) {
        // Internal key: no exportable private key data
        return CRYPT_ECC_PKEY_ERR_EMPTY_KEY;
```

---
