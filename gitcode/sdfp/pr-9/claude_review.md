# Code Review: openHiTLS/sdfp#9
**Reviewer**: CLAUDE


## High

### RSA PKCS#1 v1.5 padding removal is not constant-time
`src/rsa/rsa_sign.c:305-340`
```
uint32_t padNum = 0;
while (*index == 0xff) {
    index++;
    tmpLen--;
    padNum++;
}
if (padNum < 8) { // The PS padding is at least 8.
    return CRYPT_RSA_ERR_PAD_NUM;
}
if (tmpLen == 0 || *index != 0x0) {
    return CRYPT_RSA_ERR_INPUT_VALUE;
}
```
**Issue**: The CRYPT_RSA_UnPackPkcsV15Type1_ex function validates padding using non-constant-time operations (while loop, memcmp-like checks). This creates a timing side-channel that could be exploited in Bleichenbacher-style attacks. The function is used in CRYPT_RSA_Recover for signature verification.
**Fix**:
```
/* Use constant-time padding validation similar to CRYPT_RSA_VerifyPkcsV15Type2_ex */
uint32_t padNum = 0;
uint32_t index = ~(0);
uint32_t firstByte = Uint32ConstTimeEqual(data[0], 0x00);
uint32_t secondByte = Uint32ConstTimeEqual(data[1], 0x01);

for (uint32_t i = 2; i < dataLen; i++) {
    uint32_t isFF = Uint32ConstTimeEqual(data[i], 0xff);
    padNum = Uint32ConstTimeSelect(isFF & ~index, padNum + 1, padNum);
    index = Uint32ConstTimeSelect(isFF, index, i);
}

uint32_t valid = firstByte & secondByte & (~index);
valid &= Uint32ConstTimeGe(padNum, 8);

/* Find zero separator and validate in constant-time */
uint32_t zeroPos = ~(0);
for (uint32_t i = 2 + padNum; i < dataLen; i++) {
    uint32_t isZero = Uint32ConstTimeIsZero(data[i]);
    zeroPos = Uint32ConstTimeSelect(isZero & ~zeroPos, i, zeroPos);
}

valid &= ~Uint32ConstTimeEqual(zeroPos, ~(0));
if (valid == 0) {
    return CRYPT_RSA_ERR_PAD_NUM;
}

/* Copy result in constant-time */
zeroPos++;
if (dataLen - zeroPos > *outLen) {
    return CRYPT_RSA_BUFF_LEN_NOT_ENOUGH;
}
for (uint32_t i = 0; i < dataLen - zeroPos; i++) {
    out[i] = Uint8ConstTimeSelect(valid, data[zeroPos + i], 0);
}
*outLen = dataLen - zeroPos;
return CRYPT_SUCCESS;
```

---


## Medium

### Race condition in SDF library loading
`src/common/sdf_dl.c:70-71`
```
if (g_sdfLibHandle != NULL) {
    return SDFP_SUCCESS;
}

g_sdfLibHandle = dlopen(libPath, RTLD_NOW | RTLD_GLOBAL);
```
**Issue**: The check for g_sdfLibHandle != NULL and the subsequent dlopen call are not atomic. If two threads call SDF_DL_Load simultaneously, both may see NULL and proceed to load the library, causing a resource leak or undefined behavior.
**Fix**:
```
/* Use pthread_once or a similar mechanism for thread-safe initialization */
static pthread_once_t g_loadOnce = PTHREAD_ONCE_INIT;
static int g_loadResult = SDFP_SUCCESS;

static void LoadSdfLib(void) {
    g_loadResult = SDFP_ERR_LOAD_FAILED;
    g_sdfLibHandle = dlopen(libPath, RTLD_NOW | RTLD_GLOBAL);
    if (g_sdfLibHandle == NULL) {
        SDFP_LOG(SDFP_ERR_LOAD_FAILED);
        return;
    }
    /* Load symbols here... */
    g_loadResult = SDFP_SUCCESS;
}

int32_t SDF_DL_Load(const char *libPath) {
    if (libPath == NULL) {
        SDFP_LOG(SDFP_ERR_NULL_INPUT);
        return SDFP_ERR_NULL_INPUT;
    }
    int ret = pthread_once(&g_loadOnce, LoadSdfLib);
    if (ret != 0) {
        return SDFP_ERR_LOAD_FAILED;
    }
    return g_loadResult;
}
```

---

### Stack-allocated hash buffer not zeroized after signing
`src/rsa/rsa_sign.c:57-71`
```
static int32_t CRYPT_RSA_Sign(SDFP_RSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    uint8_t hash[64]; // 64 is max hash len
    uint32_t hashLen = sizeof(hash) / sizeof(hash[0]);
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = EAL_Md(algId, data, dataLen, hash, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    return CRYPT_RSA_SignData(ctx, hash, hashLen, sign, signLen);
}
```
**Issue**: The hash buffer in CRYPT_RSA_Sign contains the message digest which could be sensitive. While it's on the stack and has limited lifetime, explicit zeroization would be more secure for a cryptographic library handling sensitive operations.
**Fix**:
```
static int32_t CRYPT_RSA_Sign(SDFP_RSA_Ctx *ctx, int32_t algId, const uint8_t *data, uint32_t dataLen,
    uint8_t *sign, uint32_t *signLen)
{
    uint8_t hash[64]; // 64 is max hash len
    uint32_t hashLen = sizeof(hash) / sizeof(hash[0]);
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }
    int32_t ret = EAL_Md(algId, data, dataLen, hash, &hashLen);
    if (ret != CRYPT_SUCCESS) {
        (void)memset(hash, 0, sizeof(hash));
        return ret;
    }
    ret = CRYPT_RSA_SignData(ctx, hash, hashLen, sign, signLen);
    (void)memset(hash, 0, sizeof(hash));
    return ret;
}
```

---

### memset may be optimized out by compiler
`src/rsa/rsa_sign.c:122-128`
```
EXIT:
    (void)memset(pad, 0, padLen);
    BSL_SAL_FREE(pad);
    return ret;
```
**Issue**: The (void)memset pattern used to zeroize sensitive data may be optimized out by the compiler. The cast to void does not prevent dead store elimination in modern compilers with optimization enabled.
**Fix**:
```
EXIT:
    /* Use compiler-resistant zeroization */
    BSL_SAL_CleanseData(pad, padLen);
    BSL_SAL_FREE(pad);
    return ret;
```

---


## Low

### Hardcoded default password "12345678" is weak
`src/common/provider.c:23-24`
```
static const char   g_defaultPass[]  = "12345678";
static const uint32_t g_defaultPassLen = 8;
```
**Issue**: The default SDF device password "12345678" is a weak, predictable value. While it's documented and can be overridden, using such a weak default could lead to security issues if users don't change it.
**Fix**:
```
/* Do NOT use a hardcoded default password. Require explicit password configuration. */
static const char   g_defaultPass[]  = "";
static const uint32_t g_defaultPassLen = 0;

/* In CRYPT_EAL_ProviderInit, return error if password not provided: */
if (provCtx->pass == NULL || provCtx->passLen == 0) {
    SDFP_LOG(SDFP_ERR_NULL_INPUT);
    BSL_SAL_Free(sdfLibPath);
    return SDFP_ERR_NULL_INPUT;
}
```

---

### Key handle directly exposed through output parameter
`src/sm2/sm2_keyexch.c:35-36`
```
memcpy(out, &hKeyHandle, sizeof(void *));
*outlen = sizeof(void *);
```
**Issue**: The CRYPT_SM2_KapComputeKey function directly copies the key handle pointer to the output buffer. This breaks encapsulation and could lead to use-after-free bugs if the session is closed.
**Fix**:
```
/* Store the key handle in the context instead of returning it directly */
selfCtx->hKeyHandle = hKeyHandle;
/* Return an opaque identifier or handle reference */
*(uint32_t*)out = 1; /* Return success indicator, caller uses ctx->hKeyHandle */
*outlen = sizeof(uint32_t);
```

---

### Derived public key not validated to be on curve
`src/sm2/sm2_sign.c:243-252`
```
/* Generate the public key using CRYPT_CTRL_GEN_ECC_PUBLICKEY */
ret = CRYPT_EAL_PkeyCtrl(sm2Ctx, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0);
if (ret != CRYPT_SUCCESS) {
    SDFP_LOG(ret);
    CRYPT_EAL_PkeyFreeCtx(sm2Ctx);
    return ret;
}
```
**Issue**: The DeriveSm2PublicKey function computes a public key from a private key but doesn't validate that the resulting point is actually on the SM2 curve. While the built-in SM2 implementation should be correct, explicit validation would be defense-in-depth.
**Fix**:
```
/* Generate the public key using CRYPT_CTRL_GEN_ECC_PUBLICKEY */
ret = CRYPT_EAL_PkeyCtrl(sm2Ctx, CRYPT_CTRL_GEN_ECC_PUBLICKEY, NULL, 0);
if (ret != CRYPT_SUCCESS) {
    SDFP_LOG(ret);
    CRYPT_EAL_PkeyFreeCtx(sm2Ctx);
    return ret;
}

/* Validate the generated public key is on the curve */
ret = CRYPT_EAL_PkeyCtrl(sm2Ctx, CRYPT_EAL_PKEY_CHECK, NULL, 0);
if (ret != CRYPT_SUCCESS) {
    SDFP_LOG(ret);
    CRYPT_EAL_PkeyFreeCtx(sm2Ctx);
    return CRYPT_ECC_PKEY_ERR_NOT_VALID_KEY;
}
```

---

### Tag buffer not explicitly zeroized in SDFP_SM4_GCM_CleanCtx
`src/sm4/sm4_gcm.c:39-51`
```
static void SDFP_SM4_GCM_CleanCtx(SDFP_SM4_GCM_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    SDFP_SM4_GCM_CleanKey(ctx);
    if (ctx->hSessionHandle != NULL) {
        (void)SDF_DL_CloseSession(ctx->hSessionHandle);
        ctx->hSessionHandle = NULL;
    }
    BSL_SAL_CleanseData(ctx->iv, sizeof(ctx->iv));
    BSL_SAL_CleanseData(ctx->aad, sizeof(ctx->aad));
    BSL_SAL_CleanseData(ctx->tag, sizeof(ctx->tag));
```
**Issue**: The SDFP_SM4_GCM_CleanCtx function calls BSL_SAL_CleanseData on iv, aad, and tag buffers, but the tag buffer contains sensitive authentication data that should be explicitly zeroized. While BSL_SAL_CleanseData should handle this, the implementation should be verified.
**Fix**:
```
/* Verify BSL_SAL_CleanseData implementation uses memset_s or equivalent */
/* If BSL_SAL_CleanseData is not guaranteed to be compiler-resistant: */
static void SDFP_SM4_GCM_CleanCtx(SDFP_SM4_GCM_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    SDFP_SM4_GCM_CleanKey(ctx);
    if (ctx->hSessionHandle != NULL) {
        (void)SDF_DL_CloseSession(ctx->hSessionHandle);
        ctx->hSessionHandle = NULL;
    }
    /* Explicitly zeroize sensitive data using compiler-resistant method */
    (void)explicit_bzero(ctx->iv, sizeof(ctx->iv));
    (void)explicit_bzero(ctx->aad, sizeof(ctx->aad));
    (void)explicit_bzero(ctx->tag, sizeof(ctx->tag));
```

---

### No validation that RSA public exponent e is odd or within safe range
`src/rsa/rsa_keymgmt.c:59-61`
```
static int32_t ValidateRsaParams(uint32_t eLen, uint32_t bits)
{
    /* the length of e cannot be greater than bits */
    if (eLen > BN_BITS_TO_BYTES(bits)) {
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}
```
**Issue**: The ValidateRsaParams function only checks that eLen <= bits, but doesn't validate that the public exponent e is odd (required for RSA) or within commonly accepted secure ranges (e.g., 65537 or 3).
**Fix**:
```
static int32_t ValidateRsaParams(const uint8_t *e, uint32_t eLen, uint32_t bits)
{
    /* the length of e cannot be greater than bits */
    if (eLen > BN_BITS_TO_BYTES(bits) || eLen == 0) {
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    /* Public exponent must be odd (least significant bit = 1) */
    if ((e[eLen - 1] & 0x01) == 0) {
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    /* Recommend minimum exponent value (avoid e=1 which is insecure) */
    if (eLen == 1 && e[0] < 3) {
        return CRYPT_RSA_ERR_KEY_BITS;
    }
    return CRYPT_SUCCESS;
}
```

---

### Dead code - unreachable condition in CRYPT_SM2_Sign
`src/sm2/sm2_sign.c:280-284`
```
/* Compute the message hash */
EccPubKey *pubKeyForHash = ctx->publicKey;
EccPubKey derivedPubKey = {0};

if (ctx->publicKey != NULL) {
    /* Use existing public key for Z computation */
} else {
    /* Derive public key from private key for proper Z computation */
    ret = DeriveSm2PublicKey(ctx, &derivedPubKey);
```
**Issue**: The code checks `if (ctx->publicKey != NULL)` and has an `else` block, but the condition before it only checks `if (ctx->publicKey == NULL)` and calls `DeriveSm2PublicKey` in that case. This creates confusion about control flow.
**Fix**:
```
/* Compute the message hash */
EccPubKey *pubKeyForHash = NULL;
EccPubKey derivedPubKey = {0};
bool needFree = false;

if (ctx->publicKey != NULL) {
    /* Use existing public key for Z computation */
    pubKeyForHash = ctx->publicKey;
} else {
    /* Derive public key from private key for proper Z computation */
    ret = DeriveSm2PublicKey(ctx, &derivedPubKey);
    if (ret != CRYPT_SUCCESS) {
        SDFP_LOG(ret);
        return ret;
    }
    pubKeyForHash = &derivedPubKey;
    needFree = true;
}

ret = Sm2ComputeMsgHash(ctx, pubKeyForHash, data, dataLen, tbs, &tbsLen);
if (needFree) {
    (void)memset(&derivedPubKey, 0, sizeof(derivedPubKey));
}
```

---
