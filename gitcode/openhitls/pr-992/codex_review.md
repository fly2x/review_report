# Code Review: openHiTLS/openhitls#992
**Reviewer**: CODEX


## High

### HSS param compression allows unsupported levels leading to OOB read on decompress
`crypto/lms/src/hss_utils.c:117-224`
```
if (para->levels < HSS_MIN_LEVELS || para->levels > HSS_MAX_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}

memset(compressed, 0, HSS_COMPRESSED_PARAMS_LEN);
compressed[0] = (uint8_t)para->levels;

for (uint32_t i = 0; i < para->levels && i < HSS_MAX_COMPRESSED_LEVELS; i++) {
    ...
}

uint32_t levels = compressed[0];
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}

for (uint32_t i = 0; i < levels; i++) {
    uint8_t lmsComp = compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE];
    uint8_t otsComp = compressed[HSS_COMPRESSED_LEVEL_FIELD_SIZE + i * HSS_COMPRESSED_PARAM_PAIR_SIZE + 1];
    ...
}
```
**Issue**: The compressed parameter format only has 8 bytes (max 3 levels), but HssCompressParamSet accepts levels up to 8 and silently truncates. HssDecompressParamSet then trusts `levels` and reads `compressed[...+1]`, which goes out of bounds when levels ≥ 4 (index 8). This is an out-of-bounds read and also produces keys that can’t be safely reloaded.
**Fix**:
```
if (para->levels < HSS_MIN_LEVELS || para->levels > HSS_MAX_LEVELS ||
    para->levels > HSS_MAX_COMPRESSED_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}

memset(compressed, 0, HSS_COMPRESSED_PARAMS_LEN);
compressed[0] = (uint8_t)para->levels;

for (uint32_t i = 0; i < para->levels; i++) {
    ...
}

uint32_t levels = compressed[0];
if (levels < HSS_MIN_LEVELS || levels > HSS_MAX_LEVELS ||
    levels > HSS_MAX_COMPRESSED_LEVELS) {
    return CRYPT_HSS_INVALID_LEVEL;
}

for (uint32_t i = 0; i < levels; i++) {
    ...
}
```

---


## Medium

### HSS public key load never initializes derived parameters
`crypto/lms/src/hss_api.c:362-395`
```
ctx->para->levels = levels;
ctx->para->lmsType[0] = lmsType;
ctx->para->otsType[0] = otsType;

return CRYPT_SUCCESS;
```
**Issue**: CRYPT_HSS_SetPubKey only stores `levels`, `lmsType[0]`, and `otsType[0]` but never calls HssParaInit. As a result `levelPara[*].sigLen` stays zero and HssParseSignature/Verify parse signatures incorrectly (verification always fails for a freshly loaded public key).
**Fix**:
```
ctx->para->levels = levels;
ctx->para->lmsType[0] = lmsType;
ctx->para->otsType[0] = otsType;

for (uint32_t i = 0; i < levels; i++) {
    if (ctx->para->lmsType[i] == 0 || ctx->para->otsType[i] == 0) {
        return CRYPT_HSS_INVALID_PARAM;
    }
}

int32_t ret = HssParaInit(ctx->para, levels, ctx->para->lmsType, ctx->para->otsType);
if (ret != CRYPT_SUCCESS) {
    return ret;
}
```

---


## Low

### HSS signature parsing ignores trailing bytes
`crypto/lms/src/hss_core.c:361-395`
```
parsed->bottomSigLen = para->levelPara[bottomLevel].sigLen;

if (parsed->bottomSigLen > remaining) {
    return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
}

parsed->bottomSig = sigPtr;
return CRYPT_SUCCESS;
```
**Issue**: HssParseSignature only checks `bottomSigLen > remaining` and then sets `bottomSig`, which means extra trailing bytes are silently ignored. This makes signature parsing non-strict and allows malleable signatures with junk suffixes to pass structure validation.
**Fix**:
```
parsed->bottomSigLen = para->levelPara[bottomLevel].sigLen;

if (parsed->bottomSigLen != remaining) {
    return CRYPT_HSS_SIGNATURE_PARSE_FAIL;
}

parsed->bottomSig = sigPtr;
return CRYPT_SUCCESS;
```

---

### LMS context comparison treats missing keys as equal
`crypto/lms/src/lms_api.c:124-152`
```
/* Compare public keys */
if (ctx1->publicKey != NULL && ctx2->publicKey != NULL) {
    if (memcmp(ctx1->publicKey, ctx2->publicKey, ctx1->para->pubKeyLen) != 0) {
        return CRYPT_LMS_CMP_FALSE;
    }
}

/* Compare private keys */
if (ctx1->privateKey != NULL && ctx2->privateKey != NULL) {
    if (memcmp(ctx1->privateKey, ctx2->privateKey, ctx1->para->prvKeyLen) != 0) {
        return CRYPT_LMS_CMP_FALSE;
    }
}
```
**Issue**: CRYPT_LMS_Cmp compares keys only when both sides are non-NULL. If one context has a public/private key and the other doesn’t, it returns success, incorrectly reporting equality.
**Fix**:
```
if ((ctx1->publicKey == NULL) != (ctx2->publicKey == NULL)) {
    return CRYPT_LMS_CMP_FALSE;
}
if (ctx1->publicKey != NULL &&
    memcmp(ctx1->publicKey, ctx2->publicKey, ctx1->para->pubKeyLen) != 0) {
    return CRYPT_LMS_CMP_FALSE;
}

if ((ctx1->privateKey == NULL) != (ctx2->privateKey == NULL)) {
    return CRYPT_LMS_CMP_FALSE;
}
if (ctx1->privateKey != NULL &&
    memcmp(ctx1->privateKey, ctx2->privateKey, ctx1->para->prvKeyLen) != 0) {
    return CRYPT_LMS_CMP_FALSE;
}
```

---
