# Code Review Consolidation Task

You are consolidating code review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #874
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/openhitls#874
**Reviewer**: CLAUDE


## High

### Missing NULL check for tradMethod->dupCtx result before use
`crypto/composite/src/composite.c:181-192`
```
if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
        newCtx->pqcCtx = ctx->pqcMethod->dupCtx(ctx->pqcCtx);
        newCtx->tradCtx = ctx->tradMethod->dupCtx(ctx->tradCtx);
        if (newCtx->pqcCtx == NULL || newCtx->tradCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto ERR;
        }
    }
```
**Issue**: In CRYPT_COMPOSITE_DupCtx, if pqcMethod->dupCtx succeeds but tradMethod->dupCtx fails, the code returns NULL without cleaning up the successfully allocated pqcCtx. More critically, it uses newCtx->pqcCtx which could be non-NULL to check if both succeeded, but if tradCtx allocation fails, pqcCtx is leaked.
**Fix**:
```
if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
        newCtx->pqcCtx = ctx->pqcMethod->dupCtx(ctx->pqcCtx);
        if (newCtx->pqcCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto ERR;
        }
        newCtx->tradCtx = ctx->tradMethod->dupCtx(ctx->tradCtx);
        if (newCtx->tradCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            goto ERR;
        }
    }
```

---

### Missing NULL check on method before dereferencing in sign/verify
`crypto/composite/src/composite.c:479`
```
GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    int32_t pqcRet = ctx->pqcMethod->sign(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, &pqcSigLen);
    int32_t tradRet = ctx->tradMethod->sign(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, sign + pqcSigLen,
                                           &tradSigLen);
```
**Issue**: In CRYPT_COMPOSITE_Sign, the code calls ctx->pqcMethod->sign and ctx->tradMethod->sign but doesn't verify that ctx->pqcMethod and ctx->tradMethod are non-NULL before use. If these are NULL, it will crash.
**Fix**:
```
RETURN_RET_IF(ctx->pqcMethod == NULL || ctx->tradMethod == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_SET_CTX_INFO, (void *)(uintptr_t)ctx->info->label,
        (uint32_t)strlen(ctx->info->label)), ret);
    int32_t pqcRet = ctx->pqcMethod->sign(ctx->pqcCtx, CRYPT_MD_MAX, msg.data, msg.len, sign, &pqcSigLen);
    int32_t tradRet = ctx->tradMethod->sign(ctx->tradCtx, ctx->info->tradHashId, msg.data, msg.len, sign + pqcSigLen,
                                           &tradSigLen);
```

---

### Invalid range check for composite key type
`crypto/codecskey/src/crypt_decoder_composite.c:30-33`
```
bool isCompositePubkey = (subPubkeyInfo.keyType >= BSL_CID_MLDSA44_RSA2048_PSS_SHA256 &&
                                   subPubkeyInfo.keyType <= BSL_CID_MLDSA87_ECDSA_P521_SHA512);
```
**Issue**: The range check uses hardcoded min/max values instead of constants. If new composite algorithms are added between these values but outside the expected range, they would be rejected. More critically, the check doesn't account for potential gaps in the enum values.
**Fix**:
```
bool isCompositePubkey = (subPubkeyInfo.keyType >= BSL_CID_MLDSA44_RSA2048_PSS_SHA256 &&
                                   subPubkeyInfo.keyType <= BSL_CID_MLDSA87_ECDSA_P521_SHA512) &&
                                  !((subPubkeyInfo.keyType > BSL_CID_MLDSA87_ECDSA_P521_SHA512 &&
                                     subPubkeyInfo.keyType < BSL_CID_MLDSA44_ED25519_SHA512));
```

---

### Return value ignored in CRYPT_CompositeGetEd25519PubKey
`crypto/composite/src/composite_encdec.c:254-260`
```
static int32_t CRYPT_CompositeGetEd25519PubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = 0;
    ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen));
    RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```
**Issue**: The return value from ctx->tradMethod->ctrl is ignored, but then pubLen is used. If the ctrl call fails, pubLen remains 0, causing BITS_TO_BYTES(0) = 0, leading to 0-size allocation.
**Fix**:
```
static int32_t CRYPT_CompositeGetEd25519PubKey(const CRYPT_CompositeCtx *ctx, BSL_Buffer *encode)
{
    int32_t ret;
    uint32_t pubLen = 0;
    RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
    RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```

---


## Medium

### Missing NULL check for ctx->info before dereferencing
`crypto/composite/src/composite.c:257-262`
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
        return CRYPT_COMPOSITE_KEYLEN_ERROR;
    }
```
**Issue**: CRYPT_CompositeSetctxInfo uses ctx->info without checking if it's NULL first. If ctx->info is NULL, ctx->prvLen and ctx->pubLen may not be initialized, potentially leading to issues.
**Fix**:
```
static int32_t CRYPT_CompositeSetctxInfo(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    if (len > COMPOSITE_MAX_CTX_BYTES) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
        return CRYPT_COMPOSITE_KEYLEN_ERROR;
    }
```

---

### Missing NULL check for ctx->info in CRYPT_CompositeGetParaId
`crypto/composite/src/composite.c:283-288`
```
static int32_t CRYPT_CompositeGetParaId(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    *(int32_t *)val = ctx->info->paramId;
    return CRYPT_SUCCESS;
}
```
**Issue**: The function returns CRYPT_COMPOSITE_KEYINFO_NOT_SET if ctx->info is NULL, but it doesn't check if ctx itself is NULL first.
**Fix**:
```
static int32_t CRYPT_CompositeGetParaId(CRYPT_CompositeCtx *ctx, void *val, uint32_t len)
{
    RETURN_RET_IF(ctx == NULL, CRYPT_NULL_INPUT);
    RETURN_RET_IF(val == NULL || len != sizeof(uint32_t), CRYPT_INVALID_ARG);
    RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    *(int32_t *)val = ctx->info->paramId;
    return CRYPT_SUCCESS;
}
```

---

### Potential integer overflow in length calculation
`crypto/composite/src/composite.c:364-367`
```
ctx->prvLen = pqcPrv.dataLen + tradPrv.dataLen;
    ctx->pubLen = pqcPub.dataLen + tradPub.dataLen;
    RETURN_RET_IF_ERR(CRYPT_CompositeCreateKeyBuf(ctx), ret);
```
**Issue**: The length calculation `pqcPrv.dataLen + tradPrv.dataLen` could overflow if both values are large. While unlikely with the current key sizes, defensive coding should prevent this.
**Fix**:
```
if (pqcPrv.dataLen > UINT32_MAX - tradPrv.dataLen || pqcPub.dataLen > UINT32_MAX - tradPub.dataLen) {
        ret = CRYPT_COMPOSITE_KEYLEN_ERROR;
        goto ERR;
    }
    ctx->prvLen = pqcPrv.dataLen + tradPrv.dataLen;
    ctx->pubLen = pqcPub.dataLen + tradPub.dataLen;
    RETURN_RET_IF_ERR(CRYPT_CompositeCreateKeyBuf(ctx), ret);
```

---

### Missing bounds check before memcpy_s
`crypto/composite/src/composite.c:409-414`
```
RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    ctx->prvKey = (uint8_t *)BSL_SAL_Malloc(prv->len);
```
**Issue**: CRYPT_COMPOSITE_SetPrvKey checks that prv->len > pqcPrvkeyLen but doesn't verify that prv->len <= expected total key length. Malformed input could pass this check.
**Fix**:
```
RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(prv->len > ctx->info->pqcPrvkeyLen + ctx->info->tradPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    ctx->prvKey = (uint8_t *)BSL_SAL_Malloc(prv->len);
```

---

### Missing bounds check in CRYPT_COMPOSITE_SetPubKey
`crypto/composite/src/composite.c:428-433`
```
RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    ctx->pubKey = (uint8_t *)BSL_SAL_Malloc(pub->len);
```
**Issue**: Similar to SetPrvKey, only checks lower bound but not upper bound for total expected key length.
**Fix**:
```
RETURN_RET_IF(ctx->info == NULL, CRYPT_COMPOSITE_KEYINFO_NOT_SET);
    RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    RETURN_RET_IF(pub->len > ctx->info->pqcPubkeyLen + ctx->info->tradPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
    ctx->pubKey = (uint8_t *)BSL_SAL_Malloc(pub->len);
```

---

### Unchecked return value from memcpy_s
`crypto/composite/src/composite.c:147`
```
(void)memcpy_s(ctx->prvKey, ctx->prvLen, pqcPrv.data, pqcPrv.dataLen);
    (void)memcpy_s(ctx->prvKey + pqcPrv.dataLen, ctx->prvLen - pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
    (void)memcpy_s(ctx->pubKey, ctx->pubLen, pqcPub.data, pqcPub.dataLen);
    (void)memcpy_s(ctx->pubKey + pqcPub.dataLen, ctx->pubLen - pqcPub.dataLen, tradPub.data, tradPub.dataLen);
```
**Issue**: The return values from memcpy_s calls are explicitly cast to void and ignored. If the memcpy fails, the function continues with potentially corrupted data.
**Fix**:
```
ret = memcpy_s(ctx->prvKey, ctx->prvLen, pqcPrv.data, pqcPrv.dataLen);
    if (ret != EOK) { ret = CRYPT_ERR; goto ERR; }
    ret = memcpy_s(ctx->prvKey + pqcPrv.dataLen, ctx->prvLen - pqcPrv.dataLen, tradPrv.data, tradPrv.dataLen);
    if (ret != EOK) { ret = CRYPT_ERR; goto ERR; }
    ret = memcpy_s(ctx->pubKey, ctx->pubLen, pqcPub.data, pqcPub.dataLen);
    if (ret != EOK) { ret = CRYPT_ERR; goto ERR; }
    ret = memcpy_s(ctx->pubKey + pqcPub.dataLen, ctx->pubLen - pqcPub.dataLen, tradPub.data, tradPub.dataLen);
    if (ret != EOK) { ret = CRYPT_ERR; goto ERR; }
```

---

### Missing error code push on failure
`crypto/codecskey/src/crypt_decoder_composite.c:69`
```
CRYPT_CompositeCtx *pctx = CRYPT_COMPOSITE_NewCtxEx(libCtx);
    if (pctx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
```
**Issue**: When CRYPT_COMPOSITE_NewCtxEx fails, the function returns CRYPT_MEM_ALLOC_FAIL without pushing the error code using BSL_ERR_PUSH_ERROR, unlike other error paths.
**Fix**:
```
CRYPT_CompositeCtx *pctx = CRYPT_COMPOSITE_NewCtxEx(libCtx);
    if (pctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
```

---


---

## GEMINI Review

# Code Review: openHiTLS/openhitls#874
**Reviewer**: GEMINI


## High

### Memory leak when setting algorithm parameters multiple times
`crypto/composite/src/composite.c:247-248`
```
ctx->pqcMethod = pqcMethod;
    ctx->tradMethod = tradMethod;
    ctx->pqcCtx = pqcMethod->newCtx();
    RETURN_RET_IF((ctx->pqcCtx == NULL), CRYPT_MEM_ALLOC_FAIL);
    ctx->tradCtx = tradMethod->newCtx();
```
**Issue**: The function `CRYPT_CompositeSetAlgInfo` allocates new `pqcCtx` and `tradCtx` without checking if they are already allocated. If `CRYPT_COMPOSITE_Ctrl` with `CRYPT_CTRL_SET_PARA_BY_ID` is called multiple times on the same context, the previously allocated contexts are leaked.
**Fix**:
```
ctx->pqcMethod = pqcMethod;
    ctx->tradMethod = tradMethod;
    if (ctx->pqcCtx != NULL) {
        ctx->pqcMethod->freeCtx(ctx->pqcCtx);
        ctx->pqcCtx = NULL;
    }
    ctx->pqcCtx = pqcMethod->newCtx();
    RETURN_RET_IF((ctx->pqcCtx == NULL), CRYPT_MEM_ALLOC_FAIL);
    if (ctx->tradCtx != NULL) {
        ctx->tradMethod->freeCtx(ctx->tradCtx);
        ctx->tradCtx = NULL;
    }
    ctx->tradCtx = tradMethod->newCtx();
```

---


## Medium

### Inconsistent state on memory allocation failure
`crypto/composite/src/composite.c:261`
```
if (ctx->tradCtx == NULL) {
        pqcMethod->freeCtx(ctx->pqcCtx);
        ctx->pqcCtx = NULL;
        return CRYPT_MEM_ALLOC_FAIL;
    }
```
**Issue**: In `CRYPT_CompositeSetAlgInfo`, if `tradMethod->newCtx()` fails, the function returns `CRYPT_MEM_ALLOC_FAIL` but leaves `ctx->info` set. This puts the context in a partially initialized state (info set, but contexts null), which might lead to confusing behavior or crashes if other functions assume `info != NULL` implies valid contexts. The `ERR` label handles this by setting `info = NULL`, but this return path does not jump to `ERR`.
**Fix**:
```
if (ctx->tradCtx == NULL) {
        pqcMethod->freeCtx(ctx->pqcCtx);
        ctx->pqcCtx = NULL;
        ctx->info = NULL;
        return CRYPT_MEM_ALLOC_FAIL;
    }
```

---

### Potential memory leak in ASN.1 decoding for RSA Private Key
`crypto/composite/src/composite_encdec.c:462-475`
```
RETURN_RET_IF_ERR(
        BSL_ASN1_DecodeTemplate(&templ, NULL, &encode->data, &encode->dataLen, asn1, CRYPT_RSA_PRV_OTHER_PRIME_IDX + 1),
        ret);
    // ... use asn1 ...
    RETURN_RET_IF_ERR(ctx->tradMethod->setPrv(ctx->tradCtx, &rsaParam), ret);
    RETURN_RET_IF_ERR(ctx->tradMethod->setPub(ctx->tradCtx, &rsaParam), ret);
    RETURN_RET_IF_ERR(CRYPT_CompositeSetRsaPadding(ctx), ret);
    return CRYPT_SUCCESS;
```
**Issue**: The function `CRYPT_CompositeSetRsaPrvKey` uses `BSL_ASN1_DecodeTemplate` to populate `asn1` buffers (specifically for INTEGER types like D, N, P, Q...). If `BSL_ASN1_DecodeTemplate` allocates memory for these fields (which is common for normalizing Integers in ASN.1 decoders), that memory is never freed. The `asn1` array is on the stack, but the `buff` pointers within it might point to allocated memory. This pattern is repeated in `CRYPT_CompositeSetRsaPubKey` and `CRYPT_CompositeSetEcdsaPrvKey`.
**Fix**:
```
// Verify BSL_ASN1_DecodeTemplate behavior. If it allocates, add cleanup:
    // After usage:
    for (int i = 0; i <= CRYPT_RSA_PRV_OTHER_PRIME_IDX; i++) {
        if (asn1[i].buff != NULL && asn1[i].buff < encode->data || asn1[i].buff >= encode->data + encode->dataLen) {
             // Logic assumes if not pointing into source, it was allocated. 
             // Ideally use a BSL_ASN1_FreeTemplate or similar if available, or BSL_SAL_Free.
             BSL_SAL_Free(asn1[i].buff);
        }
    }
```

---


## Low

### Hardcoded salt length logic in RSA PSS padding
`crypto/composite/src/composite_encdec.c:153-157`
```
int32_t mdId = ctx->info->tradHashId;
        int32_t mgfId = ctx->info->tradHashId;
        int32_t saltLen = ctx->info->bits == 4096 ? 48 : 32;
```
**Issue**: The salt length selection logic is hardcoded based on the bit length of the RSA key (`bits == 4096 ? 48 : 32`). This implicitly assumes that 4096-bit keys always use SHA-384 (48 bytes) and other keys use SHA-256 (32 bytes). While this matches the current `g_composite_info` table, it is brittle and may break if new RSA-PSS combinations are added (e.g., RSA-3072 with SHA-384).
**Fix**:
```
int32_t mdId = ctx->info->tradHashId;
        int32_t mgfId = ctx->info->tradHashId;
        // Derive salt length from the digest size of tradHashId instead of bit length
        int32_t saltLen = 32; // Default to SHA256 size
        if (mdId == CRYPT_MD_SHA384) {
            saltLen = 48;
        } else if (mdId == CRYPT_MD_SHA512) {
             saltLen = 64;
        }
```

---

### Passing pointer to array instead of pointer to element
`crypto/composite/src/composite_encdec.c:474`
```
RETURN_RET_IF_ERR(ctx->tradMethod->setPrv(ctx->tradCtx, &rsaParam), ret);
```
**Issue**: `rsaParam` is declared as an array `BSL_Param rsaParam[]`. The function call `ctx->tradMethod->setPrv(ctx->tradCtx, &rsaParam)` passes the address of the array (`BSL_Param (*)[N]`), whereas the function likely expects a pointer to the first element (`BSL_Param *`). While they represent the same address, it is a type mismatch.
**Fix**:
```
RETURN_RET_IF_ERR(ctx->tradMethod->setPrv(ctx->tradCtx, rsaParam), ret);
```

---


---

## CODEX Review

# Code Review: openHiTLS/openhitls#874
**Reviewer**: CODEX


## Medium

### ECDSA public key length derived from bits causes under-allocation
`crypto/composite/src/composite_encdec.c:292-299`
```
uint32_t pubLen = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
pubLen = BITS_TO_BYTES(pubLen);
uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
...
BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
```
**Issue**: `CRYPT_CTRL_GET_BITS` returns curve size (e.g., 256/384), not the encoded public key size (e.g., 65/97 bytes for uncompressed). Converting bits to bytes under-allocates the buffer and makes `getPub` fail or truncate, breaking composite public key encoding.
**Fix**:
```
uint32_t pubLen = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_PUBKEY_LEN, &pubLen, sizeof(pubLen)), ret);
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
uint8_t *pub = (uint8_t *)BSL_SAL_Malloc(pubLen);
RETURN_RET_IF(pub == NULL, CRYPT_MEM_ALLOC_FAIL);
BSL_Param param[2] = {{CRYPT_PARAM_EC_PUBKEY, BSL_PARAM_TYPE_OCTETS, pub, pubLen, 0}, BSL_PARAM_END};
ret = ctx->tradMethod->getPub(ctx->tradCtx, &param);
if (ret != CRYPT_SUCCESS) {
    BSL_SAL_FREE(pub);
    return ret;
}
encode->data = pub;
encode->dataLen = param[0].useLen;
```

---


## Low

### Ed25519 public key length lookup ignores error return
`crypto/composite/src/composite_encdec.c:330-335`
```
uint32_t pubLen = 0;
ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen));
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```
**Issue**: The return value of `ctrl` is ignored. If the control call fails, the function returns `CRYPT_EAL_ALG_NOT_SUPPORT`, masking real errors and making debugging and error handling incorrect.
**Fix**:
```
uint32_t pubLen = 0;
RETURN_RET_IF_ERR(ctx->tradMethod->ctrl(ctx->tradCtx, CRYPT_CTRL_GET_BITS, &pubLen, sizeof(pubLen)), ret);
RETURN_RET_IF(pubLen == 0, CRYPT_EAL_ALG_NOT_SUPPORT);
```

---

### Preprocessor condition loses HITLS_CRYPTO_PROVIDER gating
`crypto/provider/src/default/crypt_default_keymgmt.c:16-22`
```
#if (defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_X25519) || \
    defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_DH) || defined(HITLS_CRYPTO_ECDSA) || \
    defined(HITLS_CRYPTO_ECDH) || defined(HITLS_CRYPTO_SM2) || defined(HITLS_CRYPTO_PAILLIER) || \
    defined(HITLS_CRYPTO_ELGAMAL) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLKEM) || \
    defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_COMPOSITE) || defined(HITLS_CRYPTO_HYBRIDKEM)) && \
    defined(HITLS_CRYPTO_PROVIDER) || defined(HITLS_CRYPTO_CLASSIC_MCELIECE) || defined(HITLS_CRYPTO_FRODOKEM)
```
**Issue**: Missing parentheses change precedence so the file is compiled when `HITLS_CRYPTO_CLASSIC_MCELIECE` or `HITLS_CRYPTO_FRODOKEM` are set even if `HITLS_CRYPTO_PROVIDER` is not defined, causing unintended compilation and potential build failures.
**Fix**:
```
#if (defined(HITLS_CRYPTO_DSA) || defined(HITLS_CRYPTO_ED25519) || defined(HITLS_CRYPTO_X25519) || \
    defined(HITLS_CRYPTO_RSA) || defined(HITLS_CRYPTO_DH) || defined(HITLS_CRYPTO_ECDSA) || \
    defined(HITLS_CRYPTO_ECDH) || defined(HITLS_CRYPTO_SM2) || defined(HITLS_CRYPTO_PAILLIER) || \
    defined(HITLS_CRYPTO_ELGAMAL) || defined(HITLS_CRYPTO_SLH_DSA) || defined(HITLS_CRYPTO_MLKEM) || \
    defined(HITLS_CRYPTO_MLDSA) || defined(HITLS_CRYPTO_COMPOSITE) || defined(HITLS_CRYPTO_HYBRIDKEM) || \
    defined(HITLS_CRYPTO_CLASSIC_MCELIECE) || defined(HITLS_CRYPTO_FRODOKEM)) && \
    defined(HITLS_CRYPTO_PROVIDER)
```

---


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the code
   - Use `git diff` and file reads to confirm
   - Remove false positives
   - Adjust severity if needed

3. **Consolidate Findings**
   - Merge duplicate issues (note which reviewers found it)
   - Keep unique valid issues
   - Prioritize by actual impact

4. **Output Format**

For each validated issue, output:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
REVIEWERS: <comma-separated list of reviewers who found this>
CONFIDENCE: trusted|likely|evaluate
PROBLEM: <consolidated description>
CODE:
```
<problematic code>
```
FIX:
```
<best suggested fix>
```
===END===

## Confidence Levels

- **trusted** (可信): Multiple reviewers found this issue AND you verified it in the code
- **likely** (较可信): Found by one reviewer AND you verified it exists in the code
- **evaluate** (需评估): Found by reviewer(s) but needs human review to confirm impact/fix

## Important

- SEVERITY indicates impact level (critical/high/medium/low)
- CONFIDENCE indicates how certain we are about this issue
- Only include issues you've verified in the code
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
