# Code Review Consolidation Task

You are consolidating code review findings from multiple AI reviewers.

## Context
- Repository: openhitls/pqcp
- PR: #33
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openhitls/pqcp#33
**Reviewer**: CLAUDE


## High

### Missing break statement in switch case leads to fallthrough
`src/provider/pqcp_pkey.c:44-46`
```
case CRYPT_PKEY_COMPOSITE_SIGN:
            pkeyCtx = CRYPT_COMPOSITE_NewCtx();
        default:
            break;
```
**Issue**: In CRYPT_PQCP_PkeyMgmtNewCtx(), the case for CRYPT_PKEY_COMPOSITE_SIGN is missing a break statement. This causes a fallthrough to the default case, which doesn't set pkeyCtx, leaving it as NULL for the COMPOSITE_SIGN algorithm.
**Fix**:
```
case CRYPT_PKEY_COMPOSITE_SIGN:
            pkeyCtx = CRYPT_COMPOSITE_NewCtx();
            break;
        default:
            break;
```

---

### CRYPT_COMPOSITE_DupCtx does not check if ctx->info is NULL before dereferencing
`src/composite_sign/src/crypt_composite_sign.c:116-143`
```
CRYPT_CompositeCtx *CRYPT_COMPOSITE_DupCtx(CRYPT_CompositeCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    CRYPT_CompositeCtx *newCtx = CRYPT_COMPOSITE_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    newCtx->info = ctx->info;  // No NULL check on ctx->info
    if (ctx->pqcMethod != NULL && ctx->tradMethod != NULL) {
```
**Issue**: The function assigns ctx->info to newCtx->info without checking if ctx->info is NULL. If a context is duplicated before setting algorithm info, the duplicated context will have NULL info, leading to potential crashes when used.
**Fix**:
```
CRYPT_CompositeCtx *CRYPT_COMPOSITE_DupCtx(CRYPT_CompositeCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    if (ctx->info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
        return NULL;
    }
    CRYPT_CompositeCtx *newCtx = CRYPT_COMPOSITE_NewCtx();
    if (newCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    newCtx->info = ctx->info;
```

---

### Wrong memcpy size parameter in CompositeMsgEncode
`src/composite_sign/src/crypt_composite_sign.c:506`
```
(void)memcpy_s(ptr, digestLen, digest, digestLen);
```
**Issue**: The last memcpy_s call uses digestLen as the size parameter instead of the actual destination buffer size. This is incorrect because memcpy_s expects the destination buffer size, not the source length.
**Fix**:
```
(void)memcpy_s(ptr, msg->len - (prefixLen + labelLen + 1 + ctx->ctxLen), digest, digestLen);
```

---


## Medium

### Duplicate algorithm labels in g_composite_info array
`src/composite_sign/src/crypt_composite_sign.c:50-59`
```
static const COMPOSITE_ALG_INFO g_composite_info[] = {
    {CRYPT_COMPOSITE_MLDSA44_SM2, "COMPSIG-MLDSA44-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_44,
        CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 1377, 64, 1312, 32, 2420,
    },
    {CRYPT_COMPOSITE_MLDSA65_SM2, "COMPSIG-MLDSA44-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65,
        CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 2017, 64, 1952, 32, 3309,
    },
    {CRYPT_COMPOSITE_MLDSA87_SM2, "COMPSIG-MLDSA44-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87,
        CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 2657, 64, 2592, 32, 4627,
    }
};
```
**Issue**: All three entries in g_composite_info have the same label "COMPSIG-MLDSA44-SM2". The labels should be unique and match their algorithm IDs (MLDSA65, MLDSA87).
**Fix**:
```
static const COMPOSITE_ALG_INFO g_composite_info[] = {
    {CRYPT_COMPOSITE_MLDSA44_SM2, "COMPSIG-MLDSA44-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_44,
        CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 1377, 64, 1312, 32, 2420,
    },
    {CRYPT_COMPOSITE_MLDSA65_SM2, "COMPSIG-MLDSA65-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65,
        CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 2017, 64, 1952, 32, 3309,
    },
    {CRYPT_COMPOSITE_MLDSA87_SM2, "COMPSIG-MLDSA87-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87,
        CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 2657, 64, 2592, 32, 4627,
    }
};
```

---

### GetConstParamValue return value ignored in CRYPT_COMPOSITE_SetPrvKeyEx
`src/composite_sign/src/crypt_composite_sign.c:446`
```
CRYPT_CompositePrv prv = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len);
    return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
```
**Issue**: The return value of GetConstParamValue is cast to void and ignored. If the parameter is not found, prv.data and prv.len remain uninitialized (zero), which will cause CRYPT_COMPOSITE_SetPrvKey to fail with a misleading error.
**Fix**:
```
CRYPT_CompositePrv prv = {0};
    if (GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &prv.len) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_COMPOSITE_SetPrvKey(ctx, &prv);
```

---

### GetConstParamValue return value ignored in CRYPT_COMPOSITE_SetPubKeyEx
`src/composite_sign/src/crypt_composite_sign.c:457`
```
CRYPT_CompositePub pub = {0};
    (void)GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len);
    return CRYPT_COMPOSITE_SetPubKey(ctx, &pub);
```
**Issue**: Same issue as SetPrvKeyEx - the return value is ignored, leading to potential uninitialized data being passed to SetPubKey.
**Fix**:
```
CRYPT_CompositePub pub = {0};
    if (GetConstParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &pub.len) == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    return CRYPT_COMPOSITE_SetPubKey(ctx, &pub);
```

---

### GetParamValue return value not checked in Ex functions
`src/composite_sign/src/crypt_composite_sign.c:414`
```
BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
```
**Issue**: In GetPrvKeyEx and GetPubKeyEx, the return value of GetParamValue is not checked. If the parameter is not found, the behavior is undefined.
**Fix**:
```
BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    if (paramPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
```

---

### Duplicate const qualifier is non-standard
`src/provider/pqcp_pkey.c:145`
```
const const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```
**Issue**: The declaration uses "const const" which is not valid C. The extra const qualifier should be removed.
**Fix**:
```
const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```

---


## Low

### Missing null check after malloc before use
`src/composite_sign/src/crypt_composite_sign_encdec.c:44-47`
```
uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(prv == NULL, CRYPT_MEM_ALLOC_FAIL);
    GOTO_ERR_IF(ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_MLDSA_SEED, prv, prvLen), ret);
    encode->data = prv;
    encode->dataLen = prvLen;
```
**Issue**: In CRYPT_CompositeGetMldsaPrvKey, the return value of the ctrl call is not checked before using the result in encode->dataLen. If the ctrl call fails, the allocated memory leaks.
**Fix**:
```
uint8_t *prv = (uint8_t *)BSL_SAL_Malloc(prvLen);
    RETURN_RET_IF(prv == NULL, CRYPT_MEM_ALLOC_FAIL);
    ret = ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_MLDSA_SEED, prv, prvLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(prv);
        return ret;
    }
    encode->data = prv;
    encode->dataLen = prvLen;
```

---

### CRYPT_COMPOSITE_GetPrvKeyEx does not validate ctx or ctx->info
`src/composite_sign/src/crypt_composite_sign.c:407-421`
```
int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
```
**Issue**: The function only checks if para is NULL but doesn't validate ctx or ctx->info before calling CRYPT_COMPOSITE_GetPrvKey. This means error messages may be misleading.
**Fix**:
```
int32_t CRYPT_COMPOSITE_GetPrvKeyEx(const CRYPT_CompositeCtx *ctx, BSL_Param *para)
{
    if (para == NULL || ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_CompositePrv prv = {0};
    BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
    int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
```

---

### Missing NULL checks for pqcMethod and tradMethod before calling ctrl
`src/composite_sign/src/crypt_composite_sign.c:278-279`
```
case CRYPT_CTRL_HYBRID_GET_PQC_PUBKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, len);
            return ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_PUBKEY_LEN, val, len);
```
**Issue**: In CRYPT_COMPOSITE_Ctrl, the cases for CRYPT_CTRL_HYBRID_GET_* call ctrl on pqcMethod/tradMethod without checking if the method pointers are NULL first.
**Fix**:
```
case CRYPT_CTRL_HYBRID_GET_PQC_PUBKEY_LEN:
            CHECK_UINT32_LEN_AND_INFO(ctx, len);
            if (ctx->pqcMethod == NULL || ctx->pqcCtx == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYINFO_NOT_SET);
                return CRYPT_COMPOSITE_KEYINFO_NOT_SET;
            }
            return ctx->pqcMethod->ctrl(ctx->pqcCtx, CRYPT_CTRL_GET_PUBKEY_LEN, val, len);
```

---


---

## GEMINI Review

# Code Review: openhitls/pqcp#33
**Reviewer**: GEMINI


## Critical

### Incorrect buffer pointer arithmetic and initialization
`src/composite_sign/src/crypt_composite_sign.c:389`
```
BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data, + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
    RETURN_RET_IF_ERR(CRYPT_CompositeSetPqcPrvKey(ctx, &pqcPrv), ret);
```
**Issue**: The initialization of `tradPrv` uses the comma operator incorrectly within the brace initializer, or attempts to initialize 3 fields when `BSL_Buffer` likely has 2. Critically, `tradPrv.data` is initialized to `prv->data` (the start of the buffer) instead of the offset pointer. This causes the traditional private key to be set using the PQC private key data.
**Fix**:
```
BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
    RETURN_RET_IF_ERR(CRYPT_CompositeSetPqcPrvKey(ctx, &pqcPrv), ret);
```

---


## Low

### Missing break statement in switch case
`src/provider/pqcp_pkey.c:46-49`
```
case CRYPT_PKEY_COMPOSITE_SIGN:
            pkeyCtx = CRYPT_COMPOSITE_NewCtx();
        default:
            break;
```
**Issue**: The `CRYPT_PKEY_COMPOSITE_SIGN` case falls through to the `default` case. While the `default` case contains a `break`, relying on this fallthrough is fragile and considered bad practice.
**Fix**:
```
case CRYPT_PKEY_COMPOSITE_SIGN:
            pkeyCtx = CRYPT_COMPOSITE_NewCtx();
            break;
        default:
            break;
```

---

### Duplicate const qualifier
`src/provider/pqcp_pkey.c:147`
```
const const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```
**Issue**: The variable `g_pqcpKeyMgmtCompositeSign` is declared with `const const`. This is redundant.
**Fix**:
```
const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```

---


---

## CODEX Review

# Code Review: openhitls/pqcp#33
**Reviewer**: CODEX


## High

### Duplicate const qualifier breaks build
`src/provider/pqcp_pkey.c:145`
```
const const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```
**Issue**: The declaration uses `const const`, which is invalid C and will not compile.
**Fix**:
```
const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```

---

### Traditional private key slice uses wrong buffer pointer
`src/composite_sign/src/crypt_composite_sign.c:386-388`
```
BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
BSL_Buffer tradPrv = {prv->data, + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
```
**Issue**: The SM2 private key buffer is initialized from the start of the composite key (and with an extra initializer), so the PQC seed is reused as the TRAD key. This corrupts key imports and can cause invalid keys or failures.
**Fix**:
```
BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen,
                      prv->len - ctx->info->pqcPrvkeyLen};
```

---


## Medium

### Composite key setters accept truncated keys
`src/composite_sign/src/crypt_composite_sign.c:385-399`
```
RETURN_RET_IF(prv->len <= ctx->info->pqcPrvkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
...
RETURN_RET_IF(pub->len <= ctx->info->pqcPubkeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
```
**Issue**: The length checks only ensure the buffer is larger than the PQC part, so a too-short TRAD component can be accepted, resulting in malformed keys and undefined behavior in downstream algorithms.
**Fix**:
```
RETURN_RET_IF(prv->len != ctx->info->compPrvKeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
...
RETURN_RET_IF(pub->len != ctx->info->compPubKeyLen, CRYPT_COMPOSITE_KEYLEN_ERROR);
```

---

### CRYPT_CTRL_SET_CTX_INFO allows NULL input with non-zero length
`src/composite_sign/src/crypt_composite_sign.c:214-225`
```
if (len > COMPOSITE_MAX_CTX_BYTES) {
    BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
    return CRYPT_COMPOSITE_KEYLEN_ERROR;
}
...
ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
```
**Issue**: `val` is not validated before being copied. If the caller passes `len > 0` with `val == NULL`, `BSL_SAL_Dump` will dereference NULL and crash.
**Fix**:
```
if (len > COMPOSITE_MAX_CTX_BYTES) {
    BSL_ERR_PUSH_ERROR(CRYPT_COMPOSITE_KEYLEN_ERROR);
    return CRYPT_COMPOSITE_KEYLEN_ERROR;
}
if (val == NULL && len > 0) {
    BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
    return CRYPT_NULL_INPUT;
}
ctx->ctxInfo = BSL_SAL_Dump((uint8_t *)val, len);
```

---

### Missing NULL checks for GetParamValue results in Get*KeyEx
`src/composite_sign/src/crypt_composite_sign.c:414-435`
```
BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
if (ret != CRYPT_SUCCESS) {
    return ret;
}
paramPrv->useLen = prv.len;

BSL_Param *paramPub = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
int32_t ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
if (ret != CRYPT_SUCCESS) {
    return ret;
}
paramPub->useLen = pub.len;
```
**Issue**: If the requested param is absent, `GetParamValue` can return NULL and `paramPrv/paramPub` are dereferenced, causing a crash instead of returning an error.
**Fix**:
```
BSL_Param *paramPrv = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PRVKEY, &prv.data, &(prv.len));
if (paramPrv == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
    return CRYPT_INVALID_ARG;
}
int32_t ret = CRYPT_COMPOSITE_GetPrvKey(ctx, &prv);
if (ret != CRYPT_SUCCESS) {
    return ret;
}
paramPrv->useLen = prv.len;

BSL_Param *paramPub = GetParamValue(para, CRYPT_PARAM_COMPOSITE_PUBKEY, &pub.data, &(pub.len));
if (paramPub == NULL) {
    BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
    return CRYPT_INVALID_ARG;
}
int32_t ret = CRYPT_COMPOSITE_GetPubKey(ctx, &pub);
if (ret != CRYPT_SUCCESS) {
    return ret;
}
paramPub->useLen = pub.len;
```

---

### Composite algorithm labels mismatched for MLDSA65/87
`src/composite_sign/src/crypt_composite_sign.c:54-58`
```
{CRYPT_COMPOSITE_MLDSA65_SM2, "COMPSIG-MLDSA44-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65,
    CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 2017, 64, 1952, 32, 3309,
},
{CRYPT_COMPOSITE_MLDSA87_SM2, "COMPSIG-MLDSA44-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87,
    CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 2657, 64, 2592, 32, 4627,
},
```
**Issue**: The MLDSA65 and MLDSA87 entries use the MLDSA44 label, so the domain-separation label in the signed message is incorrect for those variants. This can break interoperability and produce non-spec signatures.
**Fix**:
```
{CRYPT_COMPOSITE_MLDSA65_SM2, "COMPSIG-MLDSA65-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_65,
    CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 2017, 64, 1952, 32, 3309,
},
{CRYPT_COMPOSITE_MLDSA87_SM2, "COMPSIG-MLDSA87-SM2", CRYPT_PKEY_ML_DSA, CRYPT_MLDSA_TYPE_MLDSA_87,
    CRYPT_PKEY_SM2, 0, CRYPT_MD_SM3, CRYPT_MD_SM3, 0, 2657, 64, 2592, 32, 4627,
},
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
