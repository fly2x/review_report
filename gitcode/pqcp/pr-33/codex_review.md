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
