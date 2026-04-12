# Final Code Review Report
## openHiTLS/openhitls - PR #1233

### Summary
- **Total Issues**: 3
- **Critical**: 0
- **High**: 1
- **Medium**: 2
- **Low**: 0
- **Reviewers**: codex

---


## High

### StoreCtxDup breaks `VFY_LOCATION`-only builds
`pki/x509_verify/src/hitls_x509_verify.c:1867-1872`
**Reviewers**: codex | **置信度**: 需评估
```
static int32_t X509_CopyStringList(BslList *dst, const BslList *src)
{
    for (BslListNode *node = BSL_LIST_FirstNode(src); node != NULL; node = BSL_LIST_GetNextNode(src, node)) {
        char *value = (char *)BSL_LIST_GetData(node);
        char *copy = DupString(value);
        if (copy == NULL) {
```
**Issue**: `X509_CopyStringList()` now calls `DupString()` unconditionally, but `DupString()` is only compiled under `#ifdef HITLS_PKI_X509_VFY_IDENTITY`. `HITLS_X509_StoreCtxDup()` uses `X509_CopyStringList()` for `caPaths` when `HITLS_PKI_X509_VFY_LOCATION` is enabled, so the supported option set `HITLS_PKI_X509_VFY_LOCATION=ON` and `HITLS_PKI_X509_VFY_IDENTITY=OFF` will fail to compile/link.
**Fix**:
```
static int32_t X509_CopyStringList(BslList *dst, const BslList *src)
{
    for (BslListNode *node = BSL_LIST_FirstNode(src); node != NULL; node = BSL_LIST_GetNextNode(src, node)) {
        char *value = (char *)BSL_LIST_GetData(node);
        size_t len = strlen(value) + 1;
        char *copy = BSL_SAL_Dump(value, len);
        if (copy == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
        copy[len - 1] = '\0';

        int32_t ret = BSL_LIST_AddElement(dst, copy, BSL_LIST_POS_END);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_Free(copy);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
}
```

---


## Medium

### Generic SAN walker changes IP-verification failure into `EXT_NOT_FOUND`
`pki/x509_common/src/hitls_x509_util.c:167-192`
**Reviewers**: codex | **置信度**: 需评估
```
static int32_t X509_TrvSubjectAltName(HITLS_X509_Cert *cert, uint32_t nameType, X509_SanMatchCb matchCb, void *ctx,
    int32_t mismatchRet)
{
    HITLS_X509_ExtSan san = {0};
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SAN, &san, sizeof(san));
    if (ret != HITLS_PKI_SUCCESS || san.names == NULL) {
        return HITLS_X509_ERR_EXT_NOT_FOUND;
    }

    ret = HITLS_X509_ERR_EXT_NOT_FOUND;
    for (BslListNode *nameNode = BSL_LIST_FirstNode(san.names); nameNode != NULL;
        nameNode = BSL_LIST_GetNextNode(san.names, nameNode)) {
        HITLS_X509_GeneralName *gn = (HITLS_X509_GeneralName *)BSL_LIST_GetData(nameNode);
        if (gn->type != nameType) {
            continue;
        }
        ret = mismatchRet;
```
**Issue**: The new shared SAN traversal helper initializes `ret` to `HITLS_X509_ERR_EXT_NOT_FOUND` and only switches to `mismatchRet` after it sees the requested SAN type. That preserves hostname fallback behavior, but it regresses `X509_VerifyIp()`: when a certificate has a SAN extension but no `iPAddress` entry, the old code returned `HITLS_X509_ERR_VFY_IP_FAIL`, while the refactored path now returns `HITLS_X509_ERR_EXT_NOT_FOUND`. Callers can no longer distinguish “SAN exists but the requested IP is absent” from “SAN extension is absent”.
**Fix**:
```
static int32_t X509_TrvSubjectAltName(HITLS_X509_Cert *cert, uint32_t nameType, X509_SanMatchCb matchCb, void *ctx,
    int32_t noSanRet, int32_t noMatchRet)
{
    HITLS_X509_ExtSan san = {0};
    int32_t ret = HITLS_X509_CertCtrl(cert, HITLS_X509_EXT_GET_SAN, &san, sizeof(san));
    if (ret != HITLS_PKI_SUCCESS || san.names == NULL) {
        return noSanRet;
    }

    ret = noMatchRet;
    for (BslListNode *nameNode = BSL_LIST_FirstNode(san.names); nameNode != NULL;
        nameNode = BSL_LIST_GetNextNode(san.names, nameNode)) {
        HITLS_X509_GeneralName *gn = (HITLS_X509_GeneralName *)BSL_LIST_GetData(nameNode);
        if (gn->type != nameType) {
            continue;
        }
        int32_t matchRet = matchCb(&gn->value, ctx);
        if (matchRet == HITLS_PKI_SUCCESS) {
            ret = HITLS_PKI_SUCCESS;
            break;
        }
        if (matchRet != noMatchRet) {
            ret = matchRet;
            break;
        }
    }

    HITLS_X509_ClearSubjectAltName(&san);
    return ret;
}

/* hostname: fall back when SAN/DNS is absent */
return X509_TrvSubjectAltName(cert, HITLS_X509_GN_DNS, X509_MatchSanHostname, &matchCtx,
    HITLS_X509_ERR_EXT_NOT_FOUND, HITLS_X509_ERR_EXT_NOT_FOUND);

/* IP: fail when SAN exists but has no IP entry */
return X509_TrvSubjectAltName(cert, HITLS_X509_GN_IP, X509_MatchSanIp, &ipBuff,
    HITLS_X509_ERR_EXT_NOT_FOUND, HITLS_X509_ERR_VFY_IP_FAIL);
```

---

### StoreCtxDup copies session-bound `usrData` into the clone
`pki/x509_verify/src/hitls_x509_verify.c:1969-1971`
**Reviewers**: codex | **置信度**: 需评估
```
#ifdef HITLS_PKI_X509_VFY_CB
    newCtx->verifyCb = ctx->verifyCb;
    newCtx->usrData = ctx->usrData;
#endif
```
**Issue**: The new public API is documented as a deep copy of configuration with session state reset, but it copies `usrData` verbatim. In the TLS path, `usrData` is set to the active `HITLS_Ctx *` immediately before verification. Duplicating a store after it has been used therefore propagates a stale per-connection pointer into the new store, and later verification callbacks can observe or dereference the wrong/freed context.
**Fix**:
```
#ifdef HITLS_PKI_X509_VFY_CB
    newCtx->verifyCb = ctx->verifyCb;
    newCtx->usrData = NULL;
#endif
```

---
