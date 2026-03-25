# Code Review: openHiTLS/openhitls#1032
**Reviewer**: CODEX


## High

### DNS/CN matching no longer enforces `hostnameLen`
`pki/x509_common/src/hitls_x509_util.c:208-225`
```
int32_t HITLS_X509_VerifyHostname(HITLS_X509_Cert *cert, uint32_t flags, const char *hostname, uint32_t hostnameLen)
{
    if (cert == NULL || hostname == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    int32_t (*MatchCb)(const char *pattern, const char *hostname);
    if ((flags & HITLS_X509_FLAG_VFY_WITH_PARTIAL_WILDCARD) != 0) {
        MatchCb = MatchWithPartialWildcard;
    } else {
        MatchCb = MatchWithSingleWildcard;
    }

    int32_t ret = X509_VerifyHostnameWithSan(cert, hostname, hostnameLen, MatchCb);
    if (ret == HITLS_X509_ERR_EXT_NOT_FOUND) {
        return X509_VerifyHostnameWithCn(cert, hostname, MatchCb);
    }
```
**Issue**: The removed `hostnameLen == strlen(hostname)` validation means the DNS/CN paths now ignore the supplied length and keep treating `hostname` as a C string. Inputs with embedded NULs or truncated lengths can still match, and the new binary-IP caller can also fall through into CN matching when SAN is absent because `X509_VerifyHostnameWithCn()` still uses string semantics.
**Fix**:
```
int32_t HITLS_X509_VerifyHostname(HITLS_X509_Cert *cert, uint32_t flags,
    const char *hostname, uint32_t hostnameLen)
{
    if (cert == NULL || hostname == NULL || hostnameLen != (uint32_t)strlen(hostname)) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    ...
}

/* Add a separate SAN-IP helper for binary IP addresses and call that from
 * X509_CheckHost() instead of reusing the C-string hostname API. */
```

---

### Connection-specific host state was added to a shared store object
`pki/x509_verify/include/hitls_x509_verify.h:45-50`
```
BslList *hostnames;         // list of verify hostname
    unsigned char *ip;          // verify ip
    int32_t ipLen;
    uint32_t hostflags;         // verify hostfalg

    char *peername;             // hostname matched after verification
```
**Issue**: These fields live inside `HITLS_X509_StoreCtx` via `verifyParam`, but store contexts are refcount-shared when one `HITLS_Config` is cloned into multiple `HITLS_Ctx` objects. `HITLS_SetHost*()` and `HITLS_GetPeerName()` therefore mutate shared state instead of per-connection state, so sibling contexts created from the same config can overwrite each other's verification target and peer name.
**Fix**:
```
typedef struct {
    BslList *hostnames;
    unsigned char *ip;
    int32_t ipLen;
    uint32_t hostflags;
    char *peername;
} HITLS_X509_HostVerifyState;

/* Keep HITLS_X509_VerifyParam store-wide and move HITLS_X509_HostVerifyState
 * onto a per-HITLS_Ctx / per-connection object. Thread that state through
 * HITLS_SetHostFlags(), HITLS_SetHost(), HITLS_AddHost(), HITLS_GetPeerName()
 * and X509_CheckHost() instead of storing it in HITLS_X509_StoreCtx. */
```

---


## Medium

### SetVerifyParam can return success with stale or missing host targets
`pki/x509_verify/src/hitls_x509_verify.c:710-726`
```
storeCtx->verifyParam.hostflags = verifyParam->hostflags;
    if (verifyParam->hostnames != NULL) {
        BSL_LIST_FREE(storeCtx->verifyParam.hostnames, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
        storeCtx->verifyParam.hostnames = BSL_LIST_Copy(verifyParam->hostnames, (BSL_LIST_PFUNC_DUP)DupString,
            (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    }
    if (verifyParam->ip != NULL && verifyParam->ipLen > 0) {
        BSL_SAL_FREE(storeCtx->verifyParam.ip);
        storeCtx->verifyParam.ip = BSL_SAL_Calloc(verifyParam->ipLen + 1, sizeof(unsigned char));
```
**Issue**: `X509_SetVerifyParam()` mutates `hostnames` and `ip` in place. It frees the old hostname list before copying the new one, never checks whether `BSL_LIST_Copy()` failed, and leaves the previous host/IP untouched whenever the incoming field is NULL. That can silently disable hostname verification after an allocation failure or keep enforcing a stale identity when the caller intended to replace or clear it.
**Fix**:
```
BslList *newHostnames = NULL;
    unsigned char *newIp = NULL;
    int32_t newIpLen = 0;

    if (verifyParam->hostnames != NULL && BSL_LIST_COUNT(verifyParam->hostnames) > 0) {
        newHostnames = BSL_LIST_Copy(verifyParam->hostnames, (BSL_LIST_PFUNC_DUP)DupString,
            (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
        if (newHostnames == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }

    /* allocate/copy verifyParam->ip into newIp/newIpLen here, then swap */
    BSL_LIST_FREE(storeCtx->verifyParam.hostnames, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    storeCtx->verifyParam.hostnames = newHostnames;
    BSL_SAL_FREE(storeCtx->verifyParam.ip);
    storeCtx->verifyParam.ip = newIp;
    storeCtx->verifyParam.ipLen = newIpLen;
```

---

### Peername survives failed or IP-based revalidation
`pki/x509_verify/src/hitls_x509_verify.c:1718-1758`
```
static int32_t X509_CheckHost(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    int32_t ret = HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    if (storeCtx->verifyParam.hostnames != NULL && BSL_LIST_COUNT(storeCtx->verifyParam.hostnames) > 0) {
        ret = CheckHostnames(storeCtx, chain);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    if (storeCtx->verifyParam.ip != NULL) {
        HITLS_X509_Cert *certee = BSL_LIST_GET_FIRST(chain);
        ret = HITLS_X509_VerifyHostname(certee, storeCtx->verifyParam.hostflags, (char *)storeCtx->verifyParam.ip,
            storeCtx->verifyParam.ipLen);
```
**Issue**: `peername` is only replaced inside the successful DNS hostname branch. If a previous verification matched a hostname and the next verification fails or verifies only an IP SAN, `HITLS_GetPeerName()` still returns the old peer name for the current connection.
**Fix**:
```
static int32_t X509_CheckHost(HITLS_X509_StoreCtx *storeCtx, HITLS_X509_List *chain)
{
    BSL_SAL_FREE(storeCtx->verifyParam.peername);
    storeCtx->verifyParam.peername = NULL;

    int32_t ret = HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
    ...
}
```

---
