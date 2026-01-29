# Code Review: openHiTLS/openhitls#1032
**Reviewer**: CODEX


## High

### IP SAN compared to hostname string (binary mismatch + OOB read)
`pki/x509_common/src/hitls_x509_util.c:182-184`
```
} else if (gn->type == HITLS_X509_GN_IP) {
            ret = memcmp(gn->value.data, hostname, gn->value.dataLen);
            if (ret == HITLS_PKI_SUCCESS) {
```
**Issue**: `memcmp` compares raw SAN IP bytes against the ASCII hostname string for `gn->value.dataLen` bytes. This never matches valid IP SANs and can read past the hostname buffer (e.g., IPv6 "::" is 2 bytes but SAN length is 16), causing out-of-bounds reads and false verification failures.
**Fix**:
```
} else if (gn->type == HITLS_X509_GN_IP) {
            uint8_t ipbuf[16];
            int af = (gn->value.dataLen == 4) ? AF_INET :
                     (gn->value.dataLen == 16) ? AF_INET6 : -1;
            if (af != -1 && inet_pton(af, hostname, ipbuf) == 1 &&
                memcmp(gn->value.data, ipbuf, gn->value.dataLen) == 0) {
                ret = HITLS_PKI_SUCCESS;
                break;
            }
        }
```

---


## Medium

### Hostname/IP verification uses AND semantics
`pki/x509_verify/src/hitls_x509_verify.c:1998-2011`
```
if (storeCtx->verifyParam.hostnames != NULL && BSL_LIST_COUNT(storeCtx->verifyParam.hostnames) > 0) {
        ret = CheckHostnames(storeCtx, chain);
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }

    if (storeCtx->verifyParam.ip != NULL) {
        HITLS_X509_Cert *certee = BSL_LIST_GET_FIRST(chain);
        ret = HITLS_X509_VerifyHostname(certee, storeCtx->verifyParam.hostflags, storeCtx->verifyParam.ip, strlen(storeCtx->verifyParam.ip));
        if (ret != HITLS_PKI_SUCCESS) {
            return ret;
        }
    }
    return HITLS_PKI_SUCCESS;
```
**Issue**: If both hostnames and IP are configured, the function requires the hostname match to succeed before it even checks the IP. This makes verification fail even when the IP matches, which is surprising for an API that allows multiple hosts/IPs.
**Fix**:
```
bool matched = false;

    if (storeCtx->verifyParam.hostnames != NULL && BSL_LIST_COUNT(storeCtx->verifyParam.hostnames) > 0) {
        matched = (CheckHostnames(storeCtx, chain) == HITLS_PKI_SUCCESS);
    }

    if (!matched && storeCtx->verifyParam.ip != NULL) {
        HITLS_X509_Cert *certee = BSL_LIST_GET_FIRST(chain);
        matched = (HITLS_X509_VerifyHostname(certee, storeCtx->verifyParam.hostflags,
            storeCtx->verifyParam.ip, strlen(storeCtx->verifyParam.ip)) == HITLS_PKI_SUCCESS);
    }

    return matched ? HITLS_PKI_SUCCESS : HITLS_X509_ERR_VFY_HOSTNAME_FAIL;
```

---

### Host flag value read incorrectly on big-endian targets
`tls/cert/hitls_x509_adapt/hitls_x509_cert_store.c:105-110`
```
case CERT_STORE_CTRL_SET_HOST_FLAG:
            if (*(int64_t *)input > UINT32_MAX || *(int64_t *)input < 0) {
                return HITLS_CERT_STORE_CTRL_ERR_SET_HOST_FLAG;
            }
            return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_HOST_FLAG, (int64_t *)input,
                sizeof(uint32_t));
```
**Issue**: `CERT_STORE_CTRL_SET_HOST_FLAG` passes an `int64_t*` with a 4-byte length. On big-endian systems, `X509_SetHostFlags` will read the high 32 bits (zero for valid values), so hostflags are effectively ignored.
**Fix**:
```
case CERT_STORE_CTRL_SET_HOST_FLAG: {
            if (*(int64_t *)input > UINT32_MAX || *(int64_t *)input < 0) {
                return HITLS_CERT_STORE_CTRL_ERR_SET_HOST_FLAG;
            }
            uint32_t hostflag = (uint32_t)*(int64_t *)input;
            return HITLS_X509_StoreCtxCtrl(store, HITLS_X509_STORECTX_SET_HOST_FLAG, &hostflag,
                sizeof(hostflag));
        }
```

---


## Low

### Hostname verification ignores configured host flags
`pki/x509_verify/src/hitls_x509_verify.c:1977-1979`
```
for (char *hostname = BSL_LIST_GET_FIRST(storeCtx->verifyParam.hostnames); hostname != NULL;) {
        ret = HITLS_X509_VerifyHostname(certee, 0, hostname, strlen(hostname));
        if (ret == HITLS_PKI_SUCCESS) {
```
**Issue**: DNS hostname checks always pass `0` as flags, so the newly added `hostflags` setting is never applied to DNS matches (only to IP checks). This makes the host flag API ineffective for DNS validation.
**Fix**:
```
for (char *hostname = BSL_LIST_GET_FIRST(storeCtx->verifyParam.hostnames); hostname != NULL;) {
        ret = HITLS_X509_VerifyHostname(certee, storeCtx->verifyParam.hostflags, hostname, strlen(hostname));
        if (ret == HITLS_PKI_SUCCESS) {
```

---

### Missing error handling for hostnames copy failure
`pki/x509_verify/src/hitls_x509_verify.c:969-973`
```
if (verifyParam->hostnames != NULL) {
        BSL_LIST_FREE(storeCtx->verifyParam.hostnames, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
        storeCtx->verifyParam.hostnames = BSL_LIST_Copy(verifyParam->hostnames, (BSL_LIST_PFUNC_DUP)DupString,
            (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
    }
```
**Issue**: `BSL_LIST_Copy` can return NULL on allocation failure, but the code ignores it and returns success, silently dropping hostnames and masking the error.
**Fix**:
```
if (verifyParam->hostnames != NULL) {
        BSL_LIST_FREE(storeCtx->verifyParam.hostnames, (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
        storeCtx->verifyParam.hostnames = BSL_LIST_Copy(verifyParam->hostnames, (BSL_LIST_PFUNC_DUP)DupString,
            (BSL_LIST_PFUNC_FREE)BSL_SAL_Free);
        if (storeCtx->verifyParam.hostnames == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
            return BSL_MALLOC_FAIL;
        }
    }
```

---
