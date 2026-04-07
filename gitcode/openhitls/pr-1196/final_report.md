# Final Code Review Report
## openHiTLS/openhitls - PR #1196

### Summary
- **Total Issues**: 3
- **Critical**: 0
- **High**: 0
- **Medium**: 3
- **Low**: 0
- **Reviewers**: claude, gemini, codex

---


## Medium

### NewDTLSConfig advertises DTLCP support that client path immediately removes
`tls/config/src/config_dtls.c:75-80`
**Reviewers**: CODEX | **置信度**: 较可信
```
#ifdef HITLS_TLS_PROTO_DTLS12
    newConfig->version |= DTLS12_VERSION_BIT;
#endif
#ifdef HITLS_TLS_PROTO_DTLCP11
    newConfig->version |= DTLCP11_VERSION_BIT;
#endif

newConfig->libCtx = libCtx;
newConfig->attrName = attrName;

newConfig->originVersionMask = newConfig->version;
```
**Issue**: HITLS_CFG_NewDTLSConfig() now sets both DTLS12_VERSION_BIT and DTLCP11_VERSION_BIT by default, making the returned config advertise DTLCP support. However, ConnectEventInIdleState() immediately strips DTLCP11_VERSION_BIT from any client config that contains both DTLS and DTLCP bits. This creates confusing behavior where a config claims DTLCP support but can never send a DTLCP ClientHello, causing connection failures against DTLCP-only peers.
**Fix**:
```
#ifdef HITLS_TLS_PROTO_DTLS12
    newConfig->version |= DTLS12_VERSION_BIT;
#endif
/* Keep HITLS_CFG_NewDTLSConfig() DTLS-only until the client path can
 * actually negotiate DTLCP as well. */

newConfig->libCtx = libCtx;
newConfig->attrName = attrName;

newConfig->originVersionMask = newConfig->version;
```

---

### DTLS version comparison logic uses wrong operator when TLCP bit is set
`tls/handshake/recv/src/recv_client_hello.c:596-605`
**Reviewers**: CODEX | **置信度**: 需评估
```
static uint32_t MapLegacyVersionToBits(const TLS_Ctx *ctx, uint16_t version)
{
    uint32_t ret = 0;
    uint16_t versions[] = {HITLS_VERSION_DTLS12, HITLS_VERSION_TLS12, HITLS_VERSION_TLCP_DTLCP11};
    bool isGreater = !IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) ||
                     IS_SUPPORT_TLCP(ctx->config.tlsConfig.originVersionMask);

    for (uint32_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        if (isGreater? version >= versions[i] : version <= versions[i]) {
            ret |= MapVersion2VersionBit(IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask), versions[i]);
        }
    }
```
**Issue**: The isGreater flag uses >= comparison whenever IS_SUPPORT_TLCP() is true, but this affects DTLS version comparisons incorrectly. DTLS version numbers are reversed (lower numeric value = higher protocol version), so DTLS requires <= comparisons. For a datagram server with both DTLS12 and DTLCP11 bits, receiving legacy_version=DTLS10 would incorrectly use >= instead of <= for the DTLS12 comparison. However, the current code appears to handle this correctly in practice since the result intersects with the server's supported versions and DTLS10 would select DTLS12 as the negotiated version. The issue may be more about code clarity than actual incorrect behavior.
**Fix**:
```
static uint32_t MapLegacyVersionToBits(const TLS_Ctx *ctx, uint16_t version)
{
    uint32_t ret = 0;
    uint16_t versions[] = {HITLS_VERSION_DTLS12, HITLS_VERSION_TLS12, HITLS_VERSION_TLCP_DTLCP11};
    bool isDatagram = IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask);

    for (uint32_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
        bool match;
        if (versions[i] == HITLS_VERSION_TLCP_DTLCP11) {
            match = version >= versions[i];
        } else if (isDatagram) {
            /* DTLS version numbers are reversed. */
            match = version <= versions[i];
        } else {
            match = version >= versions[i];
        }

        if (match) {
            ret |= MapVersion2VersionBit(isDatagram, versions[i]);
        }
    }
```

---

### Cipher suite validation bypass doesn't check negotiated version compatibility
`tls/config/src/config_check.c:104-107`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
static bool IsCipherSuiteValid(const TLS_Config *config, uint16_t cipherSuite)
{
    /* The cipher suite must match the configured version */
    return CFG_CheckCipherSuiteSupported(cipherSuite) == true &&
           (CFG_CheckCipherSuiteVersion(cipherSuite, config->minVersion, config->maxVersion) == true ||
           (IS_SUPPORT_TLCP(config->version) &&
           (cipherSuite == HITLS_ECDHE_SM4_CBC_SM3 || cipherSuite == HITLS_ECC_SM4_CBC_SM3 ||
            cipherSuite == HITLS_ECDHE_SM4_GCM_SM3 || cipherSuite == HITLS_ECC_SM4_GCM_SM3)));
}
```
**Issue**: The TLCP cipher suite bypass checks IS_SUPPORT_TLCP(config->version) but doesn't verify whether the actual negotiated version range (minVersion/maxVersion) includes TLCP. After ChangeMinMaxVersion(), if a config has both DTLS and DTLCP bits, the TLCP bits may be stripped from minVersion/maxVersion calculation while remaining in config->version. This could allow TLCP cipher suites to be configured that don't match the actual protocol version that will be negotiated. The proposed fix (adding IS_SUPPORT_DATAGRAM) is incomplete as it doesn't address the root cause of checking minVersion/maxVersion.
**Fix**:
```
static bool IsCipherSuiteValid(const TLS_Config *config, uint16_t cipherSuite)
{
    /* The cipher suite must match the configured version */
    return CFG_CheckCipherSuiteSupported(cipherSuite) == true &&
           (CFG_CheckCipherSuiteVersion(cipherSuite, config->minVersion, config->maxVersion) == true ||
           ((config->minVersion == HITLS_VERSION_TLCP_DTLCP11 || config->maxVersion == HITLS_VERSION_TLCP_DTLCP11) &&
           (cipherSuite == HITLS_ECDHE_SM4_CBC_SM3 || cipherSuite == HITLS_ECC_SM4_CBC_SM3 ||
            cipherSuite == HITLS_ECDHE_SM4_GCM_SM3 || cipherSuite == HITLS_ECC_SM4_GCM_SM3)));
}
```

---
