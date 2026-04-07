# Code Review: openHiTLS/openhitls#1196
**Reviewer**: CLAUDE


## Medium

### Cipher suite validation bypass doesn't check actual negotiated protocol
`tls/config/src/config_check.c:104-107`
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
**Issue**: The cipher suite validation bypass allows TLCP cipher suites whenever IS_SUPPORT_TLCP(config->version) is true, but it doesn't verify whether the actual negotiated version (minVersion/maxVersion) is compatible with TLCP/DTLCP. For example, if a config has version bits set for both DTLS12 and DTLCP11, but after ChangeMinMaxVersion the minVersion/maxVersion are set to DTLS12 only (because TLCP bits are cleared), the TLCP cipher suites would still be allowed by this bypass even though the negotiated version range doesn't include TLCP/DTLCP. This could allow cipher suites to be configured that don't match the actual protocol version that will be negotiated.
**Fix**:
```
static bool IsCipherSuiteValid(const TLS_Config *config, uint16_t cipherSuite)
{
    /* The cipher suite must match the configured version */
    return CFG_CheckCipherSuiteSupported(cipherSuite) == true &&
           (CFG_CheckCipherSuiteVersion(cipherSuite, config->minVersion, config->maxVersion) == true ||
           ((IS_SUPPORT_TLCP(config->version) && IS_SUPPORT_DATAGRAM(config->version)) &&
           (cipherSuite == HITLS_ECDHE_SM4_CBC_SM3 || cipherSuite == HITLS_ECC_SM4_CBC_SM3 ||
            cipherSuite == HITLS_ECDHE_SM4_GCM_SM3 || cipherSuite == HITLS_ECC_SM4_GCM_SM3)));
}
```

---
