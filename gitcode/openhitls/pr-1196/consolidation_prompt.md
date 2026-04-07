# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1196
- Title: 

## Individual Review Reports

## CLAUDE Review

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


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1196
**Reviewer**: CODEX


## High

### Mixed DTLS/DTLCP version mapping can accept unsupported DTLS1.0 hellos
`tls/handshake/recv/src/recv_client_hello.c:596-605`
```
bool isGreater = !IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask) ||
                 IS_SUPPORT_TLCP(ctx->config.tlsConfig.originVersionMask);

for (uint32_t i = 0; i < sizeof(versions) / sizeof(versions[0]); i++) {
    if (isGreater? version >= versions[i] : version <= versions[i]) {
        ret |= MapVersion2VersionBit(IS_SUPPORT_DATAGRAM(ctx->config.tlsConfig.originVersionMask), versions[i]);
    }
}
if ((IS_SUPPORT_TLS(ret) || IS_SUPPORT_DTLS(ret)) && IS_SUPPORT_TLCP(ret)) {
    ret &= ~TLCP_VERSION_BITS;
}
```
**Issue**: The new DTLS mixed-support path now runs through `MapLegacyVersionToBits()`, but that helper still flips to `>=` ordering whenever any TLCP bit is present. After this PR, `HITLS_CFG_NewDTLSConfig()` sets `DTLS12_VERSION_BIT | DTLCP11_VERSION_BIT`, so a datagram server enters the TLCP-style comparison path. For `legacy_version = HITLS_VERSION_DTLS10`, the loop incorrectly maps `DTLS12_VERSION_BIT`, and `ServerSelectNegoVersion()` can negotiate DTLS1.2 instead of returning `HITLS_MSG_HANDLE_UNSUPPORT_VERSION`. That regresses the existing DTLS1.2 version check.
**Fix**:
```
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

if ((IS_SUPPORT_TLS(ret) || IS_SUPPORT_DTLS(ret)) && IS_SUPPORT_TLCP(ret)) {
    ret &= ~TLCP_VERSION_BITS;
}
```

---


## Medium

### NewDTLSConfig now advertises DTLCP support that the client path immediately removes
`tls/config/src/config_dtls.c:75-85`
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
**Issue**: `HITLS_CFG_NewDTLSConfig()` now adds `DTLCP11_VERSION_BIT` to every full DTLS config, so the returned object reports DTLCP support and gets DTLCP cipher suites/groups/signatures by default. But the PR also changed `ConnectEventInIdleState()` to strip `DTLCP11_VERSION_BIT` from any client whose original mask contains both DTLS and DTLCP. That makes the new behavior server-only and leaves callers with a config that claims DTLCP support but can never send a DTLCP ClientHello, causing confusing connect-time failures against DTLCP-only peers.
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


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the file (code or docs)
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
- Only include issues you've verified in the changed files (code or docs)
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
