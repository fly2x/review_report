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
