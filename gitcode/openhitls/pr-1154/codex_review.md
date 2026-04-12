# Code Review: openHiTLS/openhitls#1154
**Reviewer**: CODEX


## High

### Composite keys are misclassified as legacy ECDSA certificate types
`tls/handshake/common/src/hs_cert.c:39-43`
```
case TLS_CERT_KEY_TYPE_SM2:
        case TLS_CERT_KEY_TYPE_ECDSA:
        case TLS_CERT_KEY_TYPE_ED25519:
        case TLS_CERT_KEY_TYPE_COMPOSITE:
            return CERT_TYPE_ECDSA_SIGN;
```
**Issue**: This maps a TLS1.3-only composite key to `CERT_TYPE_ECDSA_SIGN`, which is consumed by the TLS1.2/DTLS1.2 certificate-type and certificate-selection code. That lets legacy `ECDHE_ECDSA_*` paths request or select a composite certificate, including the RSA-based composite variants added by this PR, even though those handshakes have no valid composite cert type.
**Fix**:
```
case TLS_CERT_KEY_TYPE_SM2:
        case TLS_CERT_KEY_TYPE_ECDSA:
        case TLS_CERT_KEY_TYPE_ED25519:
            return CERT_TYPE_ECDSA_SIGN;
        case TLS_CERT_KEY_TYPE_COMPOSITE:
            return CERT_TYPE_UNKNOWN;
```

---


## Medium

### TLS1.3-only composite schemes leak into mixed TLS1.2/TLS1.3 defaults
`tls/config/src/config_sign.c:34-51`
```
static const uint16_t DEFAULT_SIGSCHEME_ID[] = {
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PKCS15_SHA256,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_ED25519_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_ECDSA_P256_SHA256,
    ...
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_RSA4096_PSS_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_ECDSA_P521_SHA512,
    CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
```
**Issue**: These entries are inserted into the single global default `signAlgorithms` array whenever TLS1.3 is enabled in the config. The TLS1.2/DTLS1.2 packing and certificate-selection paths later reuse that array without checking `chainVersionBits`, so a dual-stack endpoint can advertise or even negotiate composite schemes in legacy handshakes where they are not valid.
**Fix**:
```
for (uint32_t i = 0; i < sizeof(DEFAULT_SIGSCHEME_ID) / sizeof(DEFAULT_SIGSCHEME_ID[0]); i++) {
    const TLS_SigSchemeInfo *info = ConfigGetSignatureSchemeInfo(config, DEFAULT_SIGSCHEME_ID[i]);
    if (info == NULL || (config->version & info->chainVersionBits) == 0) {
        continue;
    }
#if defined(HITLS_CRYPTO_COMPOSITE)
    /* Do not place TLS1.3-only composite schemes into the shared default list for mixed-version configs. */
    if (info->signAlgId == HITLS_SIGN_COMPOSITE &&
        !(config->minVersion == HITLS_VERSION_TLS13 && config->maxVersion == HITLS_VERSION_TLS13)) {
        continue;
    }
#endif
    tempItems[size++] = DEFAULT_SIGSCHEME_ID[i];
}
```

---

### Default composite fallback can select a TLS1.3-only scheme in legacy flows
`tls/cert/cert_adapt/cert.c:73-75`
```
#if defined(HITLS_CRYPTO_COMPOSITE)
        case TLS_CERT_KEY_TYPE_COMPOSITE:
            return CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256;
#endif
```
**Issue**: `SAL_CERT_GetDefaultSignHashAlgo()` has no negotiated-version input, but this new case returns a composite signature scheme unconditionally. Callers such as `CheckSignScheme()` and `VerifySignData()` use this fallback when the peer did not send `signature_algorithms`, so a TLS1.2 handshake can silently pick a TLS1.3-only composite code point instead of rejecting the certificate.
**Fix**:
```
#if defined(HITLS_CRYPTO_COMPOSITE)
        case TLS_CERT_KEY_TYPE_COMPOSITE:
            /* Composite must be selected from an explicit TLS1.3 signature_algorithms negotiation. */
            return CERT_SIG_SCHEME_UNKNOWN;
#endif
```

---

### Config validation accepts composite schemes as TLS1.2 ECDSA auth
`tls/config/src/config_check.c:65-67`
```
if (((signAlg == HITLS_SIGN_ECDSA) || (signAlg == HITLS_SIGN_ED25519) ||
            (signAlg == HITLS_SIGN_COMPOSITE)) &&
            (authAlg == HITLS_AUTH_ECDSA)) {
            return true;
        }
```
**Issue**: `CheckSign()` uses `HaveMatchSignAlg()` to validate legacy cipher-suite/auth compatibility. Adding `HITLS_SIGN_COMPOSITE` here makes the config checker accept TLS1.2 `HITLS_AUTH_ECDSA` suites when the only matching signature schemes are composite, so impossible deployments pass validation and fail later during handshake selection.
**Fix**:
```
/* Composite schemes are TLS1.3-only and must not satisfy legacy ECDSA cipher-suite checks. */
        if (((signAlg == HITLS_SIGN_ECDSA) || (signAlg == HITLS_SIGN_ED25519)) &&
            (authAlg == HITLS_AUTH_ECDSA)) {
            return true;
        }
```

---
