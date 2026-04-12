# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1154
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/openhitls#1154
**Reviewer**: CLAUDE


## Critical

### Undefined BSL_CID_COMPOSITE constant
`include/tls/hitls_cert_type.h:170`
```
TLS_CERT_KEY_TYPE_COMPOSITE = BSL_CID_COMPOSITE
```
**Issue**: The code uses BSL_CID_COMPOSITE but this constant is not defined anywhere in the codebase. This will cause a compilation error.
**Fix**:
```
Define BSL_CID_COMPOSITE in include/bsl/bsl_obj.h (or appropriate header) with a unique value, e.g.:
    BSL_CID_COMPOSITE = 256,  /* identifies composite signature algorithms */
```

---

### Undefined BSL_CID_COMPOSITE constant
`include/tls/hitls_crypt_type.h:173`
```
HITLS_SIGN_COMPOSITE = BSL_CID_COMPOSITE,
```
**Issue**: The code uses BSL_CID_COMPOSITE but this constant is not defined anywhere in the codebase. This will cause a compilation error.
**Fix**:
```
Define BSL_CID_COMPOSITE in include/bsl/bsl_obj.h (or appropriate header) with a unique value, e.g.:
    BSL_CID_COMPOSITE = 256,  /* identifies composite signature algorithms */
```

---

### Undefined CRYPT_COMPOSITE_* and BSL_CID_MLDSA_* constants
`tls/config/src/config_sign.c:117-311`
```
{
        CONST_CAST("composite_mldsa44_rsa2048_pss_sha256"),
        CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256,
        TLS_CERT_KEY_TYPE_COMPOSITE,
        CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256,  /* UNDEFINED */
        BSL_CID_MLDSA44_RSA2048_PSS_SHA256,           /* UNDEFINED */
        ...
    },
```
**Issue**: The code uses multiple undefined constants: CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256, BSL_CID_MLDSA44_RSA2048_PSS_SHA256, etc. These are used in TLS_SigSchemeInfo structures but are not defined anywhere.
**Fix**:
```
Add the following definitions in include/crypto/crypt_algid.h:
```

---

### Missing HITLS_CRYPTO_COMPOSITE feature definition
`tls/config/src/config_sign.c:112-311`
```
#ifdef HITLS_CRYPTO_COMPOSITE
    {
        CONST_CAST("composite_mldsa44_rsa2048_pss_sha256"),
        ...
    },
#endif /* HITLS_CRYPTO_COMPOSITE */
```
**Issue**: The code is wrapped in `#ifdef HITLS_CRYPTO_COMPOSITE` but this feature macro is not defined in the configuration headers. This will cause the composite signature support to never be compiled.
**Fix**:
```
Add HITLS_CRYPTO_COMPOSITE feature definition in config/macro_config/hitls_config_layer_crypto.h:
```

---

### Duplicate undefined constants in provider
`crypto/provider/src/default/crypt_default_provider.c:904-1114`
```
{
        CONST_CAST("composite_mldsa44_rsa2048_pss_sha256"),
        CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256,
        TLS_CERT_KEY_TYPE_COMPOSITE,
        CRYPT_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256,  /* UNDEFINED */
        BSL_CID_MLDSA44_RSA2048_PSS_SHA256,           /* UNDEFINED */
        ...
    },
```
**Issue**: The same undefined CRYPT_COMPOSITE_* and BSL_CID_MLDSA44_* constants are used in the crypto provider. Once defined, they will work here too, but the issue must be fixed at the definition source.
**Fix**:
```
Same fix as for tls/config/src/config_sign.c - define the constants in the appropriate headers (include/crypto/crypt_algid.h and include/bsl/bsl_obj.h).
```

---


## High

### Missing feature guard for composite signature default
`tls/cert/cert_adapt/cert.c:73-76`
```
#if defined(HITLS_CRYPTO_COMPOSITE)
        case TLS_CERT_KEY_TYPE_COMPOSITE:
            return CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256;
#endif
```
**Issue**: The code adds a case for TLS_CERT_KEY_TYPE_COMPOSITE wrapped in HITLS_CRYPTO_COMPOSITE, but there's no check that this feature is enabled before using the default signature scheme.
**Fix**:
```
The code is correct, but ensure HITLS_CRYPTO_COMPOSITE is properly defined in the build configuration. If the feature is not intended to be compile-time optional, remove the #ifdef guard.
```

---


## Medium

### Removed error stack validation
`testcode/sdv/testcase/tls/ciphersuite/test_suite_sdv_hlt_group_signature.c:239`
```
ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

EXIT:  /* Line 239 - ASSERT_TRUE(TestIsErrStackEmpty()); was removed */
    HLT_FreeAllProcess();
```
**Issue**: The test removed `ASSERT_TRUE(TestIsErrStackEmpty());` which validates that no errors were left on the error stack after the CONNECT function. This could hide issues.
**Fix**:
```
ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
    ASSERT_TRUE(TestIsErrStackEmpty());

EXIT:
    HLT_FreeAllProcess();
```

---


## Low

### Inconsistent code formatting in if-else chain
`testcode/sdv/testcase/tls/ciphersuite/test_suite_sdv_hlt_group_signature.c:86-90`
```
} else
    if (strncmp(cert, "COMPOSITE_MLDSA65_RSA4096_PSS_SHA512", strlen("COMPOSITE_MLDSA65_RSA4096_PSS_SHA512")) == 0) {
```
**Issue**: The code has inconsistent formatting where the `else` keyword is on one line and the following `if` statement is on the next line, unlike all other branches.
**Fix**:
```
} else if (strncmp(cert, "COMPOSITE_MLDSA65_RSA4096_PSS_SHA512", strlen("COMPOSITE_MLDSA65_RSA4096_PSS_SHA512")) == 0) {
```

---


---

## GEMINI Review

# Code Review: openHiTLS/openhitls#1154
**Reviewer**: GEMINI


## Medium

### Removal of error stack emptiness assertion
`testcode/sdv/testcase/tls/ciphersuite/test_suite_sdv_hlt_group_signature.c:236-240`
```
ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);
EXIT:
    HLT_FreeAllProcess();
```
**Issue**: The PR incorrectly removes the `ASSERT_TRUE(TestIsErrStackEmpty());` check at the end of the `CONNECT` function. This assertion is critical for verifying that no unhandled errors were pushed to the error stack during a successful TLS handshake or read sequence. Removing it masks potential bugs and error state leakage.
**Fix**:
```
ASSERT_TRUE(readLen == strlen("Hello World"));
    ASSERT_TRUE(memcmp("Hello World", readBuf, readLen) == 0);

    ASSERT_TRUE(TestIsErrStackEmpty());
EXIT:
    HLT_FreeAllProcess();
```

---


## Low

### Missing conditional compilation for composite signature schemes
`tls/config/src/config_sign.c:34-52`
```
static const uint16_t DEFAULT_SIGSCHEME_ID[] = {
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PKCS15_SHA256,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_ED25519_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_ECDSA_P256_SHA256,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_RSA3072_PSS_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_RSA3072_PKCS15_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_RSA4096_PSS_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_RSA4096_PKCS15_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_ECDSA_P256_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_ECDSA_P384_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_ED25519_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_ECDSA_P384_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_RSA3072_PSS_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_RSA4096_PSS_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_ECDSA_P521_SHA512,
    CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
```
**Issue**: The composite signature schemes are unconditionally added to the `DEFAULT_SIGSCHEME_ID` array. Since their corresponding definitions in `SIGNATURE_SCHEME_INFO` are guarded by `#ifdef HITLS_CRYPTO_COMPOSITE`, these array elements should also be wrapped in the same macro to ensure consistency and avoid unnecessary iterations when the feature is disabled.
**Fix**:
```
static const uint16_t DEFAULT_SIGSCHEME_ID[] = {
#ifdef HITLS_CRYPTO_COMPOSITE
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PSS_SHA256,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_RSA2048_PKCS15_SHA256,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_ED25519_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA44_ECDSA_P256_SHA256,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_RSA3072_PSS_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_RSA3072_PKCS15_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_RSA4096_PSS_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_RSA4096_PKCS15_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_ECDSA_P256_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_ECDSA_P384_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA65_ED25519_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_ECDSA_P384_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_RSA3072_PSS_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_RSA4096_PSS_SHA512,
    CERT_SIG_SCHEME_COMPOSITE_MLDSA87_ECDSA_P521_SHA512,
#endif
    CERT_SIG_SCHEME_ECDSA_SECP256R1_SHA256,
```

---


---

## CODEX Review

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
