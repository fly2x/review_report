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
