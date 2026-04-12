# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1217
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/openhitls#1217
**Reviewer**: CLAUDE


## Critical

### Undefined option HITLS_CRYPTO_PKEY_KEM prevents source compilation
`crypto/eal/CMakeLists.txt:38`
```
if(HITLS_CRYPTO_PKEY_KEM)
    list(APPEND _eal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_kem.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_KEM)` checks an option that is never defined in cmake/hitls_options.cmake or set anywhere. In CMake, undefined variables are falsy, so `eal_pkey_kem.c` will never be compiled even when KEM algorithms are enabled. The original `file(GLOB)` would have included this file.
**Fix**:
```
# Option should be defined in cmake/hitls_options.cmake, or use existing KEM algorithm flags
if(HITLS_CRYPTO_MLKEM OR HITLS_CRYPTO_FRODOKEM OR HITLS_CRYPTO_HPKE OR HITLS_CRYPTO_HYBRIDKEM OR HITLS_CRYPTO_MCELIECE)
    list(APPEND _eal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_kem.c)
endif()
```

---

### Undefined option HITLS_CRYPTO_PKEY_KEM prevents source compilation
`crypto/provider/CMakeLists.txt:42-44`
```
if(HITLS_CRYPTO_PKEY_KEM)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_kem.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_KEM)` checks an option that is never defined in cmake/hitls_options.cmake. This causes `crypt_default_kem.c` to never be compiled, breaking KEM functionality.
**Fix**:
```
if(HITLS_CRYPTO_MLKEM OR HITLS_CRYPTO_FRODOKEM OR HITLS_CRYPTO_HPKE OR HITLS_CRYPTO_HYBRIDKEM OR HITLS_CRYPTO_MCELIECE)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_kem.c)
endif()
```

---

### Undefined option HITLS_CRYPTO_PKEY_EXCH prevents source compilation
`crypto/provider/CMakeLists.txt:45-47`
```
if(HITLS_CRYPTO_PKEY_EXCH)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_keyexch.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_EXCH)` checks an option that is never defined. This causes `crypt_default_keyexch.c` to never be compiled, breaking key exchange functionality for ECDH, SM2, SM9, and X25519.
**Fix**:
```
if(HITLS_CRYPTO_ECDH OR HITLS_CRYPTO_SM2_EXCH OR HITLS_CRYPTO_SM9_EXCH OR HITLS_CRYPTO_X25519 OR HITLS_CRYPTO_DH)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_keyexch.c)
endif()
```

---

### Undefined option HITLS_CRYPTO_PKEY_CRYPT prevents source compilation
`crypto/provider/CMakeLists.txt:48-50`
```
if(HITLS_CRYPTO_PKEY_CRYPT)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_pkeycipher.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_CRYPT)` checks an option that is never defined. This causes `crypt_default_pkeycipher.c` to never be compiled, breaking public key encryption/decryption functionality for RSA, SM2, and SM9.
**Fix**:
```
if(HITLS_CRYPTO_RSA_ENCRYPT OR HITLS_CRYPTO_RSA_DECRYPT OR HITLS_CRYPTO_SM2_CRYPT OR HITLS_CRYPTO_SM9_CRYPT)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_pkeycipher.c)
endif()
```

---

### Undefined option HITLS_CRYPTO_PKEY_SIGN prevents source compilation
`crypto/provider/CMakeLists.txt:51-53`
```
if(HITLS_CRYPTO_PKEY_SIGN)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_sign.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_SIGN)` checks an option that is never defined. This causes `crypt_default_sign.c` to never be compiled, breaking signature functionality for RSA, DSA, ECDSA, Ed25519, SM2, SM9, and XMSS.
**Fix**:
```
if(HITLS_CRYPTO_RSA_SIGN OR HITLS_CRYPTO_RSA_VERIFY OR HITLS_CRYPTO_DSA OR HITLS_CRYPTO_ECDSA OR HITLS_CRYPTO_ED25519 OR HITLS_CRYPTO_SM2_SIGN OR HITLS_CRYPTO_SM9_SIGN OR HITLS_CRYPTO_XMSS OR HITLS_CRYPTO_MLDSA)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_sign.c)
endif()
```

---


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1217
**Reviewer**: CODEX


## High

### PQC-only builds can drop the `CRYPT_RandEx` implementation
`crypto/util/CMakeLists.txt:26-27`
```
if(HITLS_CRYPTO_DRBG OR HITLS_CRYPTO_CURVE25519 OR HITLS_CRYPTO_RSA OR HITLS_CRYPTO_BN_RAND OR HITLS_CRYPTO_SM9)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_rand.c)
endif()
```
**Issue**: This gate only pulls in `crypt_util_rand.c` for `DRBG`, `CURVE25519`, `RSA`, `BN_RAND`, or `SM9`, but several other valid feature combinations still call `CRYPT_RandEx()` or `CRYPT_Rand()`. For example, `crypto/mlkem/src/ml_kem.c:694`, `crypto/xmss/src/xmss_core.c:59`, `crypto/mldsa/src/ml_dsa.c:417`, `crypto/mceliece/src/mceliece.c:191`, and `crypto/frodokem/src/frodokem.c:43` all depend on that source. With this PR, a configure-only `HITLS_CRYPTO_MLKEM=ON` build can generate `ml_kem.c.o` without `crypt_util_rand.c.o`, which leaves undefined references at link time.
**Fix**:
```
if(HITLS_CRYPTO_DRBG OR HITLS_CRYPTO_CURVE25519 OR HITLS_CRYPTO_RSA OR HITLS_CRYPTO_BN_RAND OR
   HITLS_CRYPTO_SM9 OR HITLS_CRYPTO_MLKEM OR HITLS_CRYPTO_MLDSA OR HITLS_CRYPTO_SLH_DSA OR
   HITLS_CRYPTO_XMSS OR HITLS_CRYPTO_MCELIECE OR HITLS_CRYPTO_FRODOKEM)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_rand.c)
endif()
```

---


## Medium

### XMSS builds can drop the `CRYPT_CalcHash` implementation
`crypto/util/CMakeLists.txt:23-24`
```
if(HITLS_CRYPTO_RSA_EMSA_PSS OR HITLS_CRYPTO_RSAES_OAEP OR HITLS_CRYPTO_SLH_DSA)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_mgf.c)
endif()
```
**Issue**: `crypt_util_mgf.c` does more than MGF1: it also defines `CRYPT_CalcHash()`. XMSS uses that helper in `crypto/xmss/src/xmss_hash.c:43`, but the new condition only includes the file for RSA PSS/OAEP or SLH-DSA. In a valid `HITLS_CRYPTO_XMSS=ON` build with those three flags off, `xmss_hash.c.o` is still built while `crypt_util_mgf.c.o` is omitted, causing an undefined reference to `CRYPT_CalcHash`.
**Fix**:
```
if(HITLS_CRYPTO_RSA_EMSA_PSS OR HITLS_CRYPTO_RSAES_OAEP OR HITLS_CRYPTO_SLH_DSA OR HITLS_CRYPTO_XMSS)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_mgf.c)
endif()
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
