# Final Code Review Report
## openHiTLS/openhitls - PR #1217

### Summary
- **Total Issues**: 7
- **Critical**: 5
- **High**: 1
- **Medium**: 1
- **Low**: 0
- **Reviewers**: claude, gemini, codex

---


## Critical

### Undefined option HITLS_CRYPTO_PKEY_KEM prevents source compilation
`crypto/eal/CMakeLists.txt:60`
**Reviewers**: CLAUDE | **置信度**: 可信
```
if(HITLS_CRYPTO_PKEY_KEM)
    list(APPEND _eal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_kem.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_KEM)` checks an option that is never defined in cmake/hitls_options.cmake or set anywhere. In CMake, undefined variables are falsy, so `eal_pkey_kem.c` will never be compiled even when KEM algorithms like MLKEM, FRODOKEM, MCELIECE, or HYBRIDKEM are enabled. This causes undefined references at link time for any code depending on symbols from this file.
**Fix**:
```
if(HITLS_CRYPTO_MLKEM OR HITLS_CRYPTO_FRODOKEM OR HITLS_CRYPTO_HPKE OR HITLS_CRYPTO_HYBRIDKEM OR HITLS_CRYPTO_MCELIECE)
    list(APPEND _eal_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/eal_pkey_kem.c)
endif()
```

---

### Undefined option HITLS_CRYPTO_PKEY_KEM prevents source compilation
`crypto/provider/CMakeLists.txt:42-44`
**Reviewers**: CLAUDE | **置信度**: 可信
```
if(HITLS_CRYPTO_PKEY_KEM)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_kem.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_KEM)` checks an option that is never defined in cmake/hitls_options.cmake. This causes `crypt_default_kem.c` to never be compiled, breaking KEM functionality for MLKEM, FRODOKEM, MCELIECE, HYBRIDKEM, and HPKE algorithms.
**Fix**:
```
if(HITLS_CRYPTO_MLKEM OR HITLS_CRYPTO_FRODOKEM OR HITLS_CRYPTO_HPKE OR HITLS_CRYPTO_HYBRIDKEM OR HITLS_CRYPTO_MCELIECE)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_kem.c)
endif()
```

---

### Undefined option HITLS_CRYPTO_PKEY_EXCH prevents source compilation
`crypto/provider/CMakeLists.txt:45-47`
**Reviewers**: CLAUDE | **置信度**: 可信
```
if(HITLS_CRYPTO_PKEY_EXCH)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_keyexch.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_EXCH)` checks an option that is never defined. This causes `crypt_default_keyexch.c` to never be compiled, breaking key exchange functionality for ECDH, SM2, SM9, X25519, and DH algorithms.
**Fix**:
```
if(HITLS_CRYPTO_ECDH OR HITLS_CRYPTO_SM2_EXCH OR HITLS_CRYPTO_SM9_EXCH OR HITLS_CRYPTO_X25519 OR HITLS_CRYPTO_DH)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_keyexch.c)
endif()
```

---

### Undefined option HITLS_CRYPTO_PKEY_CRYPT prevents source compilation
`crypto/provider/CMakeLists.txt:48-50`
**Reviewers**: CLAUDE | **置信度**: 可信
```
if(HITLS_CRYPTO_PKEY_CRYPT)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_pkeycipher.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_CRYPT)` checks an option that is never defined. This causes `crypt_default_pkeycipher.c` to never be compiled, breaking public key encryption/decryption functionality for RSA, SM2, SM9, and Paillier.
**Fix**:
```
if(HITLS_CRYPTO_RSA_ENCRYPT OR HITLS_CRYPTO_RSA_DECRYPT OR HITLS_CRYPTO_SM2_CRYPT OR HITLS_CRYPTO_SM9_CRYPT OR HITLS_CRYPTO_PAILLIER)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_pkeycipher.c)
endif()
```

---

### Undefined option HITLS_CRYPTO_PKEY_SIGN prevents source compilation
`crypto/provider/CMakeLists.txt:51-53`
**Reviewers**: CLAUDE | **置信度**: 可信
```
if(HITLS_CRYPTO_PKEY_SIGN)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_sign.c)
endif()
```
**Issue**: The condition `if(HITLS_CRYPTO_PKEY_SIGN)` checks an option that is never defined. This causes `crypt_default_sign.c` to never be compiled, breaking signature functionality for RSA, DSA, ECDSA, Ed25519, SM2, SM9, XMSS, and MLDSA.
**Fix**:
```
if(HITLS_CRYPTO_RSA_SIGN OR HITLS_CRYPTO_RSA_VERIFY OR HITLS_CRYPTO_DSA OR HITLS_CRYPTO_ECDSA OR HITLS_CRYPTO_ED25519 OR HITLS_CRYPTO_SM2_SIGN OR HITLS_CRYPTO_SM9_SIGN OR HITLS_CRYPTO_XMSS OR HITLS_CRYPTO_MLDSA)
    list(APPEND _default_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/default/crypt_default_sign.c)
endif()
```

---


## High

### PQC-only builds can drop the CRYPT_RandEx implementation
`crypto/util/CMakeLists.txt:26-27`
**Reviewers**: CODEX | **置信度**: 可信
```
if(HITLS_CRYPTO_DRBG OR HITLS_CRYPTO_CURVE25519 OR HITLS_CRYPTO_RSA OR HITLS_CRYPTO_BN_RAND OR HITLS_CRYPTO_SM9)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_rand.c)
endif()
```
**Issue**: The gate only pulls in `crypt_util_rand.c` for `DRBG`, `CURVE25519`, `RSA`, `BN_RAND`, or `SM9`. However, PQC algorithms also depend on this file: MLKEM (ml_kem.c:694,696,732), MLDSA (ml_dsa.c:417,840), XMSS (xmss_core.c:59,65,71), MCELIECE (mceliece.c:191), and FRODOKEM (frodokem.c:43). A PQC-only build (e.g., `HITLS_CRYPTO_MLKEM=ON` with others disabled) will generate object files that call `CRYPT_RandEx()` or `CRYPT_Rand()` without compiling the implementation, causing link failures.
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

### XMSS builds can drop the CRYPT_CalcHash implementation
`crypto/util/CMakeLists.txt:23-24`
**Reviewers**: CODEX | **置信度**: 可信
```
if(HITLS_CRYPTO_RSA_EMSA_PSS OR HITLS_CRYPTO_RSAES_OAEP OR HITLS_CRYPTO_SLH_DSA)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_mgf.c)
endif()
```
**Issue**: The file `crypt_util_mgf.c` provides both MGF1 padding and `CRYPT_CalcHash()`. XMSS uses `CRYPT_CalcHash()` in `crypto/xmss/src/xmss_hash.c:43`, but the condition only includes the file for RSA PSS/OAEP or SLH-DSA. A build with `HITLS_CRYPTO_XMSS=ON` and those three flags off will build `xmss_hash.c.o` without `crypt_util_mgf.c.o`, causing an undefined reference to `CRYPT_CalcHash`.
**Fix**:
```
if(HITLS_CRYPTO_RSA_EMSA_PSS OR HITLS_CRYPTO_RSAES_OAEP OR HITLS_CRYPTO_SLH_DSA OR HITLS_CRYPTO_XMSS)
    list(APPEND _util_sources ${CMAKE_CURRENT_SOURCE_DIR}/crypt_util_mgf.c)
endif()
```

---
