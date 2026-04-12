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
