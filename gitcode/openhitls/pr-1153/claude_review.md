# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CLAUDE


## High

### Missing ARMv8 architecture check before including assembly files
`crypto/mldsa/CMakeLists.txt:15-28`
```
if(HITLS_CRYPTO_MLDSA_ARMV8)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/decompose_armv8.S)
    ...
```
**Issue**: The CMakeLists.txt includes ARMv8 assembly files when HITLS_CRYPTO_MLDSA_ARMV8 is ON, but doesn't verify the build architecture is actually ARMv8. Building with HITLS_CRYPTO_MLDSA_ARMV8=ON on x86_64 will fail to compile or produce incorrect results. The check should also verify HITLS_ASM_ARMV8 is enabled.
**Fix**:
```
if(HITLS_CRYPTO_MLDSA_ARMV8 AND HITLS_ASM_ARMV8)
    list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/decompose_armv8.S)
    ...
```

---

### Missing HITLS_CRYPTO_MLDSA_ARMV8 dependency definition
`cmake/hitls_define_dependencies.cmake:420-424`
```
hitls_define_dependency(HITLS_CRYPTO_MLDSA
    DEPS HITLS_CRYPTO_PKEY
        HITLS_CRYPTO_PKEY_SIGN HITLS_CRYPTO_SHA3 HITLS_BSL_PARAMS HITLS_BSL_OBJ_DEFAULT
    CHILDREN HITLS_CRYPTO_MLDSA_CHECK
)
```
**Issue**: HITLS_CRYPTO_MLDSA_ARMV8 is not defined in hitls_define_dependencies.cmake, unlike all other *_ARMV8 features. This means there's no automatic validation that HITLS_ASM_ARMV8 is enabled when HITLS_CRYPTO_MLDSA_ARMV8 is ON. Other ARMV8 features (like HITLS_CRYPTO_BN_ARMV8, HITLS_CRYPTO_AES_ARMV8) have proper dependency definitions.
**Fix**:
```
hitls_define_dependency(HITLS_CRYPTO_MLDSA
    DEPS HITLS_CRYPTO_PKEY
        HITLS_CRYPTO_PKEY_SIGN HITLS_CRYPTO_SHA3 HITLS_BSL_PARAMS HITLS_BSL_OBJ_DEFAULT
    CHILDREN HITLS_CRYPTO_MLDSA_CHECK HITLS_CRYPTO_MLDSA_ARMV8
)
hitls_define_dependency(HITLS_CRYPTO_MLDSA_ARMV8 DEPS HITLS_CRYPTO_MLDSA)
```

---

### HITLS_CRYPTO_MLDSA_ARMV8 bypasses ASM architecture validation
`cmake/hitls_config_check.cmake:113-117`
```
if(_var MATCHES "^HITLS_CRYPTO_.*_ARMV8$")
    if(NOT HITLS_ASM_ARMV8)
```
**Issue**: The config check validates that all other *_ARMV8 features require HITLS_ASM_ARMV8, but HITLS_CRYPTO_MLDSA_ARMV8 is not included in this check because it's not in the dependency system. The pattern matching regex "^HITLS_CRYPTO_.*_ARMV8$" should match MLDSA_ARMV8 but the feature isn't properly registered.

---


## Low

### Header file incorrectly added as source file
`crypto/mldsa/CMakeLists.txt:28`
```
list(APPEND _mldsa_sources ${CMAKE_CURRENT_SOURCE_DIR}/src/asm/export_ml_dsa_armv8.h)
```
**Issue**: Header file export_ml_dsa_armv8.h is added to _mldsa_sources. Header files should not be listed as sources in CMake.
**Fix**:
```
# Remove this line - header files should not be in source lists
```

---
