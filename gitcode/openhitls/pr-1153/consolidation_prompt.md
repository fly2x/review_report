# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1153
- Title: 

## Individual Review Reports

## CLAUDE Review

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


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CODEX


## High

### Secret-dependent early returns leak signing state
`crypto/mldsa/src/ml_dsa_core.c:616-630`
```
static bool ValidityChecksL(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const z[MLDSA_L_MAX], uint32_t t)
{
    bool valid = true;
    for (uint8_t i = 0; i < ctx->info->l; i++) {
        if (MLDSA_ValidityChecks(z[i], t) == false) {
            return false;
        }
    }
    return valid;
}

static bool ValidityChecksK(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const z[MLDSA_K_MAX], uint32_t t)
{
    bool valid = true;
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        if (MLDSA_ValidityChecks(z[i], t) == false) {
            return false;
        }
    }
    return valid;
}
```
**Issue**: These helpers used to scan every vector and accumulate the result. The new early-return form stops at the first failing vector. `MLDSA_SignInternal()` calls these checks on secret-dependent `z`, `r0`, and `ct0`, so the signing runtime now reveals which vector fails first in each rejection-sampling round.
**Fix**:
```
static bool ValidityChecksL(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const z[MLDSA_L_MAX], uint32_t t)
{
    bool valid = true;
    for (uint8_t i = 0; i < ctx->info->l; i++) {
        valid &= MLDSA_ValidityChecks(z[i], t);
    }
    return valid;
}

static bool ValidityChecksK(const CRYPT_ML_DSA_Ctx *ctx, int32_t *const z[MLDSA_K_MAX], uint32_t t)
{
    bool valid = true;
    for (uint8_t i = 0; i < ctx->info->k; i++) {
        valid &= MLDSA_ValidityChecks(z[i], t);
    }
    return valid;
}
```

---

### ARMv8 bound check short-circuits on first failing chunk
`crypto/mldsa/src/asm/validity_check_armv8.S:100-105`
```
UMAXV s30, mask_final.4s
    umov w3, v30.s[0]
    cbnz w3, done

    subs count, count, #1
    cbnz count, check_loop
```
**Issue**: The new ARMv8 fast path exits as soon as any 32-coefficient chunk fails. That makes the leak above much finer-grained on Armv8: signing time depends on the first failing chunk inside each vector, not just the first failing vector.
**Fix**:
```
eor tmp.16b, tmp.16b, tmp.16b

check_loop:
    load_data
    check_one_line data0, mask_final

    check_one_line data1, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data2, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data3, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data4, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data5, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data6, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b
    check_one_line data7, mask_tmp
    ORR mask_final.16b, mask_final.16b, mask_tmp.16b

    ORR tmp.16b, tmp.16b, mask_final.16b
    subs count, count, #1
    cbnz count, check_loop

    UMAXV s29, tmp.4s
    umov w3, v29.s[0]
```

---


## Low

### ABS-based check accepts INT32_MIN as in-range
`crypto/mldsa/src/asm/validity_check_armv8.S:30-37`
```
.macro check_one_line ldata, lmask
    // n = z[j] >> 31;    // Shift rightwards by 31 bits.
    // n = z[j] - (n & ((uint32_t)z[j] << 1));
    // if (n >= t) return false;
    // => n = z < 0? z - z*2 : z = ABS(z); 
    // n>=t -> hit -> return 1
    ABS \ldata\().4s, \ldata\().4s
    CMGE \lmask\().4s, \ldata\().4s, const_t.4s
.endm
```
**Issue**: The scalar reference computes the magnitude with bit-twiddling, which rejects `INT32_MIN`. This replacement uses `ABS` and then a signed `CMGE`. On AArch64, `ABS` does not make `INT32_MIN` positive, so `CMGE` sees it as negative and the bound check can return a false success for that value.
**Fix**:
```
.macro check_one_line ldata, lmask
    // n = z - ((z >> 31) & ((uint32_t)z << 1))
    SSHR tmp1.4s, \ldata\().4s, #31
    SHL  \lmask\().4s, \ldata\().4s, #1
    AND  \lmask\().16b, \lmask\().16b, tmp1.16b
    SUB  \ldata\().4s, \ldata\().4s, \lmask\().4s
    CMGE \lmask\().4s, \ldata\().4s, const_t.4s
.endm
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
