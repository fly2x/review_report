# Code Review: openHiTLS/pqcp#38
**Reviewer**: CLAUDE


## Medium

### Incorrect enum name in pqcp_err.h
`include/pqcp_err.h:46`
```
} CRYPT_ERROR;
```
**Issue**: The enum is named `CRYPT_ERROR` but should be `PQCP_ERROR` to match the header file name and error code prefixes. This appears to be a copy-paste error from the original crypt_errno.h.
**Fix**:
```
} PQCP_ERROR;
```

---

### Bash 4.0+ specific syntax reduces portability
`build_pqcp.sh:40`
```
algo_to_macro()
{
    local algo="$1"
    echo "PQCP_${algo^^}"
}
```
**Issue**: The `${algo^^}` syntax for uppercase conversion is specific to Bash 4.0+. This script may fail on systems with older bash versions (e.g., macOS default bash 3.2). The script doesn't have a shebang to enforce bash 4+.
**Fix**:
```
#!/usr/bin/env bash
# Add at top of file, or use portable alternative:
algo_to_macro()
{
    local algo="$1"
    local upper=$(echo "$algo" | tr '[:lower:]' '[:upper:]')
    echo "PQCP_${upper}"
}
```

---

### Shallow copy of para pointer in PQCP_SCLOUDPLUS_DupCtx
`src/scloudplus/src/scloudplus.c:389-393`
```
if (src->para != NULL) {
        ctx->para = src->para;
    }
```
**Issue**: The DupCtx function assigns `ctx->para = src->para` instead of allocating a new copy. This means both contexts share the same parameter structure pointer. If src->para points to a stack-allocated PRESET_PARAS entry (which it does), this is safe. However, if para could ever be dynamically allocated in the future, this would be a use-after-free bug.
**Fix**:
```
if (src->para != NULL) {
        ctx->para = src->para;  // Safe because para always points to static PRESET_PARAS
        // Add comment to clarify this is intentional
    }
```

---


## Low

### Inconsistent return value in SampleSparseTernaryVector256
`src/polarlac/src/polarlac_rand.c:233`
```
return 0;
}
```
**Issue**: The function returns `0` directly instead of using the `PQCP_SUCCESS` macro. While PQCP_SUCCESS is defined as 0, this is inconsistent with the rest of the codebase and reduces code readability.
**Fix**:
```
return PQCP_SUCCESS;
}
```

---

### Dead code after RETURN_RET_IF macro
`src/polarlac/src/polarlac_rand.c:133-136`
```
RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, r, 64), ret);
    if (ret != PQCP_SUCCESS) {
        return ret;
    }
```
**Issue**: The error checks after `RETURN_RET_IF` are unreachable. The RETURN_RET_IF macro returns immediately if the function fails, so the subsequent `if (ret != PQCP_SUCCESS)` checks can never execute with a failure condition.
**Fix**:
```
RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, r, 64), ret);
```

---

### Dead code after RETURN_RET_IF in SampleSparseTernaryVector256
`src/polarlac/src/polarlac_rand.c:193`
```
RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, r, SHAKE256_RATE * 2), ret);
    t = 0;
```
**Issue**: Similar to SampleSparseTernaryVector128, there's a RETURN_RET_IF followed by code, but in this case the error check was removed. However, the variable `t` is used immediately after which is correct - just noting this pattern differs from the function above it.

---

### Unused parameters in PQCP_ProviderCtrl
`src/provider/pqcp_provider.c:90-93`
```
static int32_t PQCP_ProviderCtrl(void *provCtx, int32_t cmd, void *val, uint32_t valLen)
{
    (void) provCtx;
    (void) cmd;
    (void) val;
    (void) valLen;
    /* Add provider control operations if needed */
    return PQCP_SUCCESS;
}
```
**Issue**: The function explicitly casts parameters to void to silence unused warnings, but the function accepts these parameters without using them. This suggests either incomplete implementation or unnecessary parameters.

---

### Use of GLOB_RECURSE for source files
`CMakeLists.txt:54-59`
```
file(GLOB_RECURSE PROVIDER_SOURCES
    src/provider/*.c
    src/scloudplus/src/*.c
    src/polarlac/src/*.c
    src/composite_sign/src/*.c
)
```
**Issue**: Using `file(GLOB_RECURSE ...)` automatically picks up all source files. If a new source file is added, it's automatically included. However, this behavior is not recommended by CMake documentation as it doesn't detect changes to the filesystem when re-running cmake.

---
