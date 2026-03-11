# Final Code Review Report
## openHiTLS/pqcp - PR #38

### Summary
- **Total Issues**: 12
- **Critical**: 0
- **High**: 2
- **Medium**: 6
- **Low**: 4
- **Reviewers**: claude, gemini, codex

---


## High

### KEM compare callback dropped from provider dispatch tables
`src/provider/pqcp_pkey.c:52-84`
**Reviewers**: CODEX | **置信度**: 可信
```
const CRYPT_EAL_Func g_pqcpKeyMgmtScloudPlus[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_SCLOUDPLUS_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_SCLOUDPLUS_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_SCLOUDPLUS_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_SCLOUDPLUS_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_SCLOUDPLUS_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_SCLOUDPLUS_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)PQCP_SCLOUDPLUS_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)PQCP_SCLOUDPLUS_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
```
**Issue**: The SCloud+ and PolarLAC key-management tables no longer register CRYPT_EAL_IMPLPKEYMGMT_COMPARE. The testcode/demo/polarlac_demo.c still calls CRYPT_EAL_PkeyCmp() on lines 154 and 161, which will now fail with NOT_SUPPORT error even though the API was previously available.
**Fix**:
```
const CRYPT_EAL_Func g_pqcpKeyMgmtScloudPlus[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_SCLOUDPLUS_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_SCLOUDPLUS_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_SCLOUDPLUS_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_SCLOUDPLUS_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_SCLOUDPLUS_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_SCLOUDPLUS_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)PQCP_SCLOUDPLUS_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)PQCP_SCLOUDPLUS_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)PQCP_SCLOUDPLUS_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

const CRYPT_EAL_Func g_pqcpKeyMgmtPolarLac[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_LAC2_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_LAC2_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_LAC2_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_LAC2_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_LAC2_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_LAC2_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_COMPARE, (CRYPT_EAL_ImplPkeyMgmtCompare)PQCP_LAC2_Cmp},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)PQCP_LAC2_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)PQCP_LAC2_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
```

---

### SCloud+ demo passes invalid parameter ID to CRYPT_CTRL_SET_PARA_BY_ID
`testcode/demo/scloudplus_demo.c:53`
**Reviewers**: CODEX | **置信度**: 可信
```
int32_t val = 256;
ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
```
**Issue**: The demo passes raw integer 256 to CRYPT_CTRL_SET_PARA_BY_ID, but the Ctrl function in scloudplus.c only accepts PQCP_SCLOUDPLUS_128/192/256 (defined as 6000/6001/6002). Passing 256 triggers the else case returning PQCP_SCLOUDPLUS_INVALID_ARG.
**Fix**:
```
int32_t val = PQCP_SCLOUDPLUS_256;
ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
```

---


## Medium

### Incorrect enum name CRYPT_ERROR instead of PQCP_ERROR
`include/pqcp_err.h:46`
**Reviewers**: CLAUDE | **置信度**: 可信
```
PQCP_COMPOSITE_LEN_NOT_ENOUGH
} CRYPT_ERROR;
```
**Issue**: The enum is named CRYPT_ERROR but should be PQCP_ERROR to match the header file name (pqcp_err.h) and the PQCP_ prefix used by all error codes in the enum. This appears to be a copy-paste error from crypt_errno.h.
**Fix**:
```
PQCP_COMPOSITE_LEN_NOT_ENOUGH
} PQCP_ERROR;
```

---

### SDV build ignores saved external OpenHiTLS path
`testcode/script/build_pqcp_sdv.sh:42-45`
**Reviewers**: CODEX | **置信度**: 可信
```
if [ -f ${PQCP_ROOT_DIR}/build/macro.txt ];then
    HITLS_ROOT_DIR=$(cat ${PQCP_ROOT_DIR}/build/base_path.txt)
else
    HITLS_ROOT_DIR=${PQCP_ROOT_DIR}/platform/openhitls
fi
```
**Issue**: The script checks for build/macro.txt before reading build/base_path.txt. If PQCP was built with --hitls_dir but macro.txt is missing, SDV falls back to platform/openhitls instead of using the saved HiTLS path from base_path.txt.
**Fix**:
```
if [ -f "${PQCP_ROOT_DIR}/build/base_path.txt" ]; then
    HITLS_ROOT_DIR="$(cat "${PQCP_ROOT_DIR}/build/base_path.txt")"
else
    HITLS_ROOT_DIR="${PQCP_ROOT_DIR}/platform/openhitls"
fi
export HITLS_ROOT_DIR
```

---

### Runtime library path points to non-existent Secure_C directory
`testcode/script/execute_sdv.sh:35-36`
**Reviewers**: CODEX | **置信度**: 可信
```
LIB_PATHS="$(realpath ${PQCP_ROOT_DIR}/build)"
LIB_PATHS="${LIB_PATHS}:$(realpath ${PQCP_ROOT_DIR}/platform/Secure_C/lib)"
```
**Issue**: The script adds PQCP_ROOT_DIR/platform/Secure_C/lib to LD_LIBRARY_PATH, but the actual path is PQCP_ROOT_DIR/platform/openhitls/platform/Secure_C/lib (or under an external HiTLS root from base_path.txt). The realpath will fail or resolve nothing useful.
**Fix**:
```
if [ -f "${PQCP_ROOT_DIR}/build/base_path.txt" ]; then
    HITLS_ROOT_DIR="$(cat "${PQCP_ROOT_DIR}/build/base_path.txt")"
else
    HITLS_ROOT_DIR="${PQCP_ROOT_DIR}/platform/openhitls"
fi

LIB_PATHS="$(realpath "${PQCP_ROOT_DIR}/build")"
LIB_PATHS="${LIB_PATHS}:$(realpath "${HITLS_ROOT_DIR}/platform/Secure_C/lib")"
```

---

### Invalid CMake logical negation causes dead fallback code
`testcode/sdv/CMakeLists.txt:81-82`
**Reviewers**: CODEX | **置信度**: 可信
```
if(!MACROS)
    target_link_libraries(${sdv_exe} PRIVATE SHARED_COMPILE_DEFS)
endif()
```
**Issue**: The condition uses if(!MACROS) which is not valid CMake syntax. This evaluates to false, so the SHARED_COMPILE_DEFS fallback is never applied to generated test executables when macro.txt is absent.
**Fix**:
```
if(NOT MACROS)
    target_link_libraries(${sdv_exe} PRIVATE SHARED_COMPILE_DEFS)
endif()
```

---

### Bash 4.0+ specific syntax reduces portability
`build_pqcp.sh:40`
**Reviewers**: CLAUDE | **置信度**: 可信
```
algo_to_macro()
{
    local algo="$1"
    echo "PQCP_${algo^^}"
}
```
**Issue**: The ${algo^^} uppercase conversion syntax requires Bash 4.0+. This will fail on macOS (default bash 3.2) and older systems. The shebang specifies bash but does not enforce version 4+.
**Fix**:
```
algo_to_macro()
{
    local algo="$1"
    local upper=$(echo "$algo" | tr '[:lower:]' '[:upper:]')
    echo "PQCP_${upper}"
}
```

---

### Shallow copy of para pointer in DupCtx without documentation
`src/scloudplus/src/scloudplus.c:391-392`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
if (src->para != NULL) {
    ctx->para = src->para;
}
```
**Issue**: DupCtx assigns ctx->para = src->para directly without allocation. Both contexts share the same pointer to static PRESET_PARAS. While currently safe (para always points to static data), this could become a use-after-free bug if para is ever changed to point to dynamically allocated memory.
**Fix**:
```
if (src->para != NULL) {
    /* Safe: para always points to static PRESET_PARAS array */
    ctx->para = src->para;
}
```

---


## Low

### Dead code after RETURN_RET_IF macro
`src/polarlac/src/polarlac_rand.c:133-136`
**Reviewers**: CLAUDE | **置信度**: 可信
```
RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, r, 64), ret);
if (ret != PQCP_SUCCESS) {
    return ret;
}
```
**Issue**: The error check after RETURN_RET_IF is unreachable. RETURN_RET_IF returns immediately on failure, so the subsequent if (ret != PQCP_SUCCESS) block can never execute with a failure condition.
**Fix**:
```
RETURN_RET_IF(CRYPT_EAL_MdSqueeze(mdCtx, r, 64), ret);
```

---

### Inconsistent return value using literal 0 instead of PQCP_SUCCESS
`src/polarlac/src/polarlac_rand.c:233`
**Reviewers**: CLAUDE | **置信度**: 可信
```
return 0;
```
**Issue**: The function returns literal 0 instead of using the PQCP_SUCCESS macro. While PQCP_SUCCESS is defined as 0, this is inconsistent with the rest of the codebase and reduces code readability.
**Fix**:
```
return PQCP_SUCCESS;
```

---

### SDV build only accepts Linux shared-object provider
`testcode/script/build_pqcp_sdv.sh:76-79`
**Reviewers**: CODEX | **置信度**: 可信
```
if [ ! -f "${PQCP_PROVIDER_DIR}/libpqcp_provider.so" ]; then
    echo "[WARNING] PQCP provider not found: ${PQCP_PROVIDER_DIR}/libpqcp_provider.so"
    echo "[INFO] Please build PQCP first: ./build_pqcp.sh"
    exit 1
fi
```
**Issue**: The dependency check hardcodes libpqcp_provider.so, rejecting supported configurations like static builds or macOS builds. The script will exit incorrectly when the provider library exists but with a different extension.
**Fix**:
```
# Check for any supported PQCP provider library
PROVIDER_FOUND=0
for ext in .so .dylib .a; do
    if [ -f "${PQCP_PROVIDER_DIR}/libpqcp_provider${ext}" ]; then
        PROVIDER_FOUND=1
        break
    fi
done
if [ ${PROVIDER_FOUND} -eq 0 ]; then
    echo "[WARNING] PQCP provider not found under ${PQCP_PROVIDER_DIR}"
    echo "[INFO] Please build PQCP first: ./build_pqcp.sh"
    exit 1
fi
```

---

### Unused parameters in PQCP_ProviderCtrl
`src/provider/pqcp_provider.c:91-96`
**Reviewers**: CLAUDE | **置信度**: 需评估
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
**Issue**: The function explicitly casts all parameters to void to silence unused warnings, but still accepts these parameters in its signature. This suggests either incomplete implementation or unnecessary parameters.
**Fix**:
```
/* Provider control operations not yet implemented */
static int32_t PQCP_ProviderCtrl(void *provCtx, int32_t cmd, void *val, uint32_t valLen)
{
    (void) provCtx;
    (void) cmd;
    (void) val;
    (void) valLen;
    return PQCP_SUCCESS;
}
```

---
