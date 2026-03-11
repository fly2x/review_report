# Code Review: openHiTLS/pqcp#38
**Reviewer**: CODEX


## Medium

### KEM compare callback was dropped from the provider dispatch tables
`src/provider/pqcp_pkey.c:52-84`
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

const CRYPT_EAL_Func g_pqcpKeyMgmtPolarLac[] = {
    {CRYPT_EAL_IMPLPKEYMGMT_NEWCTX, (CRYPT_EAL_ImplPkeyMgmtNewCtx)CRYPT_PQCP_PkeyMgmtNewCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_GENKEY, (CRYPT_EAL_ImplPkeyMgmtGenKey)PQCP_LAC2_Gen},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPRV, (CRYPT_EAL_ImplPkeyMgmtSetPrv)PQCP_LAC2_SetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_SETPUB, (CRYPT_EAL_ImplPkeyMgmtSetPub)PQCP_LAC2_SetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPRV, (CRYPT_EAL_ImplPkeyMgmtGetPrv)PQCP_LAC2_GetPrvKey},
    {CRYPT_EAL_IMPLPKEYMGMT_GETPUB, (CRYPT_EAL_ImplPkeyMgmtGetPub)PQCP_LAC2_GetPubKey},
    {CRYPT_EAL_IMPLPKEYMGMT_DUPCTX, (CRYPT_EAL_ImplPkeyMgmtDupCtx)PQCP_LAC2_DupCtx},
    {CRYPT_EAL_IMPLPKEYMGMT_CTRL, (CRYPT_EAL_ImplPkeyMgmtCtrl)PQCP_LAC2_Ctrl},
    {CRYPT_EAL_IMPLPKEYMGMT_FREECTX, (CRYPT_EAL_ImplPkeyMgmtFreeCtx)PQCP_LAC2_FreeCtx},
    CRYPT_EAL_FUNC_END,
};
```
**Issue**: The SCloud+ and PolarLAC key-management tables no longer register `CRYPT_EAL_IMPLPKEYMGMT_COMPARE`. Any caller that still uses `CRYPT_EAL_PkeyCmp()` now regresses from success to `NOT_SUPPORT`/failure even though the API was previously available; the new `testcode/demo/polarlac_demo.c` still calls it.
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

### SDV build ignores the saved external OpenHiTLS path
`testcode/script/build_pqcp_sdv.sh:42-45`
```
if [ -f ${PQCP_ROOT_DIR}/build/macro.txt ];then
    HITLS_ROOT_DIR=$(cat ${PQCP_ROOT_DIR}/build/base_path.txt)
else
    HITLS_ROOT_DIR=${PQCP_ROOT_DIR}/platform/openhitls
fi
```
**Issue**: `build_pqcp.sh` now writes the selected OpenHiTLS root to `build/base_path.txt`, but this script only consults that file when a nonexistent `build/macro.txt` is present. If PQCP was built with `--hitls_dir`, SDV falls back to `platform/openhitls` and then cannot find the headers/libs used for the actual provider build.
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

### Runtime library path points at a non-existent Secure_C directory
`testcode/script/execute_sdv.sh:35-36`
```
LIB_PATHS="$(realpath ${PQCP_ROOT_DIR}/build)"
LIB_PATHS="${LIB_PATHS}:$(realpath ${PQCP_ROOT_DIR}/platform/Secure_C/lib)"
```
**Issue**: The runner adds `${PQCP_ROOT_DIR}/platform/Secure_C/lib` to the loader path, but the repository layout is `platform/openhitls/platform/Secure_C/lib` (or an external root from `base_path.txt`). On a normal checkout the `realpath` call resolves nothing useful, so the SDV executables can miss `boundscheck` at runtime.
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

### Fallback compile definitions are never applied to generated SDV suites
`testcode/sdv/CMakeLists.txt:81-82`
```
if(!MACROS)
    target_link_libraries(${sdv_exe} PRIVATE SHARED_COMPILE_DEFS)
endif()
```
**Issue**: `if(!MACROS)` is not a valid logical negation in CMake and evaluates false here, so the `SHARED_COMPILE_DEFS` fallback is dead code. When `macro.txt` is absent, the support library gets the fallback defines but the generated `sdv_exe` targets do not, which makes the two parts of the test build compile with different OpenHiTLS feature sets.
**Fix**:
```
if(NOT MACROS)
    target_link_libraries(${sdv_exe} PRIVATE SHARED_COMPILE_DEFS)
endif()
```

---


## Low

### SDV build only accepts a Linux shared-object provider
`testcode/script/build_pqcp_sdv.sh:76-79`
```
if [ ! -f "${PQCP_PROVIDER_DIR}/libpqcp_provider.so" ]; then
    echo "[WARNING] PQCP provider not found: ${PQCP_PROVIDER_DIR}/libpqcp_provider.so"
    echo "[INFO] Please build PQCP first: ./build_pqcp.sh"
    exit 1
fi
```
**Issue**: The dependency check hardcodes `libpqcp_provider.so`. This rejects supported configurations introduced elsewhere in the PR, such as `./build_pqcp.sh static`, and it also fails on macOS where the provider filename is `.dylib`.
**Fix**:
```
if ! compgen -G "${PQCP_PROVIDER_DIR}/libpqcp_provider.so" >/dev/null && \
   ! compgen -G "${PQCP_PROVIDER_DIR}/libpqcp_provider.dylib" >/dev/null && \
   ! compgen -G "${PQCP_PROVIDER_DIR}/libpqcp_provider.a" >/dev/null; then
    echo "[WARNING] PQCP provider not found under ${PQCP_PROVIDER_DIR}"
    echo "[INFO] Please build PQCP first: ./build_pqcp.sh"
    exit 1
fi
```

---

### SCloud+ demo still passes the removed raw parameter ID
`testcode/demo/scloudplus_demo.c:53-71`
```
uint32_t sharekey2Len = 32;
uint8_t sharekey2[32] = {0};
int32_t val = 256;
uint8_t pubdata[37520/2];
BSL_Param pub[2] = {
    {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
    BSL_PARAM_END
};
CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
    "provider=pqcp");
...
ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
```
**Issue**: The provider now accepts `PQCP_SCLOUDPLUS_128/192/256` in `CRYPT_CTRL_SET_PARA_BY_ID`, but the demo still passes literal `256`. With the new control logic this returns `PQCP_SCLOUDPLUS_INVALID_ARG`, so the demo exits at its first parameter setup call.
**Fix**:
```
uint32_t sharekey2Len = 32;
uint8_t sharekey2[32] = {0};
int32_t val = PQCP_SCLOUDPLUS_256;
uint8_t pubdata[37520 / 2];
BSL_Param pub[2] = {
    {PQCP_PARAM_SCLOUDPLUS_PUBKEY, BSL_PARAM_TYPE_OCTETS, pubdata, sizeof(pubdata), 0},
    BSL_PARAM_END
};
CRYPT_EAL_PkeyCtx *ctx = CRYPT_EAL_ProviderPkeyNewCtx(NULL, PQCP_PKEY_SCLOUDPLUS, CRYPT_EAL_PKEY_KEM_OPERATE,
    "provider=pqcp");
...
ret = CRYPT_EAL_PkeyCtrl(ctx, CRYPT_CTRL_SET_PARA_BY_ID, &val, sizeof(val));
```

---
