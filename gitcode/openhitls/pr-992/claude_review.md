# Code Review: openhitls/openhitls#992
**Reviewer**: CLAUDE


## Critical

### Missing error codes CRYPT_LMS_PAIRWISE_CHECK_FAIL and CRYPT_HSS_PAIRWISE_CHECK_FAIL
`include/crypto/crypt_errno.h:672-687`
```
CRYPT_HSS_SIGN_FAIL,                         /**< HSS signature generation failed. */
    CRYPT_HSS_KEYGEN_FAIL,                       /**< HSS key generation failed. */
};
```
**Issue**: The code in lms_api.c (lines 510, 515, 529) and hss_api.c (lines 439, 445, 455, 471) uses CRYPT_LMS_PAIRWISE_CHECK_FAIL and CRYPT_HSS_PAIRWISE_CHECK_FAIL error codes, but these are not defined in crypt_errno.h. This will cause compilation errors.
**Fix**:
```
CRYPT_HSS_SIGN_FAIL,                         /**< HSS signature generation failed. */
    CRYPT_HSS_KEYGEN_FAIL,                       /**< HSS key generation failed. */
    CRYPT_LMS_PAIRWISE_CHECK_FAIL,               /**< LMS key pair check failed. */
    CRYPT_HSS_PAIRWISE_CHECK_FAIL,               /**< HSS key pair check failed. */
};
```

---


## Medium

### libCtx field not copied in CRYPT_LMS_DupCtx
`crypto/lms/src/lms_api.c:118-120`
```
ctx->signatureIndex = srcCtx->signatureIndex;

    return ctx;
}
```
**Issue**: The CRYPT_LMS_DupCtx function does not copy the libCtx field from the source context. The duplicated context will always have libCtx = NULL, even if the source context had a valid library context pointer. This can cause issues when the duplicated context is used with provider APIs that rely on libCtx.
**Fix**:
```
ctx->signatureIndex = srcCtx->signatureIndex;
    ctx->libCtx = srcCtx->libCtx;

    return ctx;
}
```

---

### libCtx field not copied in CRYPT_HSS_DupCtx
`crypto/lms/src/hss_api.c:121-123`
```
// Copy state
    newCtx->signatureIndex = srcCtx->signatureIndex;

    return newCtx;
}
```
**Issue**: The CRYPT_HSS_DupCtx function does not copy the libCtx field from the source context. The duplicated context will always have libCtx = NULL, even if the source context had a valid library context pointer. This can cause issues when the duplicated context is used with provider APIs that rely on libCtx.
**Fix**:
```
// Copy state
    newCtx->signatureIndex = srcCtx->signatureIndex;
    newCtx->libCtx = srcCtx->libCtx;

    return newCtx;
}
```

---


## Low

### Context structure not zeroized before free in CRYPT_HSS_FreeCtx
`crypto/lms/src/hss_api.c:91-92`
```
if (ctx->para != NULL) {
        LmsZeroize(ctx->para, sizeof(HSS_Para));
        BSL_SAL_Free(ctx->para);
    }

    BSL_SAL_Free(ctx);
}
```
**Issue**: Unlike CRYPT_LMS_FreeCtx which zeroizes the ctx structure before freeing, CRYPT_HSS_FreeCtx does not zeroize the ctx structure. The ctx structure contains signatureIndex which may be considered sensitive state information. For consistency with LMS and proper secure cleanup, ctx should be zeroized.
**Fix**:
```
if (ctx->para != NULL) {
        LmsZeroize(ctx->para, sizeof(HSS_Para));
        BSL_SAL_Free(ctx->para);
    }

    LmsZeroize(ctx, sizeof(CRYPT_HSS_Ctx));
    BSL_SAL_Free(ctx);
}
```

---

### Magic numbers used for control commands instead of defined constants
`crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_lms.c:45-48`
```
uint32_t lmsType = 5;  // LMS_SHA256_M32_H5
    uint32_t otsType = 4;  // LMOTS_SHA256_N32_W8
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, 1, &lmsType, sizeof(lmsType)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, 2, &otsType, sizeof(otsType)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
```
**Issue**: The selftest code uses magic numbers 1 and 2 for CRYPT_EAL_PkeyCtrl calls instead of the defined symbolic constants CRYPT_CTRL_LMS_SET_TYPE and CRYPT_CTRL_LMS_SET_OTS_TYPE. This makes the code harder to maintain and could break if the control command values change.
**Fix**:
```
uint32_t lmsType = LMS_SHA256_M32_H5;
    uint32_t otsType = LMOTS_SHA256_N32_W8;
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_LMS_SET_TYPE, &lmsType, sizeof(lmsType)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_LMS_SET_OTS_TYPE, &otsType, sizeof(otsType)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
```

---

### Magic numbers used for control commands instead of defined constants
`crypto/provider/src/cmvp/cmvp_utils/cmvp_selftest_hss.c:48-58`
```
GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, 1, &levels, sizeof(levels)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, 2, lmsParams, sizeof(lmsParams)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, 3, otsParams, sizeof(otsParams)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
```
**Issue**: The selftest code uses magic numbers 1, 2, and 3 for CRYPT_EAL_PkeyCtrl calls instead of the defined symbolic constants CRYPT_CTRL_HSS_SET_LEVELS, CRYPT_CTRL_HSS_SET_LMS_TYPE, and CRYPT_CTRL_HSS_SET_OTS_TYPE. This makes the code harder to maintain and could break if the control command values change.
**Fix**:
```
GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_HSS_SET_LEVELS, &levels, sizeof(levels)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_HSS_SET_LMS_TYPE, lmsParams, sizeof(lmsParams)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_ERR_IF_TRUE(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_HSS_SET_OTS_TYPE, otsParams, sizeof(otsParams)) != CRYPT_SUCCESS,
        CRYPT_CMVP_ERR_ALGO_SELFTEST);
```

---
