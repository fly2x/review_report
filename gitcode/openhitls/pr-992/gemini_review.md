# Code Review: openHiTLS/openhitls#992
**Reviewer**: GEMINI


## Critical

### Unhandled LmsHash failure in LmsSeedDerive leads to uninitialized key material usage
`crypto/hbs/lms/src/lms_hash.c:316`
```
int32_t LmsSeedDerive(uint8_t *seed, LMS_SeedDerive *derive, bool incrementJ)
{
    uint8_t buffer[LMS_PRG_LEN];

    (void)memcpy_s(buffer + LMS_PRG_I_OFFSET, LMS_I_LEN, derive->I, LMS_I_LEN);
    LmsPutBigendian(buffer + LMS_PRG_Q_OFFSET, derive->q, LMS_Q_LEN);
    LmsPutBigendian(buffer + LMS_PRG_J_OFFSET, derive->j, LMS_K_LEN);
    buffer[LMS_PRG_FF_OFFSET] = LMS_PRG_FF_VALUE;
    (void)memcpy_s(buffer + LMS_PRG_SEED_OFFSET, LMS_SEED_LEN, derive->masterSeed, LMS_SEED_LEN);

    LmsHash(seed, buffer, LMS_PRG_LEN);
    BSL_SAL_CleanseData(buffer, LMS_PRG_LEN);

    if (incrementJ) {
        derive->j += 1;
    }
    return CRYPT_SUCCESS;
}
```
**Issue**: In `LmsSeedDerive`, the return value of `LmsHash` is ignored, and the function unconditionally returns `CRYPT_SUCCESS`. If the underlying hash operation fails (e.g., due to a failed memory allocation or hardware error in `CRYPT_CalcHash`), the `seed` buffer remains unmodified (containing uninitialized or stale memory). Since callers in `lms_ots.c` rely on this function to generate critical cryptographic material (such as OTS private keys and signature randomizers) without checking for errors, they will proceed to use the uninitialized memory. This compromises the cryptographic integrity of the generated keys and signatures.
**Fix**:
```
int32_t LmsSeedDerive(uint8_t *seed, LMS_SeedDerive *derive, bool incrementJ)
{
    uint8_t buffer[LMS_PRG_LEN];

    (void)memcpy_s(buffer + LMS_PRG_I_OFFSET, LMS_I_LEN, derive->I, LMS_I_LEN);
    LmsPutBigendian(buffer + LMS_PRG_Q_OFFSET, derive->q, LMS_Q_LEN);
    LmsPutBigendian(buffer + LMS_PRG_J_OFFSET, derive->j, LMS_K_LEN);
    buffer[LMS_PRG_FF_OFFSET] = LMS_PRG_FF_VALUE;
    (void)memcpy_s(buffer + LMS_PRG_SEED_OFFSET, LMS_SEED_LEN, derive->masterSeed, LMS_SEED_LEN);

    int32_t ret = LmsHash(seed, buffer, LMS_PRG_LEN);
    BSL_SAL_CleanseData(buffer, LMS_PRG_LEN);
    
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    if (incrementJ) {
        derive->j += 1;
    }
    return CRYPT_SUCCESS;
}
```

---


## High

### Incorrect sigsPerTree calculation causes divide-by-zero (SIGFPE)
`crypto/hbs/hss/src/hss_utils.c:387`
```
for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
        uint32_t childHeight = para->levelPara[i + 1].height;
        sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << childHeight);
    }

    // Calculate tree and leaf indices for each level
    for (uint32_t i = 0; i < para->levels; i++) {
        // Tree index at level i = globalIndex / sigsPerTree[i]
        treeIndex[i] = globalIndex / sigsPerTree[i];
```
**Issue**: `HssCalculateTreeIndices` incorrectly calculates `sigsPerTree[i]` using `childHeight` instead of the current tree's height. For valid parameter combinations (e.g., `h0=5, h1=5, h2=25, h3=25` where true max signatures is $2^{60}$), the erroneous multiplication `sigsPerTree[i+1] * (1ULL << childHeight)` can easily exceed $2^{64}$, wrapping around to exactly 0. This results in a hardware divide-by-zero exception (`SIGFPE`) at `globalIndex / sigsPerTree[i]`, causing a denial of service. Furthermore, the calculated `treeIndex` and `leafIndex` are entirely unused by the caller `CRYPT_HSS_Sign`, as it recomputes them correctly via `HssTree_CalculateIndices`.
**Fix**:
```
for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
        uint32_t currentHeight = para->levelPara[i].height;
        sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << currentHeight);
    }

    // Calculate tree and leaf indices for each level
    for (uint32_t i = 0; i < para->levels; i++) {
        if (sigsPerTree[i] == 0) {
            return CRYPT_HSS_INVALID_PARAM;
        }
        // Tree index at level i = globalIndex / sigsPerTree[i]
        treeIndex[i] = globalIndex / sigsPerTree[i];
```

---


## Medium

### Missing memory cleanse for sensitive keys in HSSKeyPairCheck
`crypto/hbs/hss/src/hss_api.c:472`
```
uint8_t masterSeed[LMS_SEED_LEN];
    (void)memcpy_s(masterSeed, sizeof(masterSeed), prvKey->privateKey + HSS_PRVKEY_SEED_OFFSET, HSS_PRVKEY_SEED_LEN);

    uint8_t rootI[LMS_I_LEN];
    uint8_t rootSeed[LMS_SEED_LEN];
    ret = HssGenerateRootSeed(rootI, rootSeed, masterSeed);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return HSSVerifyRootHash(pubKey, prvKey, rootI, rootSeed);
```
**Issue**: `masterSeed` (extracted from the private key) and `rootSeed` are sensitive cryptographic materials used to derive all HSS subkeys. They are copied/generated on the stack in `HSSKeyPairCheck` but are not cleansed before the function returns, potentially leading to side-channel leakage or sensitive data exposure through uninitialized stack memory reuse.
**Fix**:
```
uint8_t masterSeed[LMS_SEED_LEN];
    (void)memcpy_s(masterSeed, sizeof(masterSeed), prvKey->privateKey + HSS_PRVKEY_SEED_OFFSET, HSS_PRVKEY_SEED_LEN);

    uint8_t rootI[LMS_I_LEN];
    uint8_t rootSeed[LMS_SEED_LEN];
    ret = HssGenerateRootSeed(rootI, rootSeed, masterSeed);
    
    BSL_SAL_CleanseData(masterSeed, sizeof(masterSeed));

    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_CleanseData(rootSeed, sizeof(rootSeed));
        return ret;
    }

    ret = HSSVerifyRootHash(pubKey, prvKey, rootI, rootSeed);
    BSL_SAL_CleanseData(rootSeed, sizeof(rootSeed));

    return ret;
```

---
