# Code Review: openHiTLS/openhitls#1114
**Reviewer**: CODEX


## Medium

### AArch64 PAC return-address signing macro removed from default defines
`config/json/compile.json:33-39`
```
"CC_DEFINE_FLAGS": [
    "-DHITLS_CRYPTO_EAL_REPORT",
    "-DHITLS_CRYPTO_NIST_ECC_ACCELERATE",
    "-DHITLS_CRYPTO_BN_COMBA",
    "-DHITLS_CRYPTO_AES_PRECALC_TABLES",
    "-DHITLS_CRYPTO_SM2_PRECOMPUTE_512K_TBL"
]
```
**Issue**: The default compile defines no longer include `-DHITLS_AARCH64_PACIASP`, so `AARCH64_PACIASP/AARCH64_AUTIASP` expand to no-ops in assembly (`crypt_arm.h`). This removes return-address signing hardening for AArch64 assembly crypto code.
**Fix**:
```
"CC_DEFINE_FLAGS": [
    "-DHITLS_CRYPTO_EAL_REPORT",
    "-DHITLS_CRYPTO_NIST_ECC_ACCELERATE",
    "-DHITLS_CRYPTO_BN_COMBA",
    "-DHITLS_CRYPTO_AES_PRECALC_TABLES",
    "-DHITLS_AARCH64_PACIASP",
    "-DHITLS_CRYPTO_SM2_PRECOMPUTE_512K_TBL"
]
```

---

### x2 SHAKE path is endianness-incorrect on big-endian AArch64
`crypto/sha3/src/aarch64_sha3.c:216-218`
```
uint64x1_t v0 = vreinterpret_u64_u8(vld1_u8(in0 + i * 8));
uint64x1_t v1 = vreinterpret_u64_u8(vld1_u8(in1 + i * 8));
state[i] = veorq_u64(state[i], vcombine_u64(v0, v1));

...

vst1_u8(out0 + i * 8, vreinterpret_u8_u64(vget_low_u64(s[i])));
vst1_u8(out1 + i * 8, vreinterpret_u8_u64(vget_high_u64(s[i])));
```
**Issue**: The new NEON x2 SHAKE absorb/squeeze path loads/stores 64-bit lanes as raw bytes without LE conversion. Existing SHA3 ARMv8 assembly handles `HITLS_BIG_ENDIAN`, but this new C path does not, producing wrong SHAKE output on big-endian targets.
**Fix**:
```
#ifdef HITLS_BIG_ENDIAN
uint64_t lane0 = GET_UINT64_LE(in0, i * 8);
uint64_t lane1 = GET_UINT64_LE(in1, i * 8);
state[i] = veorq_u64(state[i], vcombine_u64(vcreate_u64(lane0), vcreate_u64(lane1)));
#else
uint64x1_t v0 = vreinterpret_u64_u8(vld1_u8(in0 + i * 8));
uint64x1_t v1 = vreinterpret_u64_u8(vld1_u8(in1 + i * 8));
state[i] = veorq_u64(state[i], vcombine_u64(v0, v1));
#endif

...

#ifdef HITLS_BIG_ENDIAN
PUT_UINT64_LE(vgetq_lane_u64(s[i], 0), out0, i * 8);
PUT_UINT64_LE(vgetq_lane_u64(s[i], 1), out1, i * 8);
#else
vst1_u8(out0 + i * 8, vreinterpret_u8_u64(vget_low_u64(s[i])));
vst1_u8(out1 + i * 8, vreinterpret_u8_u64(vget_high_u64(s[i])));
#endif
```

---

### ML-KEM switched from provider-aware hash dispatch to hardwired local SHA3/SHAKE
`crypto/mlkem/src/ml_kem_pke.c:346`
```
CRYPT_SHA3_512(digest, seed, MLKEM_SEED_LEN + 1);

...

CRYPT_SHAKE256(bufEncE, MLKEM_PRF_BLOCKSIZE * ctx->info->eta2, r, MLKEM_SEED_LEN + 1);
```
**Issue**: Keygen/encrypt now call direct one-shot SHA3/SHAKE functions, bypassing `ctx->libCtx` provider dispatch and its error path. This breaks consistency with provider-based operation used elsewhere in the file and can violate provider/FIPS routing expectations.
**Fix**:
```
ret = HashFuncG(ctx->libCtx, seed, MLKEM_SEED_LEN + 1, digest, CRYPT_SHA3_512_DIGESTSIZE);
RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

...

ret = HashFuncJ(ctx->libCtx, r, MLKEM_SEED_LEN + 1, bufEncE, MLKEM_PRF_BLOCKSIZE * ctx->info->eta2);
GOTO_ERR_IF_EX(ret, ret);
```

---

### Noise PRF path ignores `libCtx` and cannot report SHAKE provider errors
`crypto/mlkem/src/ml_kem_poly.c:266-273`
```
CRYPT_SHAKE256(prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX, q, MLKEM_SEED_LEN + 1);
...
CRYPT_SHAKE256(prfOut, MLKEM_PRF_BLOCKSIZE * MLKEM_ETA2_MAX, q, MLKEM_SEED_LEN + 1);
```
**Issue**: `SampleEta1/2` now use direct `CRYPT_SHAKE256` one-shot calls and always return success, bypassing provider dispatch (`ctx->libCtx`) and removing error propagation previously provided by EAL MD calls.
**Fix**:
```
uint32_t outLen = MLKEM_PRF_BLOCKSIZE * MLKEM_ETA1_MAX;
int32_t ret = EAL_Md(CRYPT_MD_SHAKE256, ctx->libCtx, NULL, q, MLKEM_SEED_LEN + 1,
    prfOut, &outLen, false, ctx->libCtx != NULL);
RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);

/* Apply the same pattern for eta2 output length */
outLen = MLKEM_PRF_BLOCKSIZE * MLKEM_ETA2_MAX;
ret = EAL_Md(CRYPT_MD_SHAKE256, ctx->libCtx, NULL, q, MLKEM_SEED_LEN + 1,
    prfOut, &outLen, false, ctx->libCtx != NULL);
RETURN_RET_IF(ret != CRYPT_SUCCESS, ret);
```

---


## Low

### Sensitive buffer cleanse length not updated after buffer size increase
`crypto/mlkem/src/ml_kem_pke.c:551`
```
uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE + 1];    // K and r
...
BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
...
BSL_SAL_CleanseData(kr, CRYPT_SHA3_512_DIGESTSIZE);
```
**Issue**: `kr` was expanded from 64 to 65 bytes, but cleansing still wipes only 64 bytes. One byte remains uncleansed on stack.
**Fix**:
```
uint8_t kr[CRYPT_SHA3_512_DIGESTSIZE + 1];    // K and r
...
BSL_SAL_CleanseData(kr, sizeof(kr));
...
BSL_SAL_CleanseData(kr, sizeof(kr));
```

---
