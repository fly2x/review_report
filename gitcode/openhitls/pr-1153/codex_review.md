# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CODEX


## High

### ML-DSA source split still leaves the deleted NTT file in the always-built public list
`config/json/feature.json:1417-1427`
```
".srcs": {
    "public": [
        "crypto/mldsa/src/ml_dsa_core.c",
        "crypto/mldsa/src/ml_dsa_ntt.c",
        "crypto/mldsa/src/ml_dsa.c"
    ],
    "no_asm": "crypto/mldsa/src/noasm/*.c",
    "armv8": [
        "crypto/mldsa/src/asm/*armv8.S",
        "crypto/mldsa/src/asm/*armv8.c",
        "crypto/mldsa/src/asm/*table.c"
    ]
}
```
**Issue**: The new `no_asm`/`armv8` split moved `ml_dsa_ntt.c` into `crypto/mldsa/src/noasm/`, but the `public` list still points at the old deleted path. The local source resolver always includes `.srcs.public` before the variant-specific list, so any build with `mldsa` enabled expands a missing source file.
**Fix**:
```
".srcs": {
    "public": [
        "crypto/mldsa/src/ml_dsa_core.c",
        "crypto/mldsa/src/ml_dsa.c"
    ],
    "no_asm": "crypto/mldsa/src/noasm/*.c",
    "armv8": [
        "crypto/mldsa/src/asm/*armv8.S",
        "crypto/mldsa/src/asm/*armv8.c",
        "crypto/mldsa/src/asm/*table.c"
    ]
}
```

---


## Medium

### ARMv8 rejection sampler byte-swaps the raw SHAKE stream before parsing it
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:99-104`
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
for (uint32_t i = 0; i < buflen; i++) {
    buf[i] = CRYPT_HTOLE32(buf[i]);
}
uint32_t gensize = 0;
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
```
**Issue**: `MldRejUniformAsm` consumes the SHAKE output as a byte stream, but this wrapper rewrites every `uint32_t` with `CRYPT_HTOLE32` before casting the buffer back to `uint8_t *`. On big-endian AArch64 that permutes the bytes inside each 32-bit word, so the armv8 path expands a different matrix than the scalar implementation.
**Fix**:
```
GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);

uint32_t gensize = 0;
gensize = MldRejUniformAsm(a, (const uint8_t *)buf, outlen, MLD_REJ_UNIFORM_TABLE);
```

---


## Low

### Scalar fallback for `MLDSA_RejNTTPoly` restarts from an already-consumed buffer
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:103-149`
```
uint32_t gensize = 0;
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
outlen = CRYPT_SHAKE128_BLOCKSIZE;
buflen = CRYPT_SHAKE128_BLOCKSIZE / 4; // buflen in terms of uint32_t

uint32_t j = 0;
for (uint32_t i = gensize; i < MLDSA_N;) {
    const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
    const uint32_t w1 = CRYPT_HTOLE32(buf[j + 1]);
    const uint32_t w2 = CRYPT_HTOLE32(buf[j + 2]);
    ...
    j += 3;
    if (j >= buflen && i < MLDSA_N) {
        GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
        j = 0;
    }
}
```
**Issue**: After `MldRejUniformAsm` processes the initial five SHAKE128 blocks, the scalar tail starts with `j = 0` and reads from `buf[0]` again. If the fast path returns fewer than 256 accepted coefficients, the continuation duplicates bytes from the beginning of the XOF output instead of squeezing the next block, so the ARMv8 result diverges from the reference rejection sampler on that edge path.
**Fix**:
```
uint32_t gensize = MldRejUniformAsm(a, (const uint8_t *)buf, outlen, MLD_REJ_UNIFORM_TABLE);
outlen = CRYPT_SHAKE128_BLOCKSIZE;
buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;

if (gensize < MLDSA_N) {
    GOTO_ERR_IF(hashMethod->squeeze(mdCtx, (uint8_t *)buf, outlen), ret);
}
uint32_t j = 0;
for (uint32_t i = gensize; i < MLDSA_N;) {
    const uint32_t w0 = CRYPT_HTOLE32(buf[j]);
    const uint32_t w1 = CRYPT_HTOLE32(buf[j + 1]);
    const uint32_t w2 = CRYPT_HTOLE32(buf[j + 2]);
    ...
}
```

---
