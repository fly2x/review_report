# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CLAUDE


## Critical

### Incorrect buffer index initialization in MLDSA_RejBoundedPolyEta2
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:182`
```
gensize = MldRejUniformEta2Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = bufLen+1; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
```
**Issue**: The fallback loop initializes j = bufLen+1 (137), which immediately triggers a buffer refill on the first iteration (j >= CRYPT_SHAKE256_BLOCKSIZE). This skips bytes from the buffer that were just fetched from SHAKE256. The C reference implementation uses j = 0. This could cause incorrect polynomial generation and weaken cryptographic security.
**Fix**:
```
gensize = MldRejUniformEta2Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = 0; i < MLDSA_N; j++) {
    if (j == CRYPT_SHAKE256_BLOCKSIZE) {
```

---

### Incorrect buffer index initialization in MLDSA_RejBoundedPolyEta4
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:235`
```
gensize = MldRejUniformEta4Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = bufLen+1; i < MLDSA_N; j++) {
    if (j >= CRYPT_SHAKE256_BLOCKSIZE) {
```
**Issue**: Similar to issue in Eta2, the loop initializes j = bufLen+1 (273), causing immediate buffer refill and skipping valid bytes. Additionally, the condition compares j against CRYPT_SHAKE256_BLOCKSIZE (136) instead of bufLen (272), which is inconsistent with the 2-block buffer allocation.
**Fix**:
```
gensize = MldRejUniformEta4Asm(a, buf, bufLen, MLD_REJ_UNIFORM_ETA_TABLE);

for (uint32_t i = gensize, j = 0; i < MLDSA_N; j++) {
    if (j == CRYPT_SHAKE256_BLOCKSIZE) {
```

---


## High

### Memory allocation bug fix for MLDSAKeyGenCreateMatrix
`crypto/mldsa/src/ml_dsa_core.c:95-102`
```
for (uint8_t i = 0; i < l; i++) {
    MLDSA_SET_VECTOR_MEM(st->s1[i], buf);
}
for (uint8_t i = 0; i < l; i++) {
    MLDSA_SET_VECTOR_MEM(st->s1Ntt[i], buf);
}
```
**Issue**: The original code had a critical bug where s1[i] and s1Ntt[i] were assigned memory in the same loop iteration, causing them to point to overlapping memory regions. The fix correctly splits this into two separate loops. This is a correct fix for a memory corruption bug.

---


## Medium

### Inconsistent buffer handling in MLDSA_RejNTTPoly fallback loop
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:108-109`
```
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
outlen = CRYPT_SHAKE128_BLOCKSIZE;
buflen = CRYPT_SHAKE128_BLOCKSIZE / 4;

uint32_t j = 0;
for (uint32_t i = gensize; i < MLDSA_N;) {
```
**Issue**: After the assembly call processes 5 blocks of SHAKE128 data, the fallback loop starts with j = 0. This means it re-processes the buffer from the beginning rather than continuing from where the assembly function left off. The C reference implementation starts with j = 0 but in a different context (no initial assembly preprocessing).
**Fix**:
```
gensize = MldRejUniformAsm(a, (uint8_t *) buf, outlen, MLD_REJ_UNIFORM_TABLE);
// Calculate how many bytes were consumed by the assembly function
uint32_t bytesConsumed = (gensize * 3 + 2) / 4 * sizeof(uint32_t); // Approximate
uint32_t j = bytesConsumed / sizeof(uint32_t);
buflen = outlen / sizeof(uint32_t);

for (uint32_t i = gensize; i < MLDSA_N;) {
```

---


## Low

### Malformed comments missing mathematical symbols
`crypto/mldsa/src/asm/export_ml_dsa_armv8.c:190`
```
// if  = 2 and b < 15 then return 2  (b mod 5)
...
// 2  (b mod 5)
```
**Issue**: The comments are missing mathematical operators (eta symbol η and minus sign -), making them incomplete and potentially misleading for developers trying to understand the algorithm.
**Fix**:
```
// if η = 2 and b < 15 then return 2 − (b mod 5)
...
// 2 − (b mod 5)
```

---
