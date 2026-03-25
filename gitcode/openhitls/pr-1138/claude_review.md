# Code Review: openHiTLS/openhitls#1138
**Reviewer**: CLAUDE


## High

### Error handling removed in BssaUnBlind
`crypto/rsa/src/rsa_encdec.c:702`
```
(void)BN_Bin2Bn(z, input, inputLen);
GOTO_ERR_IF(BN_ModMul(s, z, blind->rInv, n, opt), ret);
```
**Issue**: The function ignores the return value of BN_Bn2Bn. If the function fails (e.g., memory allocation in BnExtend), z is zeroized and the computation proceeds with z=0, causing incorrect cryptographic output instead of returning an error.
**Fix**:
```
GOTO_ERR_IF(BN_Bin2Bn(z, input, inputLen), ret);
GOTO_ERR_IF(BN_ModMul(s, z, blind->rInv, n, opt), ret);
```

---

### NULL check removed in X509_AddCAPath
`pki/x509_verify/src/hitls_x509_verify.c:408-419`
```
static int32_t X509_AddCAPath(HITLS_X509_StoreCtx *storeCtx, const void *val, uint32_t valLen)
{
    if (valLen == 0 || valLen > MAX_PATH_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    const char *caPath = (const char *)val;
    ...
    if (strlen(existPath) == valLen && memcmp(existPath, caPath, valLen) == 0) {
```
**Issue**: The NULL check for val parameter was removed. If val is NULL but valLen is a valid number, the function will crash at line 419 when calling memcmp(existPath, caPath, valLen) where caPath is NULL.
**Fix**:
```
static int32_t X509_AddCAPath(HITLS_X509_StoreCtx *storeCtx, const void *val, uint32_t valLen)
{
    if (val == NULL || valLen == 0 || valLen > MAX_PATH_LEN) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    const char *caPath = (const char *)val;
    ...
```

---


## Medium

### Error handling removed for BN_SubLimb
`crypto/rsa/src/rsa_encdec.c:52`
```
(void)BN_SubLimb(nMinusOne, n, 1);
if (BN_Cmp(input, nMinusOne) >= 0) {
    ret = CRYPT_RSA_ERR_INPUT_VALUE;
```
**Issue**: BN_SubLimb can fail with CRYPT_NULL_INPUT or CRYPT_MEM_ALLOC_FAIL. Ignoring the error means if nMinusOne allocation fails, the comparison with n-1 is skipped, potentially accepting invalid input values.
**Fix**:
```
ret = BN_SubLimb(nMinusOne, n, 1);
if (ret != CRYPT_SUCCESS) {
    BSL_ERR_PUSH_ERROR(ret);
    BN_Destroy(nMinusOne);
    return ret;
}
if (BN_Cmp(input, nMinusOne) >= 0) {
```

---

### NULL check removed in TcpGetFd
`bsl/uio/src/uio_tcp.c:143-152`
```
static int32_t TcpGetFd(BSL_UIO *uio, int32_t size, int32_t *fd)
{
    ...
    TcpPrameters *ctx = uio->ctx;
    *fd = ctx->fd;
```
**Issue**: The function no longer checks if uio->ctx is NULL before accessing ctx->fd. While uio->ctx should be non-NULL after BSL_UIO_New, this reduces robustness.
**Fix**:
```
static int32_t TcpGetFd(BSL_UIO *uio, int32_t size, int32_t *fd)
{
    ...
    TcpPrameters *ctx = uio->ctx;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_UNINITIALIZED);
        return BSL_UIO_UNINITIALIZED;
    }
    *fd = ctx->fd;
```

---

### NULL check removed in TcpSetFd
`bsl/uio/src/uio_tcp.c:130-141`
```
static int32_t TcpSetFd(BSL_UIO *uio, int32_t size, const int32_t *fd)
{
    ...
    TcpPrameters *ctx = uio->ctx;
    if (ctx->fd != -1) {
```
**Issue**: The function no longer checks if uio->ctx is NULL before accessing ctx->fd. TcpSocketCtrl checks uio->ctx == NULL but TcpSetFd can be called directly.
**Fix**:
```
static int32_t TcpSetFd(BSL_UIO *uio, int32_t size, const int32_t *fd)
{
    ...
    TcpPrameters *ctx = uio->ctx;
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_UIO_UNINITIALIZED);
        return BSL_UIO_UNINITIALIZED;
    }
    if (ctx->fd != -1) {
```

---


## Low

### Unnecessary memory allocation in RSA_GetPublicExp
`crypto/rsa/src/rsa_keygen.c:258-259`
```
BN_BigNum *r1 = BN_Create(bits);
BN_BigNum *r2 = BN_Create(bits);
// r1 = p - 1, r2 = q - 1 where p and q are ~bits/2 sized primes
```
**Issue**: r1 and r2 are allocated with bits size instead of bits>>1. Since p-1 and q-1 (where p and q are roughly bits/2 sized primes) fit in bits/2 + 1 bits, using bits size is wasteful for a bin size optimization PR.
**Fix**:
```
BN_BigNum *r1 = BN_Create(bits >> 1);
BN_BigNum *r2 = BN_Create(bits >> 1);
```

---

### Redundant NULL check removed in DRBG_CtrXor
`crypto/drbg/src/drbg_ctr.c:52-53`
```
static void DRBG_CtrXor(CRYPT_Data *dst, const CRYPT_Data *src)
{
    uint32_t xorlen;
    if (CRYPT_IsDataNull(src)) {
        return;
    }
```
**Issue**: The NULL check for dst was removed. While all callers pass stack-allocated temp buffer, this reduces defensive programming.
**Fix**:
```
static void DRBG_CtrXor(CRYPT_Data *dst, const CRYPT_Data *src)
{
    uint32_t xorlen;
    if (CRYPT_IsDataNull(dst) || CRYPT_IsDataNull(src)) {
        return;
    }
```

---

### memcpy_s error handling removed
`crypto/drbg/src/drbg_ctr.c:202`
```
(void)memcpy_s(temp + tempPos, left, in->data + offset, cpyLen);
```
**Issue**: Ignoring memcpy_s return value removes bounds checking validation, though the code ensures valid sizes.
**Fix**:
```
if (memcpy_s(temp + tempPos, left, in->data + offset, cpyLen) != EOK) {
    BSL_ERR_PUSH_ERROR(CRYPT_SECUREC_FAIL);
    return CRYPT_SECUREC_FAIL;
}
```

---
