# Final Code Review Report
## openssl/openssl - PR #29381
** Added LMS support for OpenSSL commandline signature verification using pkeyutl.**

### Summary
- **Total Issues**: 10
- **Critical**: 0
- **High**: 2
- **Medium**: 5
- **Low**: 3
- **Reviewers**: claude, gemini, codex

---


## High

### NULL pointer dereference before NULL check in ossl_lms_key_to_text()
`providers/implementations/encode_decode/lms_codecs.c:145-148`
**Reviewers**: CODEX | **置信度**: 可信
```
int ossl_lms_key_to_text(BIO *out, const LMS_KEY *key, int selection)
{
    const LMS_PARAMS *lms_params = key->lms_params;
    const LM_OTS_PARAMS *ots_params = key->ots_params;

    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
```
**Issue**: The function dereferences `key` to fetch `lms_params` and `ots_params` on lines 147-148, but the NULL check for `key` is on line 150. If called with a NULL key, the function will crash instead of returning the intended error.
**Fix**:
```
int ossl_lms_key_to_text(BIO *out, const LMS_KEY *key, int selection)
{
    const LMS_PARAMS *lms_params;
    const LM_OTS_PARAMS *ots_params;

    if (out == NULL || key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    lms_params = key->lms_params;
    ots_params = key->ots_params;
```

---

### ossl_lms_i2d_pubkey() always uses 32-byte header regardless of key digest size
`providers/implementations/encode_decode/lms_codecs.c:117-136`
**Reviewers**: CLAUDE, GEMINI | **置信度**: 可信
```
int ossl_lms_i2d_pubkey(const LMS_KEY *key, unsigned char **out)
{
    if (key->pub.encoded == NULL || key->pub.encodedlen == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
            "no %s public key data available", "LMS");
        return 0;
    }
    if (out != NULL) {
        uint8_t *buf = OPENSSL_malloc(HSS_HEADER + key->pub.encodedlen);

        if (buf == NULL)
            return 0;
        /* Output HSS format which has a 4 byte value (L = 1) */
        memcpy(buf, hss_lms_32_spkifmt.header + sizeof(hss_lms_32_spkifmt.header) - HSS_HEADER, HSS_HEADER);
```
**Issue**: The function always copies the HSS header from `hss_lms_32_spkifmt.header` on line 130, regardless of the actual key's digest size (n=24 or n=32). This causes incorrect ASN.1 encoding for keys using 24-byte digest, as the length byte in the SPKI header will be wrong.
**Fix**:
```
int ossl_lms_i2d_pubkey(const LMS_KEY *key, unsigned char **out)
{
    const uint8_t *header_src;
    
    if (key->pub.encoded == NULL || key->pub.encodedlen == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
            "no %s public key data available", "LMS");
        return 0;
    }
    if (key->lms_params == NULL) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "LMS key parameters not available");
        return 0;
    }
    if (out != NULL) {
        uint8_t *buf = OPENSSL_malloc(HSS_HEADER + key->pub.encodedlen);

        if (buf == NULL)
            return 0;
        /* Select the correct header based on digest size */
        header_src = (key->lms_params->n == 24) 
                    ? hss_lms_24_spkifmt.header + sizeof(hss_lms_24_spkifmt.header) - HSS_HEADER
                    : hss_lms_32_spkifmt.header + sizeof(hss_lms_32_spkifmt.header) - HSS_HEADER;
        memcpy(buf, header_src, HSS_HEADER);
```

---


## Medium

### Missing NULL check in ossl_lms_key_get_pub()
`crypto/lms/lms_key.c:111-114`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
const uint8_t *ossl_lms_key_get_pub(const LMS_KEY *key)
{
    return key->pub.encoded;
}
```
**Issue**: The function returns `key->pub.encoded` without checking if `key` is NULL. While the caller in `lms_get_params()` does check for NULL, defensive programming suggests the getter should handle NULL input gracefully.
**Fix**:
```
const uint8_t *ossl_lms_key_get_pub(const LMS_KEY *key)
{
    if (key == NULL)
        return NULL;
    return key->pub.encoded;
}
```

---

### Getter functions don't validate lms_params and ots_params pointers
`crypto/lms/lms_key.c:117-130`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
size_t ossl_lms_key_get_pub_len(const LMS_KEY *key)
{
    return 24 + key->lms_params->n;
}

size_t ossl_lms_key_get_collision_strength_bits(const LMS_KEY *key)
{
    return key->lms_params->n * 8;
}

size_t ossl_lms_key_get_sig_len(const LMS_KEY *key)
{
    return 12 + key->lms_params->n * (1 + key->ots_params->p + key->lms_params->h);
}
```
**Issue**: The functions `ossl_lms_key_get_pub_len()`, `ossl_lms_key_get_collision_strength_bits()`, and `ossl_lms_key_get_sig_len()` dereference `key->lms_params` and `key->ots_params` without NULL checks. These are called from `lms_get_params()` which only validates that `key` is non-NULL, not that its internal pointers are initialized. A partially initialized LMS_KEY could cause a crash.
**Fix**:
```
size_t ossl_lms_key_get_pub_len(const LMS_KEY *key)
{
    if (key == NULL || key->lms_params == NULL)
        return 0;
    return 24 + key->lms_params->n;
}

size_t ossl_lms_key_get_collision_strength_bits(const LMS_KEY *key)
{
    if (key == NULL || key->lms_params == NULL)
        return 0;
    return key->lms_params->bit_strength;
}

size_t ossl_lms_key_get_sig_len(const LMS_KEY *key)
{
    if (key == NULL || key->lms_params == NULL || key->ots_params == NULL)
        return 0;
    return 12 + key->lms_params->n * (1 + key->ots_params->p + key->lms_params->h);
}
```

---

### Missing NULL checks in setdigest()
`providers/implementations/signature/lms_signature.c:67-88`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
static int setdigest(PROV_LMS_CTX *ctx, const char *digestname)
{
    /*
     * Assume that only one digest can be used by LMS.
     * Set the digest to the one contained in the public key.
     * If the optional digestname passed in by the user is different
     * then return an error.
     */
    LMS_KEY *key = ctx->key;
    const char *pub_digestname = key->ots_params->digestname;
```
**Issue**: The `setdigest()` function accesses `ctx->key->ots_params->digestname` without checking if `ctx->key` or `ctx->key->ots_params` are NULL. While the caller `lms_verify_msg_init()` checks for NULL key, a partially initialized key with NULL `ots_params` would cause a crash.
**Fix**:
```
static int setdigest(PROV_LMS_CTX *ctx, const char *digestname)
{
    /*
     * Assume that only one digest can be used by LMS.
     * Set the digest to the one contained in the public key.
     * If the optional digestname passed in by the user is different
     * then return an error.
     */
    LMS_KEY *key = ctx->key;
    
    if (key == NULL || key->ots_params == NULL)
        return 0;
    const char *pub_digestname = key->ots_params->digestname;
```

---

### ossl_lms_key_get_collision_strength_bits() ignores bit_strength field
`crypto/lms/lms_key.c:122-125`
**Reviewers**: CODEX, CLAUDE, GEMINI | **置信度**: 可信
```
size_t ossl_lms_key_get_collision_strength_bits(const LMS_KEY *key)
{
    return key->lms_params->n * 8;
}
```
**Issue**: The function returns `key->lms_params->n * 8` which equals the digest output size (256 or 192 bits), but the `lms_params` table has a `bit_strength` field that contains correct collision resistance values (128 or 96 bits). Using the digest size instead of collision resistance overstates security strength for policy checks.
**Fix**:
```
size_t ossl_lms_key_get_collision_strength_bits(const LMS_KEY *key)
{
    if (key == NULL || key->lms_params == NULL)
        return 0;
    return key->lms_params->bit_strength;
}
```

---

### SHAKE security strength uses digest size instead of collision resistance
`crypto/lms/lms_params.c:24-34`
**Reviewers**: GEMINI | **置信度**: 需评估
```
{ OSSL_LMS_TYPE_SHAKE_N32_H5, "SHAKE-256", 32, 5, 256 },
{ OSSL_LMS_TYPE_SHAKE_N32_H10, "SHAKE-256", 32, 10, 256 },
{ OSSL_LMS_TYPE_SHAKE_N32_H15, "SHAKE-256", 32, 15, 256 },
{ OSSL_LMS_TYPE_SHAKE_N32_H20, "SHAKE-256", 32, 20, 256 },
{ OSSL_LMS_TYPE_SHAKE_N32_H25, "SHAKE-256", 32, 25, 256 },
/* SHAKE-256/192 */
{ OSSL_LMS_TYPE_SHAKE_N24_H5, "SHAKE-256", 24, 5, 192 },
{ OSSL_LMS_TYPE_SHAKE_N24_H10, "SHAKE-256", 24, 10, 192 },
{ OSSL_LMS_TYPE_SHAKE_N24_H15, "SHAKE-256", 24, 15, 192 },
{ OSSL_LMS_TYPE_SHAKE_N24_H20, "SHAKE-256", 24, 20, 192 },
{ OSSL_LMS_TYPE_SHAKE_N24_H25, "SHAKE-256", 24, 25, 192 },
```
**Issue**: The SHAKE-based LMS parameters list 256/192 bit_strength, but collision resistance for hash-based signatures should be n/2. For SHAKE256 with 32-byte output, collision resistance is 128 bits, not 256. For 24-byte output, it's 96 bits, not 192. The SHA256 entries correctly use 128/96, but SHAKE entries use 256/192.
**Fix**:
```
/* Collision resistance is n/2 for hash-based signatures */
{ OSSL_LMS_TYPE_SHAKE_N32_H5, "SHAKE-256", 32, 5, 128 },
{ OSSL_LMS_TYPE_SHAKE_N32_H10, "SHAKE-256", 32, 10, 128 },
{ OSSL_LMS_TYPE_SHAKE_N32_H15, "SHAKE-256", 32, 15, 128 },
{ OSSL_LMS_TYPE_SHAKE_N32_H20, "SHAKE-256", 32, 20, 128 },
{ OSSL_LMS_TYPE_SHAKE_N32_H25, "SHAKE-256", 32, 25, 128 },
/* SHAKE-256/192 */
{ OSSL_LMS_TYPE_SHAKE_N24_H5, "SHAKE-256", 24, 5, 96 },
{ OSSL_LMS_TYPE_SHAKE_N24_H10, "SHAKE-256", 24, 10, 96 },
{ OSSL_LMS_TYPE_SHAKE_N24_H15, "SHAKE-256", 24, 15, 96 },
{ OSSL_LMS_TYPE_SHAKE_N24_H20, "SHAKE-256", 24, 20, 96 },
{ OSSL_LMS_TYPE_SHAKE_N24_H25, "SHAKE-256", 24, 25, 96 },
```

---


## Low

### Missing NULL pointer check for pk parameter
`providers/implementations/encode_decode/lms_codecs.c:87-115`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
LMS_KEY *
ossl_lms_d2i_PUBKEY(const uint8_t *pk, int pk_len, PROV_CTX *provctx)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    LMS_KEY *ret;
    const LMS_SPKI_FMT *spkifmt;

    if (pk_len <= 0)
        return NULL;
    spkifmt = find_spkifmt(pk, pk_len);
```
**Issue**: The function `ossl_lms_d2i_PUBKEY()` does not check if `pk` is NULL before passing it to `memcmp()` in `find_spkifmt()`. If a NULL pointer is passed, `memcmp()` will crash.
**Fix**:
```
LMS_KEY *
ossl_lms_d2i_PUBKEY(const uint8_t *pk, int pk_len, PROV_CTX *provctx)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    LMS_KEY *ret;
    const LMS_SPKI_FMT *spkifmt;

    if (pk == NULL || pk_len <= HSS_LMS_SPKI_OVERHEAD)
        return NULL;
    spkifmt = find_spkifmt(pk, pk_len);
```

---

### Trace printf may dereference NULL description pointer
`crypto/encode_decode/decoder_pkey.c:422-427`
**Reviewers**: CODEX | **置信度**: 较可信
```
OSSL_TRACE_BEGIN(DECODER)
{
    BIO_printf(trc_out,
        "(Collecting KeyManager %s %s [id %d]:\n",
        keymgmt->description, keymgmt->type_name, keymgmt->id);
}
```
**Issue**: `keymgmt->description` can be NULL (algorithm descriptions are optional in OpenSSL). Passing NULL to `%s` format specifier is undefined behavior and can crash on some libc implementations when decoder tracing is enabled.
**Fix**:
```
OSSL_TRACE_BEGIN(DECODER)
{
    const char *desc = keymgmt->description != NULL ? keymgmt->description : "";
    BIO_printf(trc_out,
        "(Collecting KeyManager %s %s [id %d]:\n",
        desc, keymgmt->type_name, keymgmt->id);
}
```

---

### Commented out code suggests incomplete implementation
`providers/implementations/signature/lms_signature.c:128-142`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
static int lms_digest_verify_init(void *vctx, const char *mdname, void *vkey,
    const OSSL_PARAM params[])
{
    PROV_LMS_CTX *ctx = (PROV_LMS_CTX *)vctx;

    if (mdname != NULL && mdname[0] != '\0') {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
            "Explicit digest not supported for LMS operations");
        return 0;
    }
    if (vkey == NULL && ctx->key != NULL)
        return 1; /* lms_set_ctx_params(ctx, params); */

    return lms_verify_msg_init(vctx, vkey, params);
}
```
**Issue**: Line 139 contains commented out code `/* lms_set_ctx_params(ctx, params); */` suggesting the `params` argument should be processed when `vkey == NULL && ctx->key != NULL`. Currently, the params are silently ignored, which may lead to unexpected behavior.
**Fix**:
```
static int lms_digest_verify_init(void *vctx, const char *mdname, void *vkey,
    const OSSL_PARAM params[])
{
    PROV_LMS_CTX *ctx = (PROV_LMS_CTX *)vctx;

    if (mdname != NULL && mdname[0] != '\0') {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
            "Explicit digest not supported for LMS operations");
        return 0;
    }
    if (vkey == NULL && ctx->key != NULL) {
        /* Process params if provided - currently no params are supported */
        if (params != NULL && OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST) != NULL) {
            ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DIGEST,
                "Explicit digest not supported for LMS operations");
            return 0;
        }
        return 1;
    }

    return lms_verify_msg_init(vctx, vkey, params);
}
```

---
