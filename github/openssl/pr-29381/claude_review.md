# Code Review: openssl/openssl#29381
**Reviewer**: CLAUDE

** Added LMS support for OpenSSL commandline signature verification using pkeyutl.**


## Critical

### NULL pointer dereference in ossl_lms_key_get_pub_len()
`crypto/lms/lms_key.c:117-119`
```
size_t ossl_lms_key_get_pub_len(const LMS_KEY *key)
{
    return 24 + key->lms_params->n;
}
```
**Issue**: The function `ossl_lms_key_get_pub_len()` dereferences `key->lms_params->n` without checking if `key->lms_params` is NULL. This function is called from `lms_get_params()` in lms_kmgmt.c before validating the key. If a partially initialized or corrupted LMS_KEY is passed, this will cause a NULL pointer dereference crash.
**Fix**:
```
size_t ossl_lms_key_get_pub_len(const LMS_KEY *key)
{
    if (key == NULL || key->lms_params == NULL)
        return 0;
    return 24 + key->lms_params->n;
}
```

---

### NULL pointer dereference in ossl_lms_key_get_collision_strength_bits()
`crypto/lms/lms_key.c:122-125`
```
size_t ossl_lms_key_get_collision_strength_bits(const LMS_KEY *key)
{
    return key->lms_params->n * 8;
}
```
**Issue**: The function dereferences `key->lms_params->n` without checking if `key->lms_params` is NULL. This is called from `lms_get_params()` in lms_kmgmt.c and can crash if the key is not fully initialized.
**Fix**:
```
size_t ossl_lms_key_get_collision_strength_bits(const LMS_KEY *key)
{
    if (key == NULL || key->lms_params == NULL)
        return 0;
    return key->lms_params->n * 8;
}
```

---

### NULL pointer dereference in ossl_lms_key_get_sig_len()
`crypto/lms/lms_key.c:127-130`
```
size_t ossl_lms_key_get_sig_len(const LMS_KEY *key)
{
    return 12 + key->lms_params->n * (1 + key->ots_params->p + key->lms_params->h);
}
```
**Issue**: The function dereferences `key->lms_params` and `key->ots_params` without NULL checks. This is called from `lms_get_params()` in lms_kmgmt.c and can crash if the key is not fully initialized.
**Fix**:
```
size_t ossl_lms_key_get_sig_len(const LMS_KEY *key)
{
    if (key == NULL || key->lms_params == NULL || key->ots_params == NULL)
        return 0;
    return 12 + key->lms_params->n * (1 + key->ots_params->p + key->lms_params->h);
}
```

---


## High

### NULL pointer dereference in ossl_lms_key_get_pub()
`crypto/lms/lms_key.c:111-114`
```
const uint8_t *ossl_lms_key_get_pub(const LMS_KEY *key)
{
    return key->pub.encoded;
}
```
**Issue**: The function returns `key->pub.encoded` without checking if `key` is NULL. While `lms_get_params()` checks for NULL before calling this, defensive programming suggests the check should be in the getter function itself.
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

### Missing validation in ossl_lms_d2i_PUBKEY()
`providers/implementations/encode_decode/lms_codecs.c:87-115`
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
    if (spkifmt == NULL)
        return NULL;

    if ((ret = ossl_lms_key_new(libctx)) == NULL)
        return NULL;

    pk += sizeof(spkifmt->header);
    pk_len -= sizeof(spkifmt->header);

    if (!ossl_lms_pubkey_decode(pk, (size_t)pk_len, ret)) {
```
**Issue**: The function does not validate that `pk_len` matches the expected size after finding the spkifmt. If `pk_len` is exactly `HSS_LMS_SPKI_OVERHEAD`, the function skips the check on line 79 but passes the `find_spkifmt` check. Then on lines 103-104, it subtracts `sizeof(spkifmt->header)` which is a compile-time constant (24), but uses `pk_len` which could be exactly 24, resulting in a zero-length payload being passed to `ossl_lms_pubkey_decode()`. Additionally, there's no check that `pk` is not NULL before dereferencing it.
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
    if (spkifmt == NULL)
        return NULL;

    if ((ret = ossl_lms_key_new(libctx)) == NULL)
        return NULL;

    pk += sizeof(spkifmt->header);
    pk_len -= sizeof(spkifmt->header);

    if (!ossl_lms_pubkey_decode(pk, (size_t)pk_len, ret)) {
```

---

### Missing NULL checks before calling getter functions
`providers/implementations/keymgmt/lms_kmgmt.c:175-203`
```
static int lms_get_params(void *keydata, OSSL_PARAM params[])
{
    LMS_KEY *key = keydata;
    const uint8_t *d;
    size_t len;
    struct lms_get_params_st p;

    if (key == NULL || !lms_get_params_decoder(params, &p))
        return 0;

    if (p.bits != NULL
        && !OSSL_PARAM_set_size_t(p.bits, 8 * ossl_lms_key_get_pub_len(key)))
        return 0;

    if (p.secbits != NULL
        && !OSSL_PARAM_set_size_t(p.secbits, ossl_lms_key_get_collision_strength_bits(key)))
        return 0;

    if (p.maxsize != NULL
        && !OSSL_PARAM_set_size_t(p.maxsize, ossl_lms_key_get_sig_len(key)))
```
**Issue**: The `lms_get_params()` function checks if `key == NULL` but then calls getter functions like `ossl_lms_key_get_pub_len()` which dereference `key->lms_params` and `key->ots_params` without checking if those pointers are NULL. If a partially initialized LMS_KEY object is passed (where `key` is not NULL but `lms_params` or `ots_params` are), this will cause a crash.
**Fix**:
```
static int lms_get_params(void *keydata, OSSL_PARAM params[])
{
    LMS_KEY *key = keydata;
    const uint8_t *d;
    size_t len;
    struct lms_get_params_st p;

    if (key == NULL || !lms_get_params_decoder(params, &p))
        return 0;
    
    /* Validate that the key is properly initialized */
    if (key->lms_params == NULL || key->ots_params == NULL)
        return 0;

    if (p.bits != NULL
        && !OSSL_PARAM_set_size_t(p.bits, 8 * ossl_lms_key_get_pub_len(key)))
        return 0;

    if (p.secbits != NULL
        && !OSSL_PARAM_set_size_t(p.secbits, ossl_lms_key_get_collision_strength_bits(key)))
        return 0;

    if (p.maxsize != NULL
        && !OSSL_PARAM_set_size_t(p.maxsize, ossl_lms_key_get_sig_len(key)))
```

---

### Missing NULL check in setdigest()
`providers/implementations/signature/lms_signature.c:67-88`
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
**Issue**: The `setdigest()` function accesses `ctx->key->ots_params->digestname` without checking if `ctx->key` is NULL. The function is called from `lms_verify_msg_init()` which does check for NULL key, but `setdigest()` is not defensive. If the key's `ots_params` is NULL, this will crash.
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

### Hardcoded header format in ossl_lms_i2d_pubkey()
`providers/implementations/encode_decode/lms_codecs.c:117-136`
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
        /* Output the LMS encoded public key */
        memcpy(buf + HSS_HEADER, key->pub.encoded, key->pub.encodedlen);
        *out = buf;
    }
    return (int)key->pub.encodedlen + HSS_HEADER;
}
```
**Issue**: The function always uses `hss_lms_32_spkifmt.header` when copying the HSS header, regardless of the actual key's digest size. If the key uses 24-byte digest (n=24), the wrong header format is copied, which will result in incorrect ASN.1 encoding. The function should check the key's `lms_params->n` value to select the correct header.
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
        /* Output HSS format which has a 4 byte value (L = 1) */
        memcpy(buf, header_src, HSS_HEADER);
        /* Output the LMS encoded public key */
        memcpy(buf + HSS_HEADER, key->pub.encoded, key->pub.encodedlen);
        *out = buf;
    }
    return (int)key->pub.encodedlen + HSS_HEADER;
}
```

---


## Medium

### Missing call to lms_set_ctx_params in lms_digest_verify_init()
`providers/implementations/signature/lms_signature.c:128-142`
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
**Issue**: The comment on line 139 says `/* lms_set_ctx_params(ctx, params); */` suggesting this code should be called but it's commented out. This means the `params` argument is completely ignored when `vkey == NULL`, which could lead to unexpected behavior if parameters are passed.
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
        /* Process params if provided */
        if (params != NULL) {
            /* TODO: Implement lms_set_ctx_params or handle params here */
            return 0;
        }
        return 1;
    }

    return lms_verify_msg_init(vctx, vkey, params);
}
```

---

### Missing closing parenthesis in BIO_printf trace
`crypto/encode_decode/decoder_pkey.c:422-427`
```
OSSL_TRACE_BEGIN(DECODER)
{
    BIO_printf(trc_out,
        "(Collecting KeyManager %s %s [id %d]:\n",
        keymgmt->description, keymgmt->type_name, keymgmt->id);
}
```
**Issue**: The `BIO_printf` call on line 424 is missing the closing parenthesis at the end of the format string. This will cause a compilation error or undefined behavior.
**Fix**:
```
OSSL_TRACE_BEGIN(DECODER)
{
    BIO_printf(trc_out,
        "(Collecting KeyManager %s %s [id %d])\n",
        keymgmt->description, keymgmt->type_name, keymgmt->id);
}
```

---


## Low

### Incorrect selection check in lms_has()
`providers/implementations/keymgmt/lms_kmgmt.c:54`
```
static int lms_has(const void *keydata, int selection)
{
    LMS_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
-    if ((selection & LMS_POSSIBLE_SELECTIONS) == 0)
+    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1; /* the selection is not missing */
```
**Issue**: The code changes `LMS_POSSIBLE_SELECTIONS` to `OSSL_KEYMGMT_SELECT_KEYPAIR` but `OSSL_KEYMGMT_SELECT_KEYPAIR` includes both public and private key selections. Since LMS only supports public keys, checking `OSSL_KEYMGMT_SELECT_KEYPAIR` will incorrectly return 1 when only private key is selected. The original `LMS_POSSIBLE_SELECTIONS` (defined as `OSSL_KEYMGMT_SELECT_PUBLIC_KEY`) was more correct.
**Fix**:
```
static int lms_has(const void *keydata, int selection)
{
    LMS_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1; /* the selection is not missing */
    
    /* Only public key is supported for LMS */
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        return 0;
    
    return ossl_lms_key_has(key, selection);
```

---
