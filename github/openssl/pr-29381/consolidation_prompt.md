# Code Review Consolidation Task

You are consolidating code review findings from multiple AI reviewers.

## Context
- Repository: openssl/openssl
- PR: #29381
- Title:  Added LMS support for OpenSSL commandline signature verification using pkeyutl.

## Individual Review Reports

## CLAUDE Review

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


---

## GEMINI Review

# Code Review: openssl/openssl#29381
**Reviewer**: GEMINI

** Added LMS support for OpenSSL commandline signature verification using pkeyutl.**


## High

### ossl_lms_i2d_pubkey violates i2d semantics and leaks memory
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
**Issue**: The function `ossl_lms_i2d_pubkey` does not follow the standard OpenSSL `i2d` calling convention. 
1. It ignores the value of `*out` if `out` is not NULL, and always allocates a new buffer. If `*out` pointed to an existing buffer (as expected by many OpenSSL internal encoders), that pointer is overwritten, leading to a memory leak of the ignored buffer or incorrect writing behavior.
2. It returns `0` on error, whereas `i2d` functions typically return a negative value on error, or `0` could be ambiguous. However, returning `0` for length is generally considered an error in this context.
3. It does not support the mode where it writes to a user-provided buffer (incrementing the pointer).

Calls from `encode_key2any.c` (via `lms_spki_pub_to_der`) might expect standard `i2d` behavior (allocation only if `*out` is NULL).
**Fix**:
```
int ossl_lms_i2d_pubkey(const LMS_KEY *key, unsigned char **out)
{
    int len;
    unsigned char *p;

    if (key->pub.encoded == NULL || key->pub.encodedlen == 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_NOT_A_PUBLIC_KEY,
            "no %s public key data available", "LMS");
        return -1;
    }
    
    len = (int)key->pub.encodedlen + HSS_HEADER;

    if (out == NULL)
        return len;

    if (*out == NULL) {
        if ((*out = OPENSSL_malloc(len)) == NULL)
            return -1;
        p = *out;
    } else {
        p = *out;
    }

    /* Output HSS format which has a 4 byte value (L = 1) */
    memcpy(p, hss_lms_32_spkifmt.header + sizeof(hss_lms_32_spkifmt.header) - HSS_HEADER, HSS_HEADER);
    /* Output the LMS encoded public key */
    memcpy(p + HSS_HEADER, key->pub.encoded, key->pub.encodedlen);

    if (*out != p) /* If we didn't allocate, advance the pointer */
        *out += len;
        
    return len;
}
```

---


## Medium

### Brittle manual parsing of SPKI header violates DER rules
`providers/implementations/encode_decode/lms_codecs.c:81`
```
if (memcmp(pk, codecs[i].spkifmt->header, HSS_LMS_SPKI_OVERHEAD) == 0)
            return codecs[i].spkifmt;
```
**Issue**: The function `find_spkifmt` (and thus `ossl_lms_d2i_PUBKEY`) uses `memcmp` to verify the SubjectPublicKeyInfo (SPKI) header against a hardcoded byte sequence. This rejects valid DER/BER encodings that use long-form length encoding (e.g., `81 4E` instead of `4E`) or other valid variations. It also relies on the exact byte match of the AlgorithmIdentifier OID and parameters, making it brittle. OpenSSL provides `d2i_X509_PUBKEY` for robust parsing of SPKI structures.
**Fix**:
```
/* Use d2i_X509_PUBKEY to parse the header robustly */
LMS_KEY *
ossl_lms_d2i_PUBKEY(const uint8_t *pk, int pk_len, PROV_CTX *provctx)
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    LMS_KEY *ret = NULL;
    X509_PUBKEY *xpk = NULL;
    const unsigned char *p = pk;
    const unsigned char *pk_data;
    int pk_data_len;
    ASN1_OBJECT *oid;

    /* robustly decode SPKI */
    if ((xpk = d2i_X509_PUBKEY(NULL, &p, pk_len)) == NULL)
        return NULL;

    if (!X509_PUBKEY_get0_param(&oid, &pk_data, &pk_data_len, NULL, xpk))
        goto err;

    /* Verify OID is id-ad-hss-lms-hash-sig (1.2.840.113549.1.9.16.3.17) */
    /* Implementation needs the OID object or NID check here */
    /* For simplicity in this context, assuming we can check NID or data */
    
    if ((ret = ossl_lms_key_new(libctx)) == NULL)
        goto err;

    /* Skip the HSS L=1 header (4 bytes) contained in the BIT STRING if present */
    /* The hardcoded check expected the BIT STRING content to start with 00 00 00 01 */
    if (pk_data_len < 4) 
        goto err;
    
    /* Check HSS L=1 marker 00 00 00 01 */
    /* Note: Previous code implied the input was SPKI, and extracted data after header */
    
    if (pk_data[3] != 1) { /* Simplified check, strictly should check 00 00 00 01 */
         /* Handle error */
    }

    if (!ossl_lms_pubkey_decode(pk_data + 4, pk_data_len - 4, ret)) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_BAD_ENCODING,
            "error parsing %s public key from input SPKI", "LMS");
        ossl_lms_key_free(ret);
        ret = NULL;
    }

err:
    X509_PUBKEY_free(xpk);
    return ret;
}
```

---

### OSSL_PKEY_PARAM_PUB_KEY returns incomplete HSS public key
`providers/implementations/keymgmt/lms_kmgmt.c:184`
```
if (p.pubkey != NULL) {
        d = ossl_lms_key_get_pub(key);
        if (d != NULL) {
            len = ossl_lms_key_get_pub_len(key);
            if (!OSSL_PARAM_set_octet_string(p.pubkey, d, len))
                return 0;
        }
    }
```
**Issue**: `lms_get_params` exports the raw LMS public key (without the HSS L=1 header) for the `OSSL_PKEY_PARAM_PUB_KEY` parameter. However, `EVP_PKEY_HSS_LMS` keys are expected to be HSS keys (NIST SP 800-208). The standard representation of an HSS public key includes the 4-byte header (L || public_key). Exporting it without the header creates an invalid key for external consumers expecting the HSS format.
**Fix**:
```
if (p.pubkey != NULL) {
        d = ossl_lms_key_get_pub(key);
        if (d != NULL) {
            unsigned char buf[64]; /* Enough for HSS header + largest LMS key */
            size_t lms_len = ossl_lms_key_get_pub_len(key);
            
            if (lms_len + 4 > sizeof(buf)) /* Should not happen with current params */
                return 0;

            /* Prepend HSS Header (L=1) */
            memset(buf, 0, 3);
            buf[3] = 1;
            memcpy(buf + 4, d, lms_len);
            
            if (!OSSL_PARAM_set_octet_string(p.pubkey, buf, lms_len + 4))
                return 0;
        }
    }
```

---

### Incorrect security strength for SHAKE instances
`crypto/lms/lms_params.c:22-26`
```
{ OSSL_LMS_TYPE_SHAKE_N32_H5, "SHAKE-256", 32, 5, 256 },
    { OSSL_LMS_TYPE_SHAKE_N32_H10, "SHAKE-256", 32, 10, 256 },
    ...
    /* SHAKE-256/192 */
    { OSSL_LMS_TYPE_SHAKE_N24_H5, "SHAKE-256", 24, 5, 192 },
```
**Issue**: The bit strength for SHAKE-based LMS parameters is listed as 256 or 192 bits, which corresponds to the output length (N) * 8. However, the security strength of a signature scheme is typically defined by its collision resistance. For SHAKE256 with output length $d$, the collision resistance is $\min(d/2, 256)$ (or 128 for $d=256$). Listing 256 bits for N=32 (256-bit output) overstates the collision resistance, which is 128 bits. Similarly for N=24, it should be 96 bits, not 192.
**Fix**:
```
/* Collision resistance is n/2 for SHAKE with length n */
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


---

## CODEX Review

# Code Review: openssl/openssl#29381
**Reviewer**: CODEX

** Added LMS support for OpenSSL commandline signature verification using pkeyutl.**


## Medium

### LMS security bits overstated for SHA256 variants
`crypto/lms/lms_key.c:122-124`
```
size_t ossl_lms_key_get_collision_strength_bits(const LMS_KEY *key)
{
    return key->lms_params->n * 8;
}
```
**Issue**: `ossl_lms_key_get_collision_strength_bits()` returns `n * 8`, which equals the digest output size, not the collision strength. For SHA256-based LMS (n=32/24), this reports 256/192 bits instead of the intended 128/96 (as reflected by the new `bit_strength` field). This feeds `OSSL_PKEY_PARAM_SECURITY_BITS` via `lms_get_params`, potentially bypassing security policy checks.
**Fix**:
```
size_t ossl_lms_key_get_collision_strength_bits(const LMS_KEY *key)
{
    return key->lms_params->bit_strength;
}
```

---


## Low

### NULL dereference before NULL check in LMS text encoder
`providers/implementations/encode_decode/lms_codecs.c:145-148`
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
**Issue**: `ossl_lms_key_to_text()` dereferences `key` to fetch `lms_params` and `ots_params` before validating `key` is non-NULL. If called with a NULL key, it will crash instead of returning the intended error.
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

### Trace printf may dereference NULL description
`crypto/encode_decode/decoder_pkey.c:422-426`
```
BIO_printf(trc_out,
    "(Collecting KeyManager %s %s [id %d]:\n",
    keymgmt->description, keymgmt->type_name, keymgmt->id);
```
**Issue**: `keymgmt->description` can be NULL (algorithm descriptions are optional). Passing NULL to `%s` is undefined and can crash on some libc implementations when decoder tracing is enabled.
**Fix**:
```
const char *desc = keymgmt->description != NULL ? keymgmt->description : "";
BIO_printf(trc_out,
    "(Collecting KeyManager %s %s [id %d]:\n",
    desc, keymgmt->type_name, keymgmt->id);
```

---


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the code
   - Use `git diff` and file reads to confirm
   - Remove false positives
   - Adjust severity if needed

3. **Consolidate Findings**
   - Merge duplicate issues (note which reviewers found it)
   - Keep unique valid issues
   - Prioritize by actual impact

4. **Output Format**

For each validated issue, output:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
REVIEWERS: <comma-separated list of reviewers who found this>
CONFIDENCE: trusted|likely|evaluate
PROBLEM: <consolidated description>
CODE:
```
<problematic code>
```
FIX:
```
<best suggested fix>
```
===END===

## Confidence Levels

- **trusted** (可信): Multiple reviewers found this issue AND you verified it in the code
- **likely** (较可信): Found by one reviewer AND you verified it exists in the code
- **evaluate** (需评估): Found by reviewer(s) but needs human review to confirm impact/fix

## Important

- SEVERITY indicates impact level (critical/high/medium/low)
- CONFIDENCE indicates how certain we are about this issue
- Only include issues you've verified in the code
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
