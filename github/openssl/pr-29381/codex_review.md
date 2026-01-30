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
