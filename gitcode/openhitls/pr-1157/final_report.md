# Final Code Review Report
## openHiTLS/openhitls - PR #1157

### Summary
- **Total Issues**: 4
- **Critical**: 0
- **High**: 3
- **Medium**: 1
- **Low**: 0
- **Reviewers**: claude, gemini, codex

---


## High

### Stale CRT parameters retained when setting new private key without factors
`crypto/rsa/src/rsa_keyop.c:175-195`
**Reviewers**: CODEX, GEMINI | **置信度**: 可信
```
if (prv->p != NULL) {
    BN_Destroy(ctx->key.p);
    ctx->key.p = tmpCtx.key.p;
    tmpCtx.key.p = NULL;

    BN_Destroy(ctx->key.q);
    ctx->key.q = tmpCtx.key.q;
    tmpCtx.key.q = NULL;

    BN_Destroy(ctx->key.dP);
    ctx->key.dP = tmpCtx.key.dP;
    tmpCtx.key.dP = NULL;

    BN_Destroy(ctx->key.dQ);
    ctx->key.dQ = tmpCtx.key.dQ;
    tmpCtx.key.dQ = NULL;

    BN_Destroy(ctx->key.qInv);
    ctx->key.qInv = tmpCtx.key.qInv;
    tmpCtx.key.qInv = NULL;
}
```
**Issue**: When CRYPT_RSA_SetPrvKey is called with a private key that does not include CRT parameters (prv->p == NULL), the code conditionally skips replacing the p, q, dP, dQ, and qInv fields in ctx->key. Since n and d are unconditionally updated to the new key's values, subsequent operations will attempt to use the new n with the old, mismatched CRT factors. The rsa_encdec.c code selects CRT mode whenever ctx->key.p is non-NULL, causing incorrect cryptographic results.
**Fix**:
```
/* Always replace CRT parameters to clear stale values from previous key */
BN_Destroy(ctx->key.p);
ctx->key.p = tmpCtx.key.p;
tmpCtx.key.p = NULL;

BN_Destroy(ctx->key.q);
ctx->key.q = tmpCtx.key.q;
tmpCtx.key.q = NULL;

BN_Destroy(ctx->key.dP);
ctx->key.dP = tmpCtx.key.dP;
tmpCtx.key.dP = NULL;

BN_Destroy(ctx->key.dQ);
ctx->key.dQ = tmpCtx.key.dQ;
tmpCtx.key.dQ = NULL;

BN_Destroy(ctx->key.qInv);
ctx->key.qInv = tmpCtx.key.qInv;
tmpCtx.key.qInv = NULL;
```

---

### Loading private key without exponent e leaves mismatched public key in context
`crypto/rsa/src/rsa_keyop.c:159-203`
**Reviewers**: CODEX | **置信度**: 可信
```
/* All validation passed. Now atomically replace the private key fields in ctx.
 * Public key fields (n, e, mont, hasPubKey) are preserved. */
BN_Destroy(ctx->key.n);
ctx->key.n = tmpCtx.key.n;
tmpCtx.key.n = NULL;

BN_Destroy(ctx->key.d);
ctx->key.d = tmpCtx.key.d;
tmpCtx.key.d = NULL;

if (prv->e != NULL) {
    BN_Destroy(ctx->key.e);
    ctx->key.e = tmpCtx.key.e;
    tmpCtx.key.e = NULL;
}

/* Rebuild mont since n has changed */
BN_MontDestroy(ctx->key.mont);
ctx->key.mont = NULL;
if (ctx->key.hasPubKey && ctx->key.n != NULL) {
    ctx->key.mont = BN_MontCreate(ctx->key.n);
}
ctx->key.hasPrvKey = true;
```
**Issue**: n is always replaced when loading a private key, but e is only replaced when prv->e != NULL. The comment says "Public key fields (n, e, mont, hasPubKey) are preserved", but preserving e when n changes creates an invalid public key (n_new + e_old) that never existed. Subsequent calls to CRYPT_RSA_GetPubKey, public encrypt, or comparison will use this mismatched key material.
**Fix**:
```
BN_Destroy(ctx->key.n);
ctx->key.n = tmpCtx.key.n;
tmpCtx.key.n = NULL;

BN_Destroy(ctx->key.d);
ctx->key.d = tmpCtx.key.d;
tmpCtx.key.d = NULL;

BN_Destroy(ctx->key.e);
if (prv->e != NULL) {
    ctx->key.e = tmpCtx.key.e;
    tmpCtx.key.e = NULL;
    ctx->key.hasPubKey = true;
} else {
    ctx->key.e = NULL;
    ctx->key.hasPubKey = false;
}

BN_MontDestroy(ctx->key.mont);
ctx->key.mont = NULL;
if (ctx->key.hasPubKey) {
    ctx->key.mont = BN_MontCreate(ctx->key.n);
    if (ctx->key.mont == NULL) {
        ret = CRYPT_MEM_ALLOC_FAIL;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }
}

ctx->key.hasPrvKey = true;
```

---

### SetPubKey creates key inconsistency by not invalidating private key when replacing modulus n
`crypto/rsa/src/rsa_keyop.c:286-296`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
// Only replace public key fields; preserve existing private key fields
BN_Destroy(ctx->key.n);
ctx->key.n = newKey.n;
newKey.n = NULL;
BN_Destroy(ctx->key.e);
ctx->key.e = newKey.e;
newKey.e = NULL;
BN_MontDestroy(ctx->key.mont);
ctx->key.mont = newKey.mont;
newKey.mont = NULL;
ctx->key.hasPubKey = true;
return ret;
```
**Issue**: When SetPubKey is called on a context that already has a private key (hasPrvKey=true), it replaces the modulus n without clearing hasPrvKey or the private key fields (d, p, q, dP, dQ, qInv). Since n is shared between public and private key in the flat storage, this creates an inconsistent state where the private key fields were computed from the old n but the context now has a new n. Subsequent private key operations (decrypt/sign) will use inconsistent key material, producing incorrect results without any error indication.
**Fix**:
```
// Only replace public key fields; preserve existing private key fields
BN_Destroy(ctx->key.n);
ctx->key.n = newKey.n;
newKey.n = NULL;
BN_Destroy(ctx->key.e);
ctx->key.e = newKey.e;
newKey.e = NULL;
BN_MontDestroy(ctx->key.mont);
ctx->key.mont = newKey.mont;
newKey.mont = NULL;
ctx->key.hasPubKey = true;

/* The modulus n is shared between public and private key. When n is replaced,
 * the private key fields (d, p, q, dP, dQ, qInv) derived from the old n become invalid.
 * Clear hasPrvKey and free the private key fields to prevent use of inconsistent key material. */
if (ctx->key.hasPrvKey) {
    BN_Destroy(ctx->key.d);
    BN_Destroy(ctx->key.p);
    BN_Destroy(ctx->key.q);
    BN_Destroy(ctx->key.dP);
    BN_Destroy(ctx->key.dQ);
    BN_Destroy(ctx->key.qInv);
    ctx->key.d = ctx->key.p = ctx->key.q = NULL;
    ctx->key.dP = ctx->key.dQ = ctx->key.qInv = NULL;
    ctx->key.hasPrvKey = false;
}
return ret;
```

---


## Medium

### CRYPT_RSA_Cmp reports false equality for private-only contexts without exponent
`crypto/rsa/src/rsa_keyop.c:463-476`
**Reviewers**: CODEX | **置信度**: 可信
```
if (a->key.hasPrvKey && b->key.hasPrvKey) {
    RETURN_RET_IF(BN_Cmp(a->key.n, b->key.n) != 0 || BN_Cmp(a->key.e, b->key.e) != 0, CRYPT_RSA_PUBKEY_NOT_EQUAL);
    return CRYPT_SUCCESS;
}
if (a->key.hasPubKey && b->key.hasPubKey) {
    RETURN_RET_IF(BN_Cmp(a->key.n, b->key.n) != 0 || BN_Cmp(a->key.e, b->key.e) != 0, CRYPT_RSA_PUBKEY_NOT_EQUAL);
    return CRYPT_SUCCESS;
}
if (a->key.hasPrvKey && b->key.hasPubKey) {
    RETURN_RET_IF(BN_Cmp(a->key.n, b->key.n) != 0 || BN_Cmp(a->key.e, b->key.e) != 0, CRYPT_RSA_PUBKEY_NOT_EQUAL);
    return CRYPT_SUCCESS;
}
if (a->key.hasPubKey && b->key.hasPrvKey) {
    RETURN_RET_IF(BN_Cmp(a->key.n, b->key.n) != 0 || BN_Cmp(a->key.e, b->key.e) != 0, CRYPT_RSA_PUBKEY_NOT_EQUAL);
    return CRYPT_SUCCESS;
}
return CRYPT_RSA_NO_KEY_INFO;
```
**Issue**: In CRYPT_RSA_Cmp, when both contexts have hasPrvKey, the function compares n and e. If neither private key carries e (e is NULL), BN_Cmp(NULL, NULL) returns 0, causing two completely different private keys to be treated as equal. This is a false positive and behavioral regression from the old implementation which returned CRYPT_RSA_NO_KEY_INFO in such cases.
**Fix**:
```
if (a->key.hasPubKey && b->key.hasPubKey) {
    RETURN_RET_IF(BN_Cmp(a->key.n, b->key.n) != 0 ||
                  BN_Cmp(a->key.e, b->key.e) != 0,
                  CRYPT_RSA_PUBKEY_NOT_EQUAL);
    return CRYPT_SUCCESS;
}
/* Compare private key to public key: only if private key has e */
if (a->key.hasPrvKey && a->key.e != NULL && !BN_IsZero(a->key.e) && b->key.hasPubKey) {
    RETURN_RET_IF(BN_Cmp(a->key.n, b->key.n) != 0 ||
                  BN_Cmp(a->key.e, b->key.e) != 0,
                  CRYPT_RSA_PUBKEY_NOT_EQUAL);
    return CRYPT_SUCCESS;
}
if (a->key.hasPubKey && b->key.hasPrvKey && b->key.e != NULL && !BN_IsZero(b->key.e)) {
    RETURN_RET_IF(BN_Cmp(a->key.n, b->key.n) != 0 ||
                  BN_Cmp(a->key.e, b->key.e) != 0,
                  CRYPT_RSA_PUBKEY_NOT_EQUAL);
    return CRYPT_SUCCESS;
}
return CRYPT_RSA_NO_KEY_INFO;
```

---
