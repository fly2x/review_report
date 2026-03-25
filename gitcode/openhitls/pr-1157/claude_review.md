# Code Review: openHiTLS/openhitls#1157
**Reviewer**: CLAUDE


## High

### SetPubKey creates key inconsistency by not invalidating private key when replacing modulus n
`crypto/rsa/src/rsa_keyop.c:286-296`
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
**Issue**: When SetPubKey is called on a context that already has a private key (hasPrvKey=true), it replaces the modulus n without clearing hasPrvKey or the private key fields (d, p, q, dP, dQ, qInv). This creates an inconsistent state where the private key fields were computed from the old n but the context now has a new n. Subsequent private key operations (decrypt/sign) will use inconsistent key material, producing incorrect results without any error indication.
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
