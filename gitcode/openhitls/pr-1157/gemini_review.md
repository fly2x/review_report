# Code Review: openHiTLS/openhitls#1157
**Reviewer**: GEMINI


## High

### Stale CRT parameters retained when setting new private key without factors
`crypto/rsa/src/rsa_keyop.c:174-194`
```
if (prv->p != NULL) {
        BN_Destroy(ctx->key.p);
        ctx->key.p = tmpCtx.key.p;
        ctx->key.p = NULL;

        BN_Destroy(ctx->key.q);
        ctx->key.q = tmpCtx.key.q;
        ctx->key.q = NULL;

        BN_Destroy(ctx->key.dP);
        ctx->key.dP = tmpCtx.key.dP;
        ctx->key.dP = NULL;

        BN_Destroy(ctx->key.dQ);
        ctx->key.dQ = tmpCtx.key.dQ;
        ctx->key.dQ = NULL;

        BN_Destroy(ctx->key.qInv);
        ctx->key.qInv = tmpCtx.key.qInv;
        ctx->key.qInv = NULL;
    }
```
**Issue**: When setting a new private key (`CRYPT_RSA_SetPrvKey`) that does not include CRT parameters (`prv->p == NULL`), the code conditionally skips replacing the `p`, `q`, `dP`, `dQ`, and `qInv` fields in `ctx->key`. This leaves the old CRT components from any previously set private key in the context. Since `n` and `d` are unconditionally updated to the new key's values, subsequent operations (like decryption or signing) will attempt to use the new `n` and `d` with the old, mismatched CRT factors, leading to incorrect cryptographic results or failures.
**Fix**:
```
BN_Destroy(ctx->key.p);
    ctx->key.p = tmpCtx.key.p;
    ctx->key.p = NULL;

    BN_Destroy(ctx->key.q);
    ctx->key.q = tmpCtx.key.q;
    ctx->key.q = NULL;

    BN_Destroy(ctx->key.dP);
    ctx->key.dP = tmpCtx.key.dP;
    ctx->key.dP = NULL;

    BN_Destroy(ctx->key.dQ);
    ctx->key.dQ = tmpCtx.key.dQ;
    ctx->key.dQ = NULL;

    BN_Destroy(ctx->key.qInv);
    ctx->key.qInv = tmpCtx.key.qInv;
    ctx->key.qInv = NULL;
```

---
