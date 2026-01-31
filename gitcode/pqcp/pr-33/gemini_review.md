# Code Review: openhitls/pqcp#33
**Reviewer**: GEMINI


## Critical

### Incorrect buffer pointer arithmetic and initialization
`src/composite_sign/src/crypt_composite_sign.c:389`
```
BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data, + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
    RETURN_RET_IF_ERR(CRYPT_CompositeSetPqcPrvKey(ctx, &pqcPrv), ret);
```
**Issue**: The initialization of `tradPrv` uses the comma operator incorrectly within the brace initializer, or attempts to initialize 3 fields when `BSL_Buffer` likely has 2. Critically, `tradPrv.data` is initialized to `prv->data` (the start of the buffer) instead of the offset pointer. This causes the traditional private key to be set using the PQC private key data.
**Fix**:
```
BSL_Buffer pqcPrv = {prv->data, ctx->info->pqcPrvkeyLen};
    BSL_Buffer tradPrv = {prv->data + ctx->info->pqcPrvkeyLen, prv->len - ctx->info->pqcPrvkeyLen};
    RETURN_RET_IF_ERR(CRYPT_CompositeSetPqcPrvKey(ctx, &pqcPrv), ret);
```

---


## Low

### Missing break statement in switch case
`src/provider/pqcp_pkey.c:46-49`
```
case CRYPT_PKEY_COMPOSITE_SIGN:
            pkeyCtx = CRYPT_COMPOSITE_NewCtx();
        default:
            break;
```
**Issue**: The `CRYPT_PKEY_COMPOSITE_SIGN` case falls through to the `default` case. While the `default` case contains a `break`, relying on this fallthrough is fragile and considered bad practice.
**Fix**:
```
case CRYPT_PKEY_COMPOSITE_SIGN:
            pkeyCtx = CRYPT_COMPOSITE_NewCtx();
            break;
        default:
            break;
```

---

### Duplicate const qualifier
`src/provider/pqcp_pkey.c:147`
```
const const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```
**Issue**: The variable `g_pqcpKeyMgmtCompositeSign` is declared with `const const`. This is redundant.
**Fix**:
```
const CRYPT_EAL_Func g_pqcpKeyMgmtCompositeSign[] = {
```

---
