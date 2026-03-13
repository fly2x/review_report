# Code Review: openHiTLS/openhitls#1112
**Reviewer**: CODEX


## High

### New SHA2 cache is initialized only for `Set*KeyEx`
`crypto/slh_dsa/src/slh_dsa.c:1038-1060`
```
(void)memcpy_s(ctx->prvKey.pub.seed, ctx->para.n, pub.pubSeed->value, ctx->para.n);
(void)memcpy_s(ctx->prvKey.pub.root, ctx->para.n, pub.pubRoot->value, ctx->para.n);
ret = InitMdCtx(ctx);
if (ret != CRYPT_SUCCESS) {
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}
ctx->keyType |= SLH_DSA_PUBKEY;
...
(void)memcpy_s(ctx->prvKey.seed, sizeof(ctx->prvKey.seed), prv.prvSeed->value, ctx->para.n);
(void)memcpy_s(ctx->prvKey.prf, sizeof(ctx->prvKey.prf), prv.prvPrf->value, ctx->para.n);
(void)memcpy_s(ctx->prvKey.pub.seed, sizeof(ctx->prvKey.pub.seed), prv.pubSeed->value, ctx->para.n);
(void)memcpy_s(ctx->prvKey.pub.root, sizeof(ctx->prvKey.pub.root), prv.pubRoot->value, ctx->para.n);
ret = InitMdCtx(ctx);
if (ret != CRYPT_SUCCESS) {
    BSL_ERR_PUSH_ERROR(ret);
    return ret;
}
ctx->keyType |= SLH_DSA_PRVKEY;
```
**Issue**: The PR makes the SHA2-compressed SLH-DSA hash path depend on `ctx->sha256MdCtx`/`ctx->sha512MdCtx`, but these changed lines only initialize that cache in `CRYPT_SLH_DSA_SetPubKeyEx` and `CRYPT_SLH_DSA_SetPrvKeyEx`. The legacy public APIs `CRYPT_SLH_DSA_SetPubKey` and `CRYPT_SLH_DSA_SetPrvKey` were left unchanged, so importing a SHA2-based key through those APIs now leaves the context unusable for sign/verify/pair-check on the first cached hash operation.
**Fix**:
```
int32_t CRYPT_SLH_DSA_SetPubKey(CryptSlhDsaCtx *ctx, const CRYPT_SlhDsaPub *pub)
{
    int32_t ret = PubKeyCheck(ctx, pub);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    (void)memcpy_s(ctx->prvKey.pub.seed, ctx->para.n, pub->seed, ctx->para.n);
    (void)memcpy_s(ctx->prvKey.pub.root, ctx->para.n, pub->root, ctx->para.n);

    ret = InitMdCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ctx->keyType |= SLH_DSA_PUBKEY;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_SLH_DSA_SetPrvKey(CryptSlhDsaCtx *ctx, const CRYPT_SlhDsaPrv *prv)
{
    int32_t ret = PrvKeyCheck(ctx, prv);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    (void)memcpy_s(ctx->prvKey.seed, sizeof(ctx->prvKey.seed), prv->seed, ctx->para.n);
    (void)memcpy_s(ctx->prvKey.prf, sizeof(ctx->prvKey.prf), prv->prf, ctx->para.n);
    (void)memcpy_s(ctx->prvKey.pub.seed, sizeof(ctx->prvKey.pub.seed), prv->pub.seed, ctx->para.n);
    (void)memcpy_s(ctx->prvKey.pub.root, sizeof(ctx->prvKey.pub.root), prv->pub.root, ctx->para.n);

    ret = InitMdCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    ctx->keyType |= SLH_DSA_PRVKEY;
    return CRYPT_SUCCESS;
}
```

---

### `DupCtx` can free the source hash cache on an earlier allocation failure
`crypto/slh_dsa/src/slh_dsa.c:363-367`
```
if (ctx->addrand != NULL) {
    newCtx->addrand = BSL_SAL_Dump(ctx->addrand, ctx->addrandLen);
    if (newCtx->addrand == NULL) {
        CRYPT_SLH_DSA_FreeCtx(newCtx);
        return NULL;
    }
}
if (ctx->sha256MdCtx != NULL && ctx->sha512MdCtx != NULL) {
    DupMdCtx(newCtx, ctx);
    if (newCtx->sha256MdCtx == NULL || newCtx->sha512MdCtx == NULL) {
        CRYPT_SLH_DSA_FreeCtx(newCtx);
        return NULL;
    }
}
```
**Issue**: `memcpy_s(newCtx, ..., ctx, ...)` copies `sha256MdCtx` and `sha512MdCtx` from the source before any deep-copying happens. These changed lines duplicate the md contexts only after the `context` and `addrand` dumps succeed, so if either dump fails, `CRYPT_SLH_DSA_FreeCtx(newCtx)` runs while `newCtx->sha*MdCtx` still alias the source object. That frees the original context's cache and turns the source into a dangling-pointer / double-free hazard.
**Fix**:
```
(void)memcpy_s(newCtx, sizeof(CryptSlhDsaCtx), ctx, sizeof(CryptSlhDsaCtx));
newCtx->context = NULL;
newCtx->addrand = NULL;
newCtx->sha256MdCtx = NULL;
newCtx->sha512MdCtx = NULL;

if (ctx->sha256MdCtx != NULL && ctx->sha512MdCtx != NULL) {
    DupMdCtx(newCtx, ctx);
    if (newCtx->sha256MdCtx == NULL || newCtx->sha512MdCtx == NULL) {
        CRYPT_SLH_DSA_FreeCtx(newCtx);
        return NULL;
    }
}

if (ctx->context != NULL) {
    newCtx->context = BSL_SAL_Dump(ctx->context, ctx->contextLen);
    if (newCtx->context == NULL) {
        CRYPT_SLH_DSA_FreeCtx(newCtx);
        return NULL;
    }
}
if (ctx->addrand != NULL) {
    newCtx->addrand = BSL_SAL_Dump(ctx->addrand, ctx->addrandLen);
    if (newCtx->addrand == NULL) {
        CRYPT_SLH_DSA_FreeCtx(newCtx);
        return NULL;
    }
}
```

---


## Low

### Cached digest contexts leak when the ctx is switched from SHA2 to SHAKE
`crypto/slh_dsa/src/slh_dsa_hash.c:130-153`
```
} else {
        ctx->sha256MdCtx = NULL;
        ctx->sha512MdCtx = NULL;
    }
    return ret;
}

void FreeMdCtx(CryptSlhDsaCtx *ctx)
{
    if (ctx->para.isCompressed) {
        const EAL_MdMethod *hashMethod256 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
        const EAL_MdMethod *hashMethod512 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA512);
        hashMethod256->freeCtx(ctx->sha256MdCtx);
        hashMethod512->freeCtx(ctx->sha512MdCtx);
        ctx->sha256MdCtx = NULL;
        ctx->sha512MdCtx = NULL;
    }
}
```
**Issue**: Cache cleanup is tied to `ctx->para.isCompressed` instead of the actual ownership of `sha256MdCtx`/`sha512MdCtx`. If a caller reuses one context and changes the parameter ID from a SHA2 SLH-DSA variant to a SHAKE variant, the `else` branch just drops the pointers and `FreeMdCtx` stops freeing them because `isCompressed` is now false. Reconfiguring a context across algorithm families therefore leaks both cached md contexts.
**Fix**:
```
int32_t InitMdCtx(CryptSlhDsaCtx *ctx)
{
    int32_t ret = CRYPT_SUCCESS;

    FreeMdCtx(ctx);
    if (!ctx->para.isCompressed) {
        return CRYPT_SUCCESS;
    }

    uint32_t n = ctx->para.n;
    uint8_t padding[SHA512_PADDING_LEN] = {0};
    const CRYPT_ConstData hashData256[] = {{ctx->prvKey.pub.seed, n}, {padding, SHA256_PADDING_LEN - n}};
    const EAL_MdMethod *hashMethod256 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    ret = CreateMdCtxAndUpdata(&ctx->sha256MdCtx, hashMethod256, hashData256,
                               sizeof(hashData256) / sizeof(hashData256[0]));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    const CRYPT_ConstData hashData512[] = {{ctx->prvKey.pub.seed, n}, {padding, SHA512_PADDING_LEN - n}};
    const EAL_MdMethod *hashMethod512 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA512);
    ret = CreateMdCtxAndUpdata(&ctx->sha512MdCtx, hashMethod512, hashData512,
                               sizeof(hashData512) / sizeof(hashData512[0]));
    if (ret != CRYPT_SUCCESS) {
        hashMethod256->freeCtx(ctx->sha256MdCtx);
        ctx->sha256MdCtx = NULL;
    }
    return ret;
}

void FreeMdCtx(CryptSlhDsaCtx *ctx)
{
    const EAL_MdMethod *hashMethod256 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    const EAL_MdMethod *hashMethod512 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA512);

    if (ctx->sha256MdCtx != NULL) {
        hashMethod256->freeCtx(ctx->sha256MdCtx);
        ctx->sha256MdCtx = NULL;
    }
    if (ctx->sha512MdCtx != NULL) {
        hashMethod512->freeCtx(ctx->sha512MdCtx);
        ctx->sha512MdCtx = NULL;
    }
}
```

---
