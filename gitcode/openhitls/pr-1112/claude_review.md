# Code Review: openHiTLS/openhitls#1112
**Reviewer**: CLAUDE


## High

### Memory leak in DupMdCtx on partial duplication failure
`crypto/slh_dsa/src/slh_dsa_hash.c:137-143`
```
void DupMdCtx(CryptSlhDsaCtx *dest, CryptSlhDsaCtx *src)
{
    const EAL_MdMethod *hashMethod256 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    const EAL_MdMethod *hashMethod512 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA512);
    dest->sha256MdCtx = hashMethod256->dupCtx(src->sha256MdCtx);
    dest->sha512MdCtx = hashMethod512->dupCtx(src->sha512MdCtx);
}
```
**Issue**: If hashMethod256->dupCtx succeeds but hashMethod512->dupCtx fails, the first duplicated context (dest->sha256MdCtx) is leaked. The function does not clean up the partially duplicated state before returning.
**Fix**:
```
void DupMdCtx(CryptSlhDsaCtx *dest, CryptSlhDsaCtx *src)
{
    const EAL_MdMethod *hashMethod256 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA256);
    const EAL_MdMethod *hashMethod512 = EAL_MdFindDefaultMethod(CRYPT_MD_SHA512);
    dest->sha256MdCtx = hashMethod256->dupCtx(src->sha256MdCtx);
    if (dest->sha256MdCtx == NULL) {
        return; // Early return on first failure
    }
    dest->sha512MdCtx = hashMethod512->dupCtx(src->sha512MdCtx);
    if (dest->sha512MdCtx == NULL) {
        // Clean up the first context on second failure
        hashMethod256->freeCtx(dest->sha256MdCtx);
        dest->sha256MdCtx = NULL;
    }
}
```

---


## Medium

### FreeMdCtx calls freeCtx without NULL check
`crypto/slh_dsa/src/slh_dsa_hash.c:145-155`
```
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
**Issue**: The function calls hashMethod->freeCtx on ctx->sha256MdCtx and ctx->sha512MdCtx without checking if they are NULL first. While some implementations may handle NULL gracefully, it's not guaranteed by all hash method implementations.
**Fix**:
```
void FreeMdCtx(CryptSlhDsaCtx *ctx)
{
    if (ctx->para.isCompressed) {
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
}
```

---


## Low

### Fragile context duplication condition in CRYPT_SLH_DSA_DupCtx
`crypto/slh_dsa/src/slh_dsa.c:363-369`
```
if (ctx->sha256MdCtx != NULL && ctx->sha512MdCtx != NULL) {
        DupMdCtx(newCtx, ctx);
        if (newCtx->sha256MdCtx == NULL || newCtx->sha512MdCtx == NULL) {
            CRYPT_SLH_DSA_FreeCtx(newCtx);
            return NULL;
        }
    }
```
**Issue**: The condition `ctx->sha256MdCtx != NULL && ctx->sha512MdCtx != NULL` only triggers duplication when BOTH are non-NULL. While this should theoretically always be the case for compressed mode, if an inconsistent state occurs (one NULL, one non-NULL), the duplication is silently skipped. This could lead to the newCtx having uninitialized contexts while being used.
**Fix**:
```
// In compressed mode, both contexts should be initialized together
    // Use ctx->para.isCompressed to determine if duplication is needed
    if (ctx->para.isCompressed) {
        DupMdCtx(newCtx, ctx);
        if (newCtx->sha256MdCtx == NULL || newCtx->sha512MdCtx == NULL) {
            CRYPT_SLH_DSA_FreeCtx(newCtx);
            return NULL;
        }
    }
```

---

### Magic number 18 for hash address offset is fragile
`crypto/slh_dsa/src/slh_dsa_hash.c:409`
```
PUT_UINT32_BE(start + i, (uint8_t *)sha256Ctx->block, 18); // 18 = layerAddrLen + treeAddrLen + typeLen + hashAddressOffset = 1 + 8 + 1 + 8
```
**Issue**: The hardcoded offset 18 is used to write the hash address in the block buffer. While the comment explains the calculation (layerAddrLen + treeAddrLen + typeLen + hashAddressOffset = 1 + 8 + 1 + 8), this magic number is fragile and could break if the address structure changes. The offset should be derived from constants or calculated dynamically.
**Fix**:
```
// Define compressed address layout constants
#define SLH_DSA_CADRS_LAYER_ADDR_LEN   1
#define SLH_DSA_CADRS_TREE_ADDR_LEN    8
#define SLH_DSA_CADRS_TYPE_LEN         1
#define SLH_DSA_CADRS_HASH_ADDR_OFFSET 8
#define SLH_DSA_CADRS_HASH_ADDR_BYTE_OFFSET \
    (SLH_DSA_CADRS_LAYER_ADDR_LEN + SLH_DSA_CADRS_TREE_ADDR_LEN + \
     SLH_DSA_CADRS_TYPE_LEN + SLH_DSA_CADRS_HASH_ADDR_OFFSET)

// In ChainSha256 function:
        PUT_UINT32_BE(start + i, (uint8_t *)sha256Ctx->block, SLH_DSA_CADRS_HASH_ADDR_BYTE_OFFSET);
```

---
