# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1157
- Title: 

## Individual Review Reports

## CLAUDE Review

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


---

## CODEX Review

# Code Review: openHiTLS/openhitls#1157
**Reviewer**: CODEX


## High

### Replacing an RSA private key can leave stale CRT parameters active
`crypto/rsa/src/rsa_keyop.c:175-195`
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
**Issue**: The new flat-key update path only copies `p/q/dP/dQ/qInv` when the incoming key includes `p`. If the context previously held a CRT-capable key and the caller loads an `n,d`-only private key, the old CRT factors stay in `ctx->key`. `rsa_encdec.c` now selects CRT whenever `ctx->key.p` is nonzero, so later decrypt/sign operations will run with CRT data from the previous key instead of falling back to plain `d mod n`.
**Fix**:
```
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

### Loading a private key without e can leave a mismatched public key in the context
`crypto/rsa/src/rsa_keyop.c:159-203`
```
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
**Issue**: `n` is always replaced, but `e` is only replaced when `prv->e != NULL`, while `hasPubKey` is preserved. If the context already has a public key and a different private key is loaded without `e`, the shared public half becomes `n_new + e_old`. After that, `CRYPT_RSA_GetPubKey`, `CRYPT_RSA_PubEnc`, comparison, and any exported public material use a public key that never existed.
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

### SetPubKey can silently invalidate an existing private key
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
```
**Issue**: With the new flat storage, `n/e` are shared by both halves of the key. This block overwrites them even when `hasPrvKey` is already set, but it leaves `d/p/q/dP/dQ/qInv` untouched. A context that previously held a private key can therefore end up with `n/e` from one key and private factors from another, and private decrypt/sign operations will still proceed because `hasPrvKey` stays true.
**Fix**:
```
if (ctx->key.hasPrvKey &&
        (ctx->key.n == NULL || BN_Cmp(ctx->key.n, newKey.n) != 0 ||
         (ctx->key.e != NULL && BN_Cmp(ctx->key.e, newKey.e) != 0))) {
        ret = CRYPT_RSA_ERR_INPUT_VALUE;
        BSL_ERR_PUSH_ERROR(ret);
        goto ERR;
    }

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
```

---


## Medium

### CRYPT_RSA_Cmp now reports equality for private-only contexts
`crypto/rsa/src/rsa_keyop.c:463-476`
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
```
**Issue**: `CRYPT_RSA_Cmp` is supposed to compare public keys, but the new first branch returns `CRYPT_SUCCESS` when both contexts only have `hasPrvKey`. If neither private key carries `e`, `BN_Cmp(NULL, NULL)` returns 0, so two contexts with no public key are treated as equal. This is a false positive and a behavioral regression from the old implementation, which returned `CRYPT_RSA_NO_KEY_INFO` in that case.
**Fix**:
```
if (a->key.hasPubKey && b->key.hasPubKey) {
        RETURN_RET_IF(BN_Cmp(a->key.n, b->key.n) != 0 ||
                      BN_Cmp(a->key.e, b->key.e) != 0,
                      CRYPT_RSA_PUBKEY_NOT_EQUAL);
        return CRYPT_SUCCESS;
    }
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


---

## GEMINI Review

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


## Your Task

1. **Analyze All Reports**
   - Read each reviewer's findings carefully
   - Identify duplicate issues reported by multiple reviewers
   - Note issues unique to each reviewer

2. **Validate Issues**
   - For each issue, verify it's a real problem by checking the file (code or docs)
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
- Only include issues you've verified in the changed files (code or docs)
- Prefer fixes that are most complete and correct
- Add REVIEWERS field showing which AIs found this issue

## CRITICAL OUTPUT REQUIREMENT

You MUST output each issue in the exact ===ISSUE===...===END=== format shown above.
Do NOT output summary tables or prose descriptions.
Each issue MUST be a separate ===ISSUE=== block.
If there are 5 validated issues, output 5 ===ISSUE=== blocks.

Start consolidation now. Output each validated issue in the required format.
