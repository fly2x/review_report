# Code Review: openHiTLS/openhitls#993
**Reviewer**: CODEX


## High

### XmssAdrs_SetType leaves stale fields in address
`crypto/xmss/src/xmss_address.c:34-36`
```
void XmssAdrs_SetType(XmssAdrs *adrs, uint32_t type)
{
    PUT_UINT32_BE(type, adrs->fields.type, 0);
}
```
**Issue**: XmssAdrs_SetType only writes the type field and does not clear the type-specific portion (bytes 16–31). This leaves stale keyPair/chain/hash/keyAndMask values when switching address types, breaking RFC 8391 domain separation and producing incorrect hashes/signatures/verification results.
**Fix**:
```
void XmssAdrs_SetType(XmssAdrs *adrs, uint32_t type)
{
    PUT_UINT32_BE(type, adrs->fields.type, 0);
    (void)memset_s(adrs->fields.keyPairAddr, sizeof(adrs->fields.keyPairAddr), 0,
                   sizeof(adrs->fields.keyPairAddr));
    (void)memset_s(adrs->fields.chainAddr, sizeof(adrs->fields.chainAddr), 0,
                   sizeof(adrs->fields.chainAddr));
    (void)memset_s(adrs->fields.hashAddr, sizeof(adrs->fields.hashAddr), 0,
                   sizeof(adrs->fields.hashAddr));
    (void)memset_s(adrs->fields.keyAndMask, sizeof(adrs->fields.keyAndMask), 0,
                   sizeof(adrs->fields.keyAndMask));
}
```

---


## Medium

### Verification accepts oversized signatures
`crypto/xmss/src/xmss_core.c:176-182`
```
if (sigLen < ctx->params.sigBytes) {
    BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
    return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
}
```
**Issue**: Verification only rejects signatures shorter than the expected size and accepts longer buffers, which allows trailing garbage/malleability and deviates from fixed-length XMSS signatures.
**Fix**:
```
if (sigLen != ctx->params.sigBytes) {
    BSL_ERR_PUSH_ERROR(CRYPT_XMSS_ERR_INVALID_SIG_LEN);
    return CRYPT_XMSS_ERR_INVALID_SIG_LEN;
}
```

---
