# Code Review: openHiTLS/sdf4j#24
**Reviewer**: CLAUDE


## High

### Incorrect method names in documentation example
`docs/开发指南.md:334-335`
```
ECCPublicKey sponsorPubKey = sponsorResult.getSponsorPubKey();
ECCPublicKey sponsorTmpPubKey = sponsorResult.getSponsorTmpPubKey();
...
ECCPublicKey responsePubKey = responseResult.getSponsorPubKey();
ECCPublicKey responseTmpPubKey = responseResult.getSponsorTmpPubKey();
```
**Issue**: The documentation uses non-existent method names getSponsorPubKey() and getSponsorTmpPubKey(). The actual method names in KeyAgreementResult are getPublicKey() and getTmpPublicKey(). Code copied from this documentation will fail to compile.
**Fix**:
```
ECCPublicKey sponsorPubKey = sponsorResult.getPublicKey();
ECCPublicKey sponsorTmpPubKey = sponsorResult.getTmpPublicKey();
...
ECCPublicKey responsePubKey = responseResult.getPublicKey();
ECCPublicKey responseTmpPubKey = responseResult.getTmpPublicKey();
```

---


## Medium

### Missing validation in HybridSignature.setL()
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridSignature.java:141-143`
```
public void setL(int l) {
        this.l = l;
    }
```
**Issue**: The setL() method does not validate that the input value is non-negative or consistent with sigM.length. Similar methods in ECCCipher.setL() and HybridCipher.setL1() perform this validation to prevent invalid state.
**Fix**:
```
public void setL(int l) {
        if (l < 0) {
            throw new IllegalArgumentException("Signature length cannot be negative");
        }
        if (sigM != null && l > sigM.length) {
            throw new IllegalArgumentException("Signature length cannot exceed data length");
        }
        this.l = l;
    }
```

---
