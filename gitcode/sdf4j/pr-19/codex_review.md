# Code Review: openHiTLS/sdf4j#19
**Reviewer**: CODEX


## High

### Error-path cleanup can dereference a null function pointer
`sdf4j/src/main/native/src/sdf_jni_keygen.c:518-520`
```
if (result == NULL) {
    g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)key_handle);
    THROW_SDF_EXCEPTION(env, 0x0100001C, "Failed to create KeyAgreementResult");
    return NULL;
}
```
**Issue**: On `KeyAgreementResult` creation failure, cleanup unconditionally calls `g_sdf_functions.SDF_DestroyKey`. If that symbol is not loaded, this becomes a native null-call crash while handling an error.
**Fix**:
```
if (result == NULL) {
    if (key_handle != 0 && g_sdf_functions.SDF_DestroyKey != NULL) {
        (void)g_sdf_functions.SDF_DestroyKey((HANDLE)sessionHandle, (HANDLE)key_handle);
    }
    THROW_SDF_EXCEPTION(env, 0x0100001C, "Failed to create KeyAgreementResult");
    return NULL;
}
```

---


## Medium

### Public ECC key-agreement APIs were changed incompatibly without compatibility overloads
`sdf4j/src/main/java/org/openhitls/sdf4j/SDF.java:507-508`
```
public native KeyAgreementResult SDF_GenerateAgreementDataWithECC(long sessionHandle, int keyIndex, int keyBits,
        byte[] sponsorID) throws SDFException;

public KeyAgreementResult SDF_GenerateAgreementDataAndKeyWithECC(
        long sessionHandle, int keyIndex, int keyBits,
        byte[] responseID, byte[] sponsorID,
        ECCPublicKey sponsorPublicKey, ECCPublicKey sponsorTmpPublicKey) throws SDFException {
    KeyAgreementResult result = SDF_GenerateAgreementDataAndKeyWithECC_Native(sessionHandle, keyIndex, keyBits,
                responseID, sponsorID, sponsorPublicKey, sponsorTmpPublicKey);
    ...
    return result;
}
```
**Issue**: The PR replaces existing public method signatures/return types for `SDF_GenerateAgreementDataWithECC` and `SDF_GenerateAgreementDataAndKeyWithECC`. Existing downstream code compiled against the old API will break (source and binary compatibility).
**Fix**:
```
@Deprecated
public long SDF_GenerateAgreementDataWithECC(
        long sessionHandle, int keyIndex, int keyBits,
        byte[] sponsorID, ECCPublicKey sponsorPublicKey,
        ECCPublicKey sponsorTmpPublicKey) throws SDFException {
    KeyAgreementResult result = SDF_GenerateAgreementDataWithECC(sessionHandle, keyIndex, keyBits, sponsorID);
    copyEccPublicKey(result.getPublicKey(), sponsorPublicKey);
    copyEccPublicKey(result.getTmpPublicKey(), sponsorTmpPublicKey);
    return result.getAgreementHandle();
}

@Deprecated
public long SDF_GenerateAgreementDataAndKeyWithECC(
        long sessionHandle, int keyIndex, int keyBits,
        byte[] responseID, byte[] sponsorID,
        ECCPublicKey sponsorPublicKey, ECCPublicKey sponsorTmpPublicKey,
        ECCPublicKey responsePublicKey, ECCPublicKey responseTmpPublicKey) throws SDFException {
    KeyAgreementResult result = SDF_GenerateAgreementDataAndKeyWithECC(
            sessionHandle, keyIndex, keyBits, responseID, sponsorID, sponsorPublicKey, sponsorTmpPublicKey);
    copyEccPublicKey(result.getPublicKey(), responsePublicKey);
    copyEccPublicKey(result.getTmpPublicKey(), responseTmpPublicKey);
    return result.getAgreementHandle();
}

private static void copyEccPublicKey(ECCPublicKey src, ECCPublicKey dst) {
    if (src != null && dst != null) {
        dst.setBits(src.getBits());
        dst.setX(src.getX());
        dst.setY(src.getY());
    }
}
```

---


## Low

### Handle naming is ambiguous and mismatches actual semantics in 6.3.14 flow
`sdf4j/src/main/java/org/openhitls/sdf4j/types/KeyAgreementResult.java:24-39`
```
private long agreementHandle;

public long getAgreementHandle() {
    return agreementHandle;
}
```
**Issue**: The class exposes only `agreementHandle`, but in `SDF_GenerateAgreementDataAndKeyWithECC` this value is actually a key handle. This naming mismatch causes API misuse risk and contradicts method intent.
**Fix**:
```
private long handle;

public KeyAgreementResult(long handle, ECCPublicKey publicKey, ECCPublicKey tmpPublicKey) {
    this.handle = handle;
    this.publicKey = publicKey;
    this.tmpPublicKey = tmpPublicKey;
}

/** 6.3.12 usage */
public long getAgreementHandle() {
    return handle;
}

/** 6.3.14 usage */
public long getKeyHandle() {
    return handle;
}
```

---
