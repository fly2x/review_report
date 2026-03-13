# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/sdf4j
- PR: #24
- Title: 

## Individual Review Reports

## CLAUDE Review

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


---

## CODEX Review

# Code Review: openHiTLS/sdf4j#24
**Reviewer**: CODEX


## High

### Renaming the example to *Test makes the default build require a live SDF environment
`examples/src/test/java/org/openhitls/SM3ExampleTest.java:29-41`
```
public class SM3ExampleTest {

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
    }
```
**Issue**: Renaming this class into Surefire’s default `*Test` pattern means `mvn test` now executes it automatically, but `setUp()` unconditionally loads the vendor library and opens a device. On any machine without a configured SDF library/device, the examples module fails instead of skipping. The same regression was introduced by the matching renames in `SM2ExampleTest` and `SM4ExampleTest`.
**Fix**:
```
import org.junit.Assume;

public class SM3ExampleTest {

    @Before
    public void setUp() {
        try {
            sdf = new SDF();
            deviceHandle = sdf.SDF_OpenDevice();
            sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        } catch (UnsatisfiedLinkError | SDFException e) {
            Assume.assumeNoException("Requires configured SDF library and device", e);
        }
    }
```

---


## Medium

### tearDown releases KEK access even when setUp never acquired it
`examples/src/test/java/org/openhitls/SM4ExampleTest.java:65-78`
```
sdf.SDF_GetKEKAccessRight(sessionHandle, KEY_INDEX, KEY_PASSWORD);
KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(sessionHandle, SM4_KEY_BITS, AlgorithmID.SGD_SM4_ECB, KEY_INDEX);
ecbKeyHandle = result.getKeyHandle();

...

if (sessionHandle != 0) {
    sdf.SDF_ReleaseKEKAccessRight(sessionHandle, KEY_INDEX);
    sdf.SDF_CloseSession(sessionHandle);
}
```
**Issue**: JUnit runs `@After` even when `@Before` fails. If `SDF_GetKEKAccessRight()` or `SDF_GenerateKeyWithKEK()` throws, `sessionHandle` is already non-zero but no KEK access right may have been granted. `tearDown()` then calls `SDF_ReleaseKEKAccessRight()` unconditionally and can replace the original setup failure with a secondary cleanup error.
**Fix**:
```
private boolean kekAccessGranted;

@Before
public void setUp() throws SDFException {
    sdf = new SDF();
    deviceHandle = sdf.SDF_OpenDevice();
    sessionHandle = sdf.SDF_OpenSession(deviceHandle);
    loadConfig();

    sdf.SDF_GetKEKAccessRight(sessionHandle, KEY_INDEX, KEY_PASSWORD);
    kekAccessGranted = true;

    KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(
            sessionHandle, SM4_KEY_BITS, AlgorithmID.SGD_SM4_ECB, KEY_INDEX);
    ecbKeyHandle = result.getKeyHandle();
}

@After
public void tearDown() throws SDFException {
    if (sdf != null) {
        if (ecbKeyHandle != 0) {
            sdf.SDF_DestroyKey(sessionHandle, ecbKeyHandle);
        }
        if (sessionHandle != 0) {
            if (kekAccessGranted) {
                sdf.SDF_ReleaseKEKAccessRight(sessionHandle, KEY_INDEX);
            }
            sdf.SDF_CloseSession(sessionHandle);
        }
        if (deviceHandle != 0) {
            sdf.SDF_CloseDevice(deviceHandle);
        }
    }
}
```

---

### Quick-start library-loading instructions use unsupported keys and the wrong path format
`docs/开发指南.md:68-87`
```
#### 方式一：Java系统属性
java -Dsdf4j.library.path=/usr/lib/libsdfx.so -jar your-app.jar

#### 方式二：配置文件
library.name=sdfx
library.search.paths=/usr/lib:/usr/local/lib

#### 方式三：环境变量
export SDF_LIBRARY_PATH=/usr/lib/libsdfx.so
```
**Issue**: The loader requires both a library name and a directory path (`sdf4j.library.name` + `sdf4j.library.path`, `library.name` + `library.path`, or `SDF_LIBRARY_NAME` + `SDF_LIBRARY_PATH`). The new guide shows only a full `.so` path and even uses `library.search.paths`, which the implementation never reads. Following these snippets will produce `UnsatisfiedLinkError`.
**Fix**:
```
#### 方式一：Java系统属性
java -Dsdf4j.library.name=sdfx -Dsdf4j.library.path=/usr/lib -jar your-app.jar

#### 方式二：配置文件
library.name=sdfx
library.path=/usr/lib

#### 方式三：环境变量
export SDF_LIBRARY_NAME=sdfx
export SDF_LIBRARY_PATH=/usr/lib
```

---

### Capability detector example cannot compile because the block lambdas resolve to Runnable
`docs/测试指南.md:183-190`
```
capabilities.put("Hash_SM3", checkFunction(() -> {
    sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
    sdf.SDF_HashUpdate(sessionHandle, new byte[16]);
    sdf.SDF_HashFinal(sessionHandle);
}));
capabilities.put("HMAC", checkFunction(() -> {
    sdf.SDF_HMACInit(sessionHandle, 0, AlgorithmID.SGD_SM3);
}));

...

private boolean checkFunction(Runnable func) {
    try {
        func.run();
        return true;
    } catch (SDFException e) {
        return e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT;
    } catch (Exception e) {
        return false;
    }
}
```
**Issue**: These block lambdas do not return a value, so overload resolution picks `checkFunction(Runnable)`. `Runnable.run()` cannot throw `SDFException`, which makes the `Hash_SM3` and `HMAC` examples uncompilable, and the `catch (SDFException e)` inside the `Runnable` overload is itself invalid Java.
**Fix**:
```
capabilities.put("Hash_SM3", checkFunction(() -> {
    sdf.SDF_HashInit(sessionHandle, AlgorithmID.SGD_SM3, null, null);
    sdf.SDF_HashUpdate(sessionHandle, new byte[16]);
    sdf.SDF_HashFinal(sessionHandle);
    return null;
}));
capabilities.put("HMAC", checkFunction(() -> {
    sdf.SDF_HMACInit(sessionHandle, 0, AlgorithmID.SGD_SM3);
    return null;
}));

private boolean checkFunction(Callable<?> func) {
    try {
        func.call();
        return true;
    } catch (SDFException e) {
        return e.getErrorCode() != ErrorCode.SDR_NOTSUPPORT;
    } catch (Exception e) {
        return false;
    }
}
```

---


## Low

### Key agreement example calls getters that do not exist
`docs/开发指南.md:334-348`
```
ECCPublicKey sponsorPubKey = sponsorResult.getSponsorPubKey();
ECCPublicKey sponsorTmpPubKey = sponsorResult.getSponsorTmpPubKey();

...

ECCPublicKey responsePubKey = responseResult.getSponsorPubKey();
ECCPublicKey responseTmpPubKey = responseResult.getSponsorTmpPubKey();
```
**Issue**: `KeyAgreementResult` only exposes `getPublicKey()` and `getTmpPublicKey()`. The new guide uses `getSponsorPubKey()` and `getSponsorTmpPubKey()`, so the sample code does not compile.
**Fix**:
```
ECCPublicKey sponsorPubKey = sponsorResult.getPublicKey();
ECCPublicKey sponsorTmpPubKey = sponsorResult.getTmpPublicKey();

...

ECCPublicKey responsePubKey = responseResult.getPublicKey();
ECCPublicKey responseTmpPubKey = responseResult.getTmpPublicKey();
```

---

### Capability detector uses a non-existent SDF_GenerateAgreementDataWithECC overload
`docs/测试指南.md:196-198`
```
capabilities.put("KeyAgreement_ECC", checkFunction(() ->
    sdf.SDF_GenerateAgreementDataWithECC(sessionHandle, 1, 128,
        new byte[16], null, null)));
```
**Issue**: `SDF_GenerateAgreementDataWithECC` takes four arguments, but the guide calls it with six. Anyone copying the sample gets a compile error instead of a usable detector.
**Fix**:
```
capabilities.put("KeyAgreement_ECC", checkFunction(() ->
    sdf.SDF_GenerateAgreementDataWithECC(sessionHandle, 1, 128, new byte[16])));
```

---

### Javadoc failures are ignored while the script still reports success
`script/build_with_simulator.sh:64-68`
```
mvn clean package \
    -Dsdf.library.name=$SDFX_LIB_NAME \
    -Dsdf.library.path=$SDFX_BUILD_DIR || exit 1
mvn javadoc:javadoc -pl sdf4j
echo "SDF4J built successfully."
```
**Issue**: The new `mvn javadoc:javadoc` step is not checked for failure. If Javadoc generation breaks, the script still prints `SDF4J built successfully.` and exits as if the full build passed.
**Fix**:
```
mvn clean package \
    -Dsdf.library.name=$SDFX_LIB_NAME \
    -Dsdf.library.path=$SDFX_BUILD_DIR || exit 1
mvn javadoc:javadoc -pl sdf4j || exit 1
echo "SDF4J built successfully."
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
