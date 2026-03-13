# Code Review: openHiTLS/sdf4j#24
**Reviewer**: CLAUDE


## Medium

### Missing validation in setL() method
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridSignature.java:141-143`
```
public void setL(int l) {
        this.l = l;
    }
```
**Issue**: The setL() method has no validation, unlike the constructor which checks `if (l < 0 || l > sigM.length)`. This allows setting an invalid length that could cause unexpected behavior. Calling setL(Integer.MAX_VALUE) followed by setSigM(new byte[100]) would succeed, leaving the object in an inconsistent state where l > sigM.length.
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


## Low

### Potential KEK access release without successful acquisition
`examples/src/test/java/org/openhitls/SM4ExampleTest.java:70-84`
```
@After
    public void tearDown() throws SDFException {
        if (sdf != null) {
            if (ecbKeyHandle != 0) {
                sdf.SDF_DestroyKey(sessionHandle, ecbKeyHandle);
            }
            if (sessionHandle != 0) {
                sdf.SDF_ReleaseKEKAccessRight(sessionHandle, KEY_INDEX);
                sdf.SDF_CloseSession(sessionHandle);
            }
            if (deviceHandle != 0) {
                sdf.SDF_CloseDevice(deviceHandle);
            }
        }
    }
```
**Issue**: If SDF_GetKEKAccessRight() fails in setUp(), tearDown() still attempts to release KEK access. While the SDF library may handle this gracefully, it's not guaranteed and could cause test instability. A flag should track whether KEK access was successfully acquired.
**Fix**:
```
private boolean kekAccessAcquired = false;

    @Before
    public void setUp() throws SDFException {
        sdf = new SDF();
        deviceHandle = sdf.SDF_OpenDevice();
        sessionHandle = sdf.SDF_OpenSession(deviceHandle);
        loadConfig();
        // 获取KEK访问权限并生成密钥
        sdf.SDF_GetKEKAccessRight(sessionHandle, KEY_INDEX, KEY_PASSWORD);
        kekAccessAcquired = true;
        KeyEncryptionResult result = sdf.SDF_GenerateKeyWithKEK(sessionHandle, SM4_KEY_BITS, AlgorithmID.SGD_SM4_ECB, KEY_INDEX);
        ecbKeyHandle = result.getKeyHandle();
    }

    @After
    public void tearDown() throws SDFException {
        if (sdf != null) {
            if (ecbKeyHandle != 0) {
                sdf.SDF_DestroyKey(sessionHandle, ecbKeyHandle);
            }
            if (sessionHandle != 0) {
                if (kekAccessAcquired) {
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

### Non-threadsafe static config loading with mutable static state
`examples/src/test/java/org/openhitls/SM4ExampleTest.java:42-56`
```
private static int KEY_INDEX = 4;
    private static String KEY_PASSWORD = "123abc!@";

    public static void loadConfig() {
        Properties testConfig = new Properties();
        try (InputStream is = SM4ExampleTest.class.getClassLoader()
                .getResourceAsStream("test-config.properties")) {
            if (is != null) {
                testConfig.load(is);
                KEY_INDEX = Integer.parseInt(
                        testConfig.getProperty("sm4.internal.key.index", String.valueOf(KEY_INDEX)));
                KEY_PASSWORD = testConfig.getProperty("sm4.key.access.password", KEY_PASSWORD);
                return;
            }
        } catch (IOException e) {
            System.err.println("读取配置文件失败: " + e.getMessage());
        }
    }
```
**Issue**: The loadConfig() method modifies static fields KEY_INDEX and KEY_PASSWORD without synchronization. If tests run in parallel, this could cause race conditions where one test overwrites config values used by another.
**Fix**:
```
private static final int KEY_INDEX;
    private static final String KEY_PASSWORD;

    static {
        int keyIndex = 4;
        String keyPassword = "123abc!@";
        Properties testConfig = new Properties();
        try (InputStream is = SM4ExampleTest.class.getClassLoader()
                .getResourceAsStream("test-config.properties")) {
            if (is != null) {
                testConfig.load(is);
                keyIndex = Integer.parseInt(
                        testConfig.getProperty("sm4.internal.key.index", "4"));
                keyPassword = testConfig.getProperty("sm4.key.access.password", "123abc!@");
            }
        } catch (IOException e) {
            System.err.println("读取配置文件失败: " + e.getMessage());
        }
        KEY_INDEX = keyIndex;
        KEY_PASSWORD = keyPassword;
    }
```

---

### Missing upper bound validation for ciphertext length
`sdf4j/src/main/java/org/openhitls/sdf4j/types/HybridCipher.java:114-122`
```
public void setL1(long l1) {
        if (l1 < 0) {
            throw new IllegalArgumentException("Ciphertext length cannot be negative");
        }
        if (ctM != null && l1 > ctM.length) {
            throw new IllegalArgumentException("len cannot exceed data length");
        }
        this.l1 = l1;
    }
```
**Issue**: The setL1() method validates that l1 is not negative and doesn't exceed ctM.length, but doesn't validate against Integer.MAX_VALUE. Since l1 is a long but array lengths are limited to Integer.MAX_VALUE, a very large l1 value could theoretically cause issues in native code that expects array indices.
**Fix**:
```
public void setL1(long l1) {
        if (l1 < 0) {
            throw new IllegalArgumentException("Ciphertext length cannot be negative");
        }
        if (l1 > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("Ciphertext length cannot exceed Integer.MAX_VALUE");
        }
        if (ctM != null && l1 > ctM.length) {
            throw new IllegalArgumentException("len cannot exceed data length");
        }
        this.l1 = l1;
    }
```

---
