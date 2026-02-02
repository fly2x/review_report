# Code Review: openhitls/openhitls#1058
**Reviewer**: GEMINI


## Low

### Mixed delimiters in feature list
`README.md:14`
```
- Authentication: Support Privacy Pass、HOTP、TOTP、SPAKE2+.
```
**Issue**: The line uses a Chinese-style enumeration comma (、) instead of an English comma (,).
**Fix**:
```
- Authentication: Support Privacy Pass, HOTP, TOTP, SPAKE2+.
```

---

### Inconsistent capitalization
`README.md:19`
```
- random: DRBG, DRBG-GM
```
**Issue**: The item "random" starts with a lowercase letter, while other items in the list start with uppercase (e.g., "Symmetric algorithms", "Post-quantum algorithms").
**Fix**:
```
- Random: DRBG, DRBG-GM
```

---

### Non-standard architecture name in header
`README.md:125`
```
* x8664 Optimize the full build:
```
**Issue**: The text "x8664" is used in the description header, but "x86_64" is the standard notation.
**Fix**:
```
* x86_64 Optimize the full build:
```

---

### Typo (Extra space)
`README-zh.md:10`
```
openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已经通 过ISO19790认证，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```
**Issue**: There is an extra space in the Chinese word "通过" (written as "通 过").
**Fix**:
```
openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已经通过ISO19790认证，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```

---

### Inconsistent punctuation in list
`README-zh.md:23-27`
```
- 随机数：DRBG，GM-DRBG
   - 密钥派生：HKDF，SCRYPT，PBKDF2
   - 哈希算法：SHA系列，MD5，SM3
   - 消息认证码：HMAC，CMAC
   - 其他：HPKE
```
**Issue**: The list items starting from line 23 lack the closing semicolon (；), which is present in the preceding items (lines 17, 19, 21).
**Fix**:
```
- 随机数：DRBG，GM-DRBG；
   - 密钥派生：HKDF，SCRYPT，PBKDF2；
   - 哈希算法：SHA系列，MD5，SM3；
   - 消息认证码：HMAC，CMAC；
   - 其他：HPKE
```

---

### Non-standard architecture name
`README-zh.md:39`
```
- 基于ARMv8、ARMv7、x8664 CPU算法性能优化；
```
**Issue**: The text uses "x8664" which is a non-standard abbreviation for "x86_64" in this context.
**Fix**:
```
- 基于ARMv8、ARMv7、x86_64 CPU算法性能优化；
```

---

### Typo in PKI acronym
`docs/zh/1_发行声明.md:57`
```
* 证书和PKIL: req，x509，pkcs7，pkcs12，crl ...
```
**Issue**: The text says "PKIL" instead of "PKI".
**Fix**:
```
* 证书和PKI: req，x509，pkcs7，pkcs12，crl ...
```

---

### Deletion of Change History
`docs/en/6_Appendix/2_Change History.md:1-5`
```
(File deleted)
```
**Issue**: The change history file is being deleted. While the new "Release Notes" covers the current version, historical data (v0.1.0 alpha1) is lost.
**Fix**:
```
(Consider keeping the file or merging historical versions into Release Notes)
```

---
