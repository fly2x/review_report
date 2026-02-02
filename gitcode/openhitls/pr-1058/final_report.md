# Final Code Review Report
## openhitls/openhitls - PR #1058

### Summary
- **Total Issues**: 16
- **Critical**: 0
- **High**: 0
- **Medium**: 7
- **Low**: 9
- **Reviewers**: claude, gemini, codex

---


## Medium

### Typo "Pailler" should be "Paillier"
`README-zh.md:20`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
- 传统非对称算法：RSA，RSA-Bind，DSA，ECDSA，ECDH，DH，SM2，SM9，Pailler，ElGamal；
```
**Issue**: The asymmetric algorithm name is misspelled as "Pailler" instead of the correct spelling "Paillier"
**Fix**:
```
- 传统非对称算法：RSA，RSA-Bind，DSA，ECDSA，ECDH，DH，SM2，SM9，Paillier，ElGamal；
```

---

### Typo "Pailler" should be "Paillier"
`docs/zh/1_发行声明.md:35`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
* Pailler算法支持同态运算
```
**Issue**: The asymmetric algorithm name is misspelled as "Pailler" instead of the correct spelling "Paillier"
**Fix**:
```
* Paillier算法支持同态运算
```

---

### Incorrect term "publicly token" should be "Privacy Pass token"
`README.md:16`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
- Authentication: Support Privacy Pass、HOTP、TOTP、SPAKE2+.
```
**Issue**: The component description says "publicly token authentication" but should say "Privacy Pass token authentication" based on RFC 9578
**Fix**:
```
- Authentication: Support Privacy Pass, HOTP, TOTP, SPAKE2+.
```

---

### Typo "PKIL" should be "PKI"
`docs/zh/1_发行声明.md:56`
**Reviewers**: CLAUDE, GEMINI, CODEX | **置信度**: 可信
```
* 证书和PKIL: req，x509，pkcs7，pkcs12，crl ...
```
**Issue**: The command line section has a typo "PKIL" instead of "PKI"
**Fix**:
```
* 证书和PKI: req，x509，pkcs7，pkcs12，crl ...
```

---

### Incorrect term "publicly token" in Chinese
`README-zh.md:45`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
```
- Auth认证组件提供了认证功能，当前提供publicly token认证功能，TOTP/HOTP，SPAKE2+等协议；
```
**Issue**: The component description says "publicly token认证功能" but should say "Privacy Pass token认证功能"
**Fix**:
```
- Auth认证组件提供了认证功能，当前提供Privacy Pass token认证功能，TOTP/HOTP，SPAKE2+等协议；
```

---

### Misleading ISO19790 certification claim
`README.md:8`
**Reviewers**: CODEX | **置信度**: 需评估
```
Currently, 5 components and cryptographic algorithms are configured, ISO19790 certified, and the performance optimization of ShangMi cryptographic algorithms on ARM, x86 is ready.
```
**Issue**: The README states "ISO19790 certified" which reads like a formal certification claim but the repository only documents an ISO19790 provider feature. This could be misleading without evidence of actual certification.
**Fix**:
```
Currently, 5 components and cryptographic algorithms are configured, ISO19790 provider support is available, and the performance optimization of ShangMi cryptographic algorithms on ARM, x86 is ready.
```

---

### Misleading ISO19790 certification claim in Chinese
`README-zh.md:8`
**Reviewers**: CODEX | **置信度**: 需评估
```
openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已经通过ISO19790认证，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```
**Issue**: "已经通过ISO19790认证" reads like a formal certification claim but the repository only documents an ISO19790 provider feature
**Fix**:
```
openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已提供ISO19790 Provider支持，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```

---


## Low

### Mixed Chinese and English punctuation
`README-zh.md:16`
**Reviewers**: CLAUDE, GEMINI | **置信度**: 可信
```
- 认证：支持 Privacy Pass、HOTP、TOTP、SPAKE2+等认证协议；
```
**Issue**: The Chinese README uses English comma instead of Chinese enumeration mark (、) and is missing space before 等认证协议
**Fix**:
```
- 认证：支持 Privacy Pass、HOTP、TOTP、SPAKE2+ 等认证协议；
```

---

### Mixed Chinese and English punctuation in English document
`README.md:16`
**Reviewers**: CLAUDE, GEMINI | **置信度**: 可信
```
- Authentication: Support Privacy Pass、HOTP、TOTP、SPAKE2+.
```
**Issue**: The English README uses Chinese enumeration mark (、) instead of English comma (,)
**Fix**:
```
- Authentication: Support Privacy Pass, HOTP, TOTP, SPAKE2+.
```

---

### Inconsistent capitalization of "random"
`README.md:21`
**Reviewers**: GEMINI | **置信度**: 较可信
```
- random: DRBG, DRBG-GM
```
**Issue**: The item "random" starts with a lowercase letter, while other items in the list start with uppercase
**Fix**:
```
- Random: DRBG, DRBG-GM
```

---

### Non-standard architecture name "x8664"
`README.md:124`
**Reviewers**: GEMINI | **置信度**: 较可信
```
* x8664 Optimize the full build:
```
**Issue**: The text "x8664" is used in the description header, but "x86_64" is the standard notation
**Fix**:
```
* x86_64 Optimize the full build:
```

---

### Extra space in Chinese text
`README-zh.md:8`
**Reviewers**: GEMINI | **置信度**: 较可信
```
openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已经通过ISO19790认证，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```
**Issue**: There is an extra space in the Chinese word "通过" (written as "通 过")
**Fix**:
```
openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，已经通过ISO19790认证，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。
```

---

### Inconsistent punctuation in algorithm list
`README-zh.md:21-24`
**Reviewers**: CLAUDE, GEMINI | **置信度**: 可信
```
- 随机数：DRBG，GM-DRBG
- 密钥派生：HKDF，SCRYPT，PBKDF2
- 哈希算法：SHA系列，MD5，SM3
- 消息认证码：HMAC，CMAC
```
**Issue**: The list items starting from line 21 lack the closing semicolon (；), which is present in the preceding items
**Fix**:
```
- 随机数：DRBG，GM-DRBG；
- 密钥派生：HKDF，SCRYPT，PBKDF2；
- 哈希算法：SHA系列，MD5，SM3；
- 消息认证码：HMAC，CMAC；
```

---

### Non-standard architecture name "x8664"
`README-zh.md:35`
**Reviewers**: GEMINI | **置信度**: 较可信
```
- 基于ARMv8、ARMv7、x8664 CPU算法性能优化；
```
**Issue**: The text uses "x8664" which is a non-standard abbreviation for "x86_64"
**Fix**:
```
- 基于ARMv8、ARMv7、x86_64 CPU算法性能优化；
```

---

### Inconsistent abbreviation "Buff" vs "Buffer"
`docs/zh/1_发行声明.md:40`
**Reviewers**: CODEX | **置信度**: 较可信
```
* 支持从Buff加载证书
```
**Issue**: "Buff" is an inconsistent abbreviation compared to "Buffer" used elsewhere in the documentation
**Fix**:
```
* 支持从Buffer加载证书
```

---

### HPKE listed twice in algorithm categories
`docs/en/2_Key Features.md:28`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
#### Traditional Asymmetric Algorithms
- RSA, RSA-Bind, DSA, ECDSA, ECDH, DH, SM2, SM9, Paillier, ElGamal, HPKE
...
#### Others
- DRBG, GM-DRBG
- HKDF, SCRYPT, PBKDF2
- SHA1, SHA2, SHA3, SHA256-MB, MD5, SM3
- HMAC, CMAC
- HPKE
```
**Issue**: HPKE (Hybrid Public Key Encryption) appears both in "Traditional Asymmetric Algorithms" and "Others" sections
**Fix**:
```
#### Traditional Asymmetric Algorithms
- RSA, RSA-Bind, DSA, ECDSA, ECDH, DH, SM2, SM9, Paillier, ElGamal
...
#### Others
- DRBG, GM-DRBG
- HKDF, SCRYPT, PBKDF2
- SHA1, SHA2, SHA3, SHA256-MB, MD5, SM3
- HMAC, CMAC
- HPKE
```

---
