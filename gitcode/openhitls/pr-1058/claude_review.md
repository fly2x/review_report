# Code Review: openhitls/openhitls#1058
**Reviewer**: CLAUDE


## Medium

### Typo in algorithm name "Pailler" should be "Paillier"
`README-zh.md:20`
```
- 传统非对称算法：RSA，RSA-Bind，DSA，ECDSA，ECDH，DH，SM2，SM9，Pailler，ElGamal；
```
**Issue**: The asymmetric algorithm name is misspelled as "Pailler" instead of the correct spelling "Paillier"
**Fix**:
```
- 传统非对称算法：RSA，RSA-Bind，DSA，ECDSA，ECDH，DH，SM2，SM9，Paillier，ElGamal；
```

---

### Typo in algorithm name "Pailler" should be "Paillier"
`docs/zh/1_发行声明.md:35`
```
* Pailler算法支持同态运算
```
**Issue**: The asymmetric algorithm name is misspelled as "Pailler" instead of the correct spelling "Paillier"
**Fix**:
```
* Paillier算法支持同态运算
```

---

### Incorrect term "publicly token" - should be "Privacy Pass token"
`README.md:45`
```
- Auth authentication component provides authentication functions. Currently, it provides publicly token authentication, TOTP/HOTP, SPAKE2+.
```
**Issue**: The component description says "publicly token authentication" but should say "Privacy Pass token authentication" based on RFC 9578
**Fix**:
```
- Auth authentication component provides authentication functions. Currently, it provides Privacy Pass token authentication, TOTP/HOTP, SPAKE2+.
```

---

### Incorrect term "publicly token" - should be "Privacy Pass token"
`README-zh.md:45`
```
- Auth认证组件提供了认证功能，当前提供publicly token认证功能，TOTP/HOTP，SPAKE2+等协议；
```
**Issue**: The component description says "publicly token认证功能" but should say "Privacy Pass token认证功能"
**Fix**:
```
- Auth认证组件提供了认证功能，当前提供Privacy Pass token认证功能，TOTP/HOTP，SPAKE2+等协议；
```

---

### Typo "PKIL" should be "PKI"
`docs/zh/1_发行声明.md:56`
```
* 证书和PKIL: req，x509，pkcs7，pkcs12，crl ...
```
**Issue**: The command line section has a typo "PKIL" instead of "PKI"
**Fix**:
```
* 证书和PKI: req，x509，pkcs7，pkcs12，crl ...
```

---


## Low

### Incorrect term "Privacy Pass" uses Chinese punctuation
`README.md:16`
```
- Authentication: Support Privacy Pass、HOTP、TOTP、SPAKE2+.
```
**Issue**: The English README uses Chinese enumeration mark (、) instead of English comma in "Privacy Pass、HOTP、TOTP、SPAKE2+"
**Fix**:
```
- Authentication: Support Privacy Pass, HOTP, TOTP, SPAKE2+.
```

---

### Mixed Chinese and English punctuation in protocol list
`README-zh.md:16`
```
- 认证：支持 Privacy Pass、HOTP、TOTP、SPAKE2+等认证协议；
```
**Issue**: The Chinese README uses English comma instead of Chinese enumeration mark (、) consistently
**Fix**:
```
- 认证：支持 Privacy Pass、HOTP、TOTP、SPAKE2+ 等认证协议；
```

---

### Missing semicolon at end of list item
`README-zh.md:28`
```
- 传统证书能力：支持X509解析验证，CRL解析验证，CSR请求生成，部分/全部证书链生成验证
```
**Issue**: The traditional certificate capabilities line is missing a semicolon at the end, inconsistent with other items
**Fix**:
```
- 传统证书能力：支持X509解析验证，CRL解析验证，CSR请求生成，部分/全部证书链生成验证；
```

---

### HPKE listed twice in algorithm categories
`docs/en/2_Key Features.md:28`
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
