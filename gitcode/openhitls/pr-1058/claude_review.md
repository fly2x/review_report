# Code Review: openhitls/openhitls#1058
**Reviewer**: CLAUDE


## Medium

### Inconsistent architecture naming in comment vs command parameter
`README.md:124`
```
* x86_64 Optimize the full build:
```
**Issue**: The comment says "x86_64 Optimize the full build:" but the actual command parameter is `--asm_type x8664`. Users may be confused and try to use `--asm_type x86_64` which would fail.
**Fix**:
```
FIX:
```

---

### Inconsistent architecture naming in Chinese comment vs command parameter
`README-zh.md:125`
```
* x86_64优化全量构建：
```
**Issue**: The Chinese comment says "x86_64优化全量构建：" but the actual command parameter is `--asm_type x8664`. Users may be confused and try to use `--asm_type x86_64` which would fail.
**Fix**:
```
FIX:
```

---


## Low

### Missing punctuation mark in Chinese documentation
`README-zh.md:28`
```
- 传统证书能力：支持X509解析验证，CRL解析验证，CSR请求生成，部分/全部证书链生成验证
   - PKCS7，PKCS8，PKCS12等；
```
**Issue**: Line 28 is missing a semicolon or period at the end, while all other items in the list end with a semicolon.
**Fix**:
```
- 传统证书能力：支持X509解析验证，CRL解析验证，CSR请求生成，部分/全部证书链生成验证；
   - PKCS7，PKCS8，PKCS12等；
```

---
