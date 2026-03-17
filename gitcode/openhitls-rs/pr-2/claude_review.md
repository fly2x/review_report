# Code Review: openHiTLS/openhitls-rs#2
**Reviewer**: CLAUDE


## Critical

### AEAD tag comparison vulnerable to timing attacks
`openhitls/src/aes.rs:202`
```
if calculated_tag != tag {
    return Err(format!("AEAD Tag mismatch! Expected {:?}, Got {:?}", tag, calculated_tag));
}
```
**Issue**: The tag comparison uses `!=` operator which is not constant-time. This allows an attacker to potentially forge valid tags through timing side-channel attacks.
**Fix**:
```
use subtle::ConstantTimeEq;

if calculated_tag.ct_eq(&tag).into() == false {
    return Err("AEAD Tag mismatch".to_string());
}
```

---

### Indistinguishable error return from successful empty key generation
`openhitls/src/ecc_pkey_gen.rs:19`
```
if ctx.is_null() {
    println!("Failed to create ECC context");
    return (Vec::new(), Vec::new());
}
```
**Issue**: The function returns (Vec::new(), Vec::new()) on error, which is indistinguishable from a successful (but impossible) generation of empty keys. Callers cannot detect failures and may use uninitialized/invalid cryptographic keys.
**Fix**:
```
pub fn ecc_genpkey(curve_id: u32) -> Result<(Vec<u8>, Vec<u8>), String> {
    // ...
    if ctx.is_null() {
        return Err("Failed to create ECC context".to_string());
    }
    // ...
    Ok((actual_pub, actual_prv))
}
```

---


## High

### Ignored return value from sha2_256_init
`openhitls/src/sha2_256.rs:12`
```
pub fn new() -> Self {
    let ctx = sha2_256_newctx();
    sha2_256_init(ctx);
    Self { ctx }
}
```
**Issue**: The sha2_256_init function returns an i32 status code (0 = success), but the return value is ignored. If initialization fails, the context will be in an invalid state but the new() function still succeeds, leading to undefined behavior when the context is used.
**Fix**:
```
pub fn new() -> Result<Self, String> {
    let ctx = sha2_256_newctx();
    if ctx.is_null() {
        return Err("Failed to allocate SHA256 context".to_string());
    }
    let ret = sha2_256_init(ctx);
    if ret != 0 {
        sha2_256_freectx(ctx);
        return Err(format!("Failed to initialize SHA256 context: {}", ret));
    }
    Ok(Self { ctx })
}
```

---

### Ignored return value from sha2_256_update
`openhitls/src/sha2_256.rs:16-18`
```
pub fn update(&mut self, data: &[u8]) {
    sha2_256_update(self.ctx, data);
}
```
**Issue**: The sha2_256_update function returns an i32 status code, but the return value is ignored. If update fails, the hash state is corrupted and the final result will be invalid.
**Fix**:
```
pub fn update(&mut self, data: &[u8]) -> Result<(), String> {
    let ret = sha2_256_update(self.ctx, data);
    if ret != 0 {
        Err(format!("Failed to update SHA256: {}", ret))
    } else {
        Ok(())
    }
}
```

---

### Silent IV truncation for CCM mode without length validation
`openhitls/src/aes.rs:33-37`
```
let actual_iv = if is_ccm(algid) && iv.len() > 12 {
    &iv[..12]
} else {
    iv
};
```
**Issue**: For CCM mode, the IV is truncated to 12 bytes if longer, but no error is raised if the IV is shorter than 12 bytes. CCM requires a 12-byte nonce (7-13 bytes allowed by spec, but 12 is standard). Using a shorter IV may lead to weak cryptography.
**Fix**:
```
let actual_iv = if is_ccm(algid) {
    if iv.len() < 12 {
        return Err("CCM mode requires IV of at least 12 bytes".to_string());
    }
    &iv[..12]
} else {
    iv
};
```

---

### Silent IV truncation for CCM mode in decrypt without length validation
`openhitls/src/aes.rs:127-131`
```
let actual_iv = if is_ccm(algid) && iv.len() > 12 {
    &iv[..12]
} else {
    iv
};
```
**Issue**: Same issue as in encrypt - CCM IV is truncated to 12 bytes if longer, but no error if shorter than 12 bytes.
**Fix**:
```
let actual_iv = if is_ccm(algid) {
    if iv.len() < 12 {
        return Err("CCM mode requires IV of at least 12 bytes".to_string());
    }
    &iv[..12]
} else {
    iv
};
```

---

### ctx_to_key returns empty vectors on error without indication
`openhitls/src/ecc_pkey_gen.rs:49-84`
```
let ret_pub = ecc_get_pub(ctx, &mut pub_key_wrapper);
if ret_pub == 0 {
    let len = pub_key_wrapper.get_pub_len() as usize;
    actual_pub = pub_buf[..len].to_vec();
} else {
    println!("Failed to get ECC public key: {}", ret_pub);
}
```
**Issue**: When ecc_get_pub or ecc_get_prv fails, the function returns partially filled or empty vectors without any error indication. The caller cannot detect that key extraction failed.
**Fix**:
```
pub fn ctx_to_key(ctx: *mut std::ffi::c_void, curve_id: u32) -> Result<(Vec<u8>, Vec<u8>), String> {
    // ...
    let ret_pub = ecc_get_pub(ctx, &mut pub_key_wrapper);
    if ret_pub != 0 {
        return Err(format!("Failed to get ECC public key: {}", ret_pub));
    }
    let ret_prv = ecc_get_prv(ctx, &mut prv_key_wrapper);
    if ret_prv != 0 {
        return Err(format!("Failed to get ECC private key: {}", ret_prv));
    }
    // ...
    Ok((actual_pub, actual_prv))
}
```

---

### pub_buf dropped before use in key_to_ctx
`openhitls/src/ecc_pkey_gen.rs:110-121`
```
if !pub_key.is_empty() {
    let mut pub_buf = pub_key.to_vec();
    let mut pub_key_wrapper = CRYPT_EAL_PkeyPub::new(ctx_id);
    pub_key_wrapper.setter(pub_buf.as_mut_ptr(), pub_buf.len() as u32);

    let ret = ecc_set_pub(ctx, &mut pub_key_wrapper);
    // pub_buf is dropped here!
}
```
**Issue**: The `pub_buf` vector is allocated and its pointer is passed to `ecc_set_pub`, but the vector goes out of scope immediately after. If the C library stores the pointer and uses it later, this will cause use-after-free. The vector needs to live as long as the context.

---


## Medium

### Output buffer size based on encrypted data length may be insufficient
`openhitls/src/ecc_pkey_crypt.rs:37`
```
let mut out_len: u32 = enc_data.len() as u32;
let mut out_buf = vec![0u8; out_len as usize];
```
**Issue**: The output buffer is sized to `enc_data.len()`, but decrypted data can be larger than encrypted data for some encryption schemes (though SM2 typically produces ciphertext larger than plaintext). This could cause a buffer overflow or truncation.
**Fix**:
```
let mut out_len: u32 = (enc_data.len() + 256) as u32;
let mut out_buf = vec![0u8; out_len as usize];
```

---

### Working directory not restored on subprocess failure
`configure.py:9-15`
```
os.chdir(deps_dir)
subprocess.run(['python3', 'configure.py'], check=True)
build_dir = os.path.join(deps_dir, 'build')
os.makedirs(build_dir, exist_ok=True)
os.chdir(build_dir)
```
**Issue**: If subprocess.run() with check=True fails, an exception is raised but the working directory has already been changed. This leaves the process in an inconsistent state and makes debugging harder.
**Fix**:
```
original_dir = os.getcwd()
try:
    os.chdir(deps_dir)
    subprocess.run(['python3', 'configure.py'], check=True)
    build_dir = os.path.join(deps_dir, 'build')
    os.makedirs(build_dir, exist_ok=True)
    os.chdir(build_dir)
    subprocess.run(['cmake', '..'], check=True)
    subprocess.run(['make', '-j'], check=True)
    os.chdir(script_dir)
except Exception:
    os.chdir(original_dir)
    raise
```

---

### sha2_256_init wrapper discards return value
`crypto/src/sha2_256.rs:18-20`
```
pub fn sha2_256_init(ctx: *mut c_void) -> i32 {
    unsafe { CRYPT_SHA2_256_Init(ctx, std::ptr::null_mut()) }
}
```
**Issue**: The safe wrapper function sha2_256_init does not return the status code from the underlying C function, making it impossible for callers to detect initialization failures.

---
