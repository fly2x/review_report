# Code Review: openHiTLS/openhitls-rs#2
**Reviewer**: CODEX


## High

### Generated build script uses `rustc-link-arg` instead of Cargo link directives
`configure.py:44-48`
```
println!("cargo:rustc-link-search=native={{}}", lib_dir);
    println!("cargo:rustc-link-arg=-Wl,-rpath,{{}}", lib_dir);
    println!("cargo:rustc-link-arg=-L{{}}", lib_dir);
    println!("cargo:rustc-link-arg=-lhitls_bsl");
    println!("cargo:rustc-link-arg=-lhitls_crypto");
```
**Issue**: The generated `crypto/build.rs` passes `-L` and `-l` through `cargo:rustc-link-arg`. Cargo only applies `rustc-link-arg` to final binaries/examples/tests, not to normal library compilation, so downstream crates depending on `openhitls` can still fail to link `hitls_bsl` and `hitls_crypto`. This makes the documented consumption path unreliable.
**Fix**:
```
content = f"""fn main() {{
    let lib_dir = "{abs_location}";
    println!("cargo:rustc-link-search=native={{}}", lib_dir);
    println!("cargo:rustc-link-lib=dylib=hitls_bsl");
    println!("cargo:rustc-link-lib=dylib=hitls_crypto");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{{}}", lib_dir);
    println!("cargo:rerun-if-changed=build.rs");
}}
"""
```

---

### CCM mode silently truncates caller-supplied IVs
`openhitls/src/aes.rs:33-37`
```
let actual_iv = if is_ccm(algid) && iv.len() > 12 {
            &iv[..12]
        } else {
            iv
        };
```
**Issue**: For CCM, any IV longer than 12 bytes is silently shortened to its first 12 bytes before encryption and decryption. That collapses distinct nonces onto the same effective IV, which is a cryptographic misuse and can cause nonce reuse under the same key. If longer IVs are unsupported, the wrapper must reject them instead of mutating them.
**Fix**:
```
let actual_iv = if is_ccm(algid) {
            if iv.len() > 12 {
                return Err("CCM IVs longer than 12 bytes are not supported".to_string());
            }
            iv
        } else {
            iv
        };
```

---


## Medium

### Signing error path leaks the allocated key context
`openhitls/src/ecdsa.rs:22-29`
```
let ret = pkey_sign(key_ctx, digest, data, &mut sig_buf, &mut sig_len);

    if ret != 0 {
        return Err(format!("Sign failed: 0x{:x}", ret));
    }

    sig_buf.truncate(sig_len as usize);
    free_ecc_pkey(key_ctx);
    Ok(sig_buf)
```
**Issue**: When `pkey_sign` fails, the function returns immediately without freeing `key_ctx`. Repeated signing failures will leak native contexts in a public API that is otherwise expected to manage resources safely.
**Fix**:
```
let ret = pkey_sign(key_ctx, digest, data, &mut sig_buf, &mut sig_len);
    if ret != 0 {
        free_ecc_pkey(key_ctx);
        return Err(format!("Sign failed: 0x{:x}", ret));
    }

    sig_buf.truncate(sig_len as usize);
    free_ecc_pkey(key_ctx);
    Ok(sig_buf)
```

---

### Verification API turns operational failures into `Ok(false)`
`openhitls/src/ecdsa.rs:48-53`
```
let ret = pkey_verify(key_ctx, digest, data, signature);
    free_ecc_pkey(key_ctx);
    if ret == 0 {
        Ok(true)
    } else {
        Ok(false)
    }
```
**Issue**: Every nonzero return code from `pkey_verify` is reported as `Ok(false)`. That hides real library failures such as bad parameters, unsupported digests, or internal verification errors, and makes callers treat infrastructure errors as ordinary signature mismatches.
**Fix**:
```
let ret = pkey_verify(key_ctx, digest, data, signature);
    free_ecc_pkey(key_ctx);

    if ret == 0 {
        Ok(true)
    } else {
        Err(format!("Verify failed: 0x{:x}", ret))
    }
```

---

### Safe SHA-256 wrapper ignores allocation and FFI error returns
`openhitls/src/sha2_256.rs:10-25`
```
pub fn new() -> Self {
        let ctx = sha2_256_newctx();
        sha2_256_init(ctx);
        Self { ctx }
    }

    pub fn update(&mut self, data: &[u8]) {
        sha2_256_update(self.ctx, data);
    }

    pub fn finalize(self) -> [u8; 32] {
        let this = ManuallyDrop::new(self);
        let mut out = [0u8; 32];
        let mut out_len = 32u32;
        sha2_256_final(this.ctx, &mut out, &mut out_len);
        sha2_256_freectx(this.ctx);
        out
    }
```
**Issue**: `Sha256::new`, `update`, and `finalize` discard the native return codes and never check whether `sha2_256_newctx()` returned null. That means allocation/init failures can turn into null-pointer calls or silently produce an all-zero/partial digest while still presenting a safe Rust API.
**Fix**:
```
pub fn new() -> Result<Self, String> {
        let ctx = sha2_256_newctx();
        if ctx.is_null() {
            return Err("CRYPT_SHA2_256_NewCtx failed".to_string());
        }

        let ret = sha2_256_init(ctx);
        if ret != 0 {
            sha2_256_freectx(ctx);
            return Err(format!("CRYPT_SHA2_256_Init failed: 0x{:x}", ret));
        }

        Ok(Self { ctx })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), String> {
        let ret = sha2_256_update(self.ctx, data);
        if ret != 0 {
            return Err(format!("CRYPT_SHA2_256_Update failed: 0x{:x}", ret));
        }
        Ok(())
    }

    pub fn finalize(self) -> Result<[u8; 32], String> {
        let this = ManuallyDrop::new(self);
        let mut out = [0u8; 32];
        let mut out_len = 32u32;
        let ret = sha2_256_final(this.ctx, &mut out, &mut out_len);
        sha2_256_freectx(this.ctx);

        if ret != 0 || out_len != 32 {
            return Err(format!("CRYPT_SHA2_256_Final failed: 0x{:x}", ret));
        }

        Ok(out)
    }
```

---

### AES example documents a fixed IV
`README.md:192-197`
```
let plaintext = "Hello OpenHiTLS!";
let key = b"0123456789abcdef";
let iv = b"0123456789abcdef";

let encrypted = aes_encrypt(AES128_CBC, plaintext.as_bytes(), key, iv).unwrap();
let decrypted = aes_decrypt(AES128_CBC, &encrypted, key, iv).unwrap();
```
**Issue**: The README shows AES encryption with a hard-coded IV. Reusing a fixed IV is unsafe for CBC and catastrophic for GCM/CCM under the same key, so this example teaches an insecure pattern in the main user-facing documentation.
**Fix**:
```
let plaintext = "Hello OpenHiTLS!";
let key = b"0123456789abcdef";
let mut iv = [0u8; 16];
getrandom::fill(&mut iv).unwrap(); // 每次加密都要生成新的 IV

let encrypted = aes_encrypt(AES128_CBC, plaintext.as_bytes(), key, &iv).unwrap();
let decrypted = aes_decrypt(AES128_CBC, &encrypted, key, &iv).unwrap();
```

---
