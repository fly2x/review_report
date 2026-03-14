# Code Review: openHiTLS/ngcc_bench#12
**Reviewer**: CLAUDE


## High

### Breaking JSON schema change without version bump
`docs/json_schema_v4.json:102-114`
```
"required": [
  "hash",
- "dsa",
- "dsa-keygen",
- "dsa-sig",
- "dsa-verify",
+ "sig",
  "kem",
- "kex",
- "kem-keygen",
- "kem-encap",
- "kem-decap"
+ "kex"
],
```
**Issue**: The schema version remains at 4 but the required fields changed from `dsa`, `dsa-keygen`, `dsa-sig`, `dsa-verify`, `kem-keygen`, `kem-encap`, `kem-decap` to just `sig`, `kem`, `kex`. This breaks any external tools or CI/CD pipelines that validate JSON output against schema v4. The version should have been incremented to v5 to indicate a breaking change.
**Fix**:
```
Option 1: Increment schema_version to 5 in json_report.c and update all schema files
Option 2: Keep backward compatibility by including old field names with deprecation markers
```

---


## Medium

### KEX 1-pass protocol leaves ssa output uninitialized
`ngcc_bench/src/bench_kex.c:98-106`
```
if (mb == NULL) {
    /* 1-pass: B derives from last A-msg, A has no B-msg to derive from.
     * Only B-side derive is possible. */
    if (api->kex_derive_ss_b(skb, skb_len, pka, pka_len, ma, ma_len, stb, stb_len, ssb, &ssb_len) != 0) {
        return -1;
    }
    /* For 1-pass, we may not be able to verify A-side without a B-msg.
     * Skip A-side derive and just check B output is valid. */
    if (ssb_len == 0 || ssb_len > ss_cap) {
        return -1;
    }
    return 0;  /* ssa never written! */
}
```
**Issue**: For 1-pass KEX protocols where `mb == NULL`, the function returns early after B-side derive_ss. The `ssa` buffer allocated by the caller is never written to, leaving it as uninitialized memory from malloc. While currently not used by the caller, this violates the function contract that both `ssa` and `ssb` should be valid outputs, creating a latent bug for future code that may use `ssa`.
**Fix**:
```
if (mb == NULL) {
    /* 1-pass: B derives from last A-msg, A has no B-msg to derive from.
     * Only B-side derive is possible. */
    if (api->kex_derive_ss_b(skb, skb_len, pka, pka_len, ma, ma_len, stb, stb_len, ssb, &ssb_len) != 0) {
        return -1;
    }
    if (ssb_len == 0 || ssb_len > ss_cap) {
        return -1;
    }
    /* For 1-pass protocol, zero-initialize ssa to indicate no A-side shared secret */
    memset(ssa, 0, ss_cap);
    unsigned long long ssa_len = 0;  /* Explicitly indicate no secret */
    /* Caller should check ssa_len > 0 before using ssa for 1-pass protocols */
    return 0;
}
```

---


## Low

### KEX 1-pass protocol may not correctly verify A-side shared secret
`ngcc_bench/src/bench_kex.c:70-105`
```
/* For 1-pass protocol: mb is NULL (no B message), derive_ss_a uses pkb directly;
 * this is handled by the derive function itself. For multi-pass: mb/ma point to last msgs. */
if (mb == NULL) {
    /* 1-pass: B derives from last A-msg, A has no B-msg to derive from.
     * Only B-side derive is possible. */
```
**Issue**: For 1-pass KEX protocols, the code notes that A-side verification "may not be able to verify" without a B-message. However, a proper 1-pass KEX protocol should still allow both parties to derive the same shared secret. The current implementation treats this as an expected limitation rather than potentially validating that the derive functions handle NULL `mb` input correctly.
**Fix**:
```
/* For 1-pass protocol: mb is NULL (no B message).
 * For proper 1-pass KEX, both parties should still derive matching secrets.
 * The derive_ss_a function should handle NULL mb internally by using
 * pkb directly without needing a received message. */
if (mb == NULL) {
    /* 1-pass protocol: attempt both sides, verify derive functions handle NULL input */
    unsigned long long ssa_len = ss_cap;
    if (api->kex_derive_ss_a(ska, ska_len, pkb, pkb_len, NULL, 0, sta, sta_len, ssa, &ssa_len) != 0) {
        /* If A-side derive fails with NULL mb, this is expected for some protocols */
        /* Fall through to B-side only verification */
    } else if (ssa_len == 0 || ssa_len > ss_cap) {
        return -1;
    }
```

---
