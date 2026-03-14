# Final Code Review Report
## openHiTLS/ngcc_bench - PR #12

### Summary
- **Total Issues**: 7
- **Critical**: 0
- **High**: 3
- **Medium**: 4
- **Low**: 0
- **Reviewers**: claude, codex

---


## High

### Breaking JSON schema change without version bump
`docs/json_schema_v4.json:102-107`
**Reviewers**: CLAUDE | **置信度**: 可信
```
"required": [
  "hash",
  "sig",
  "kem",
  "kex"
],
```
**Issue**: The JSON schema v4 changed the `tests.required` fields from `["hash", "dsa", "dsa-keygen", "dsa-sig", "dsa-verify", "kem", "kex", "kem-keygen", "kem-encap", "kem-decap"]` to `["hash", "sig", "kem", "kex"]`. This is a breaking change for external tools/CI pipelines that validate against schema v4, but the schema_version constant remains 4 in json_report.c:249. Semantic versioning requires incrementing the version for breaking changes.
**Fix**:
```
Option 1: Increment schema_version to 5 in json_report.c:249 and update all schema file names
Option 2: Keep backward compatibility by including old field names as optional (deprecated) fields
```

---

### SIG KAT mode only validates sig_verify, missing keygen/sign tests
`ngcc_bench/src/main.c:68-76`
**Reviewers**: CODEX | **置信度**: 可信
```
static int sig_verify_kat_dispatch(const ngcc_api_t *api,
                                   int digest_len_bits,
                                   const char *kat_path,
                                   unsigned long long *out_total,
                                   unsigned long long *out_passed,
                                   unsigned long long *out_failed) {
    (void) digest_len_bits;
    return ngcc_sig_verify_correctness_kat_file(api, kat_path, out_total, out_passed, out_failed);
}
```
**Issue**: The `sig_verify_kat_dispatch` function only calls `ngcc_sig_verify_correctness_kat_file()`. When `--test sig --mode correctness --kat ...` is used, `sig_keygen()` and `sig_sign()` operations are never exercised. A library with broken key generation or signing can report `[sig][correctness] PASS` as long as verify succeeds. No functions named `ngcc_sig_keygen_correctness_kat_file()` or `ngcc_sig_sign_correctness_kat_file()` exist in the codebase.
**Fix**:
```
/* SIG KAT format does not support full keygen+sign+verify validation.
 * Fall back to runtime correctness for SIG, or report unsupported. */
static int sig_kat_not_supported_dispatch(const ngcc_api_t *api,
                                         int digest_len_bits,
                                         const char *kat_path,
                                         unsigned long long *out_total,
                                         unsigned long long *out_passed,
                                         unsigned long long *out_failed) {
    (void) api;
    (void) digest_len_bits;
    (void) kat_path;
    (void) out_total;
    (void) out_passed;
    (void) out_failed;
    return 1; /* KAT_NO_VECTOR: fall back to runtime correctness */
}
```

---

### 1-pass KEX correctness passes without verifying A-side derive_ss_a
`ngcc_bench/src/bench_kex.c:121-134`
**Reviewers**: CLAUDE, CODEX | **置信度**: 可信
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
    return 0;
}
```
**Issue**: For 1-pass KEX protocols (`mb == NULL`), correctness returns success after only calling `kex_derive_ss_b()`. The `kex_derive_ss_a()` function is never called, and no shared-secret equality check is performed. A library with a broken A-side derive will pass correctness. The comment "we may not be able to verify A-side without a B-msg" is incorrect - proper 1-pass KEX should allow both parties to derive matching secrets.
**Fix**:
```
if (mb == NULL) {
    /* 1-pass protocol: both parties should derive from available info.
     * A-side uses NULL mb, B-side uses ma. Both must succeed and outputs must match. */
    unsigned long long ssa_len = ss_cap;
    if (api->kex_derive_ss_a(ska, ska_len, pkb, pkb_len, NULL, 0, sta, sta_len, ssa, &ssa_len) != 0) {
        return -1;
    }
    if (api->kex_derive_ss_b(skb, skb_len, pka, pka_len, ma, ma_len, stb, stb_len, ssb, &ssb_len) != 0) {
        return -1;
    }
    if (ssa_len == 0 || ssa_len > ss_cap || ssb_len == 0 || ssb_len > ss_cap || ssa_len != ssb_len) {
        return -1;
    }
    if (memcmp(ssa, ssb, (size_t) ssa_len) != 0) {
        return -1;
    }
    return 0;
}
```

---


## Medium

### KEX performance reuses mutable protocol state across all iterations
`ngcc_bench/src/bench_kex.c:693-764`
**Reviewers**: CODEX | **置信度**: 较可信
```
/* ── Setup: run the full protocol once to get intermediate state ── */
{
    ...
    if (api->kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len) != 0) { goto cleanup; }
    if (api->kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len) != 0) { goto cleanup; }
    ...
}

ctx_a.sta = sta;  ctx_a.sta_len = sta_len;
ctx_a.mb  = mb;   ctx_a.mb_len  = mb_len;
if (ngcc_run_performance_op(&local_cfg, kex_derive_ss_a_op, &ctx_a, out_a) != 0) {
    goto cleanup;
}
```
**Issue**: The benchmark runs the full KEX protocol once (lines 693-729), stores intermediate state (`sta`, `stb`, `ma`, `mb`), then reuses the same pointers for every derive_ss iteration. If `kex_derive_ss_a()` or `kex_derive_ss_b()` consumes or mutates the state buffers, performance will fail after the first iteration or measure an invalid hot/cold state. The correctness test may pass while performance fails.
**Fix**:
```
typedef struct {
    const ngcc_api_t *api;
    unsigned char *ska;  unsigned long long ska_len;
    unsigned char *pkb;  unsigned long long pkb_len;
    unsigned char *sta_seed; unsigned long long sta_len;
    unsigned char *mb_seed;  unsigned long long mb_len;
    unsigned char *ss;   unsigned long long ss_cap;
} kex_derive_ctx_t;

static int kex_derive_ss_a_op(void *ctx_ptr) {
    kex_derive_ctx_t *c = (kex_derive_ctx_t *) ctx_ptr;
    unsigned long long ss_len = c->ss_cap;
    unsigned char *sta = (unsigned char *) malloc((size_t) c->sta_len);
    unsigned char *mb = (unsigned char *) malloc((size_t) c->mb_len);
    int rc;

    if (sta == NULL || mb == NULL) {
        free(sta);
        free(mb);
        return -1;
    }

    memcpy(sta, c->sta_seed, (size_t) c->sta_len);
    memcpy(mb, c->mb_seed, (size_t) c->mb_len);
    rc = c->api->kex_derive_ss_a(c->ska, c->ska_len, c->pkb, c->pkb_len,
                                 mb, c->mb_len, sta, c->sta_len, c->ss, &ss_len);
    free(sta);
    free(mb);
    return rc;
}
```

---

### Byte-throughput stability metrics disabled for SIG/KEM/KEX tests
`ngcc_bench/src/main.c:398-400`
**Reviewers**: CODEX | **置信度**: 可信
```
rc = ngcc_run_stability(api,
                        dispatch->correctness_fn,
                        (test->kind == NGCC_TEST_HASH) ? dispatch->bytes_per_case_fn : NULL,
                        (test->kind == NGCC_TEST_HASH) ? opts->digest_len_bits : 0,
                        NGCC_STABILITY_MSG_LEN,
                        1,
                        opts->stability_sample_ms,
                        opts->duration_hours,
                        opts->stability_max_cases,
                        &opts->stability_thresholds,
                        &result);
```
**Issue**: The `ngcc_run_stability()` call changed from passing `dispatch->bytes_per_case_fn` directly to only passing it for HASH tests: `(test->kind == NGCC_TEST_HASH) ? dispatch->bytes_per_case_fn : NULL`. This causes `throughput_mean_bytes`, `throughput_max_bytes`, and console output `[...][stability][throughput_bytes]` to never populate for SIG, KEM, and KEX tests. This is a behavior regression from the previous version.
**Fix**:
```
rc = ngcc_run_stability(api,
                        dispatch->correctness_fn,
                        dispatch->bytes_per_case_fn,
                        (test->kind == NGCC_TEST_HASH) ? opts->digest_len_bits : 0,
                        NGCC_STABILITY_MSG_LEN,
                        1,
                        opts->stability_sample_ms,
                        opts->duration_hours,
                        opts->stability_max_cases,
                        &opts->stability_thresholds,
                        &result);
```

---

### KEX KAT verification truncates protocols above 10 passes
`ngcc_bench/src/bench_kex.c:282-283`
**Reviewers**: CODEX | **置信度**: 可信
```
/* Maximum number of KEX passes to scan for (M1..M{N}, Pass{N}_Sta/Stb). */
#define KEX_MAX_PASS_SCAN 10

...

for (pass = 1; pass <= KEX_MAX_PASS_SCAN; ++pass) {
    char m_name[16];
    ...
    snprintf(m_name, sizeof(m_name), "M%d", pass);
    msg = ngcc_kat_get_field(vec, m_name);
    if (!kex_field_populated(msg)) {
        break;  /* no more passes */
    }
```
**Issue**: KAT verification hard-codes `KEX_MAX_PASS_SCAN 10` at line 283, but the loader now accepts KEX libraries with up to 20 passes (via `kex_passes_num` in ngcc_api.h). For protocols with 11-20 passes, the verifier stops at `M10` and derives the shared secret from an incomplete transcript, causing false failures against valid KAT vectors.
**Fix**:
```
/* Use the library's reported pass count instead of hardcoded limit */
unsigned long long max_pass_scan = api->kex_passes_num;
unsigned long long pass;

for (pass = 1; pass <= max_pass_scan; ++pass) {
    char m_name[16];
    ...
    snprintf(m_name, sizeof(m_name), "M%llu", pass);
    msg = ngcc_kat_get_field(vec, m_name);
    if (!kex_field_populated(msg)) {
        break;
    }
```

---

### Stability memory metrics changed from RSS to heap without documentation
`ngcc_bench/src/stability.c:138-140`
**Reviewers**: CODEX | **置信度**: 可信
```
memory_start = ngcc_mem_heap_bytes();
memory_min = memory_start;
memory_max = memory_start;

...

current_mem = ngcc_mem_heap_bytes();
if (current_mem < memory_min) {
    memory_min = current_mem;
}
if (current_mem > memory_max) {
    memory_max = current_mem;
}

...

memory_end = ngcc_mem_heap_bytes();
if (memory_end < memory_min) {
    memory_min = memory_end;
}
if (memory_end > memory_max) {
    memory_max = memory_end;
}

...

out_result->memory_peak_rss_bytes = memory_max;
```
**Issue**: The code changed from `ngcc_mem_current_rss_bytes()` to `ngcc_mem_heap_bytes()` but the public field names `memory_*_bytes` and `memory_peak_rss_bytes` imply RSS semantics. On macOS and platforms without `mallinfo2`, `ngcc_mem_heap_bytes()` returns 0, causing memory growth to permanently report as 0 and leaks outside malloc to be invisible. This silently changes semantics without updating the schema or field names.
**Fix**:
```
/* Use RSS for cross-platform consistency; heap_bytes returns 0 on macOS */
memory_start = ngcc_mem_current_rss_bytes();
memory_min = memory_start;
memory_max = memory_start;

...

current_mem = ngcc_mem_current_rss_bytes();
if (current_mem < memory_min) {
    memory_min = current_mem;
}
if (current_mem > memory_max) {
    memory_max = current_mem;
}
{
    uint64_t peak_rss = ngcc_mem_peak_rss_bytes();
    if (peak_rss > memory_max) {
        memory_max = peak_rss;
    }
}

...

memory_end = ngcc_mem_current_rss_bytes();
/* ... min/max updates ... */

out_result->memory_peak_rss_bytes = ngcc_mem_peak_rss_bytes();
```

---
