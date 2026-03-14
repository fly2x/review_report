# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/ngcc_bench
- PR: #12
- Title: 

## Individual Review Reports

## CLAUDE Review

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


---

## CODEX Review

# Code Review: openHiTLS/ngcc_bench#12
**Reviewer**: CODEX


## High

### `sig` KAT mode only validates `sig_verify`
`ngcc_bench/src/main.c:68-75`
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

#define NGCC_TEST_DISPATCH_TABLE(X) \
    X(TEST_MASK_HASH, NGCC_TEST_HASH, "hash", hash_correctness_dispatch, hash_kat_dispatch, hash_performance_dispatch, msg_len_bytes_per_case) \
    X(TEST_MASK_SIG, NGCC_TEST_SIG, "sig", sig_correctness_dispatch, sig_verify_kat_dispatch, NULL, msg_len_bytes_per_case) \
    X(TEST_MASK_KEM, NGCC_TEST_KEM, "kem", kem_correctness_dispatch, kem_kat_dispatch, NULL, kem_bytes_per_case) \
    X(TEST_MASK_KEX, NGCC_TEST_KEX, "kex", kex_correctness_dispatch, kex_kat_dispatch, NULL, kex_bytes_per_case)
```
**Issue**: The new aggregate `sig` test is wired to `ngcc_sig_verify_correctness_kat_file()`. When `--test sig --mode correctness --kat ...` is used, `sig_keygen()` and `sig_sign()` are never exercised, so a library with broken key generation/signing can still report `[sig][correctness] PASS`. I reproduced this with a mock where `sig_keygen()`/`sig_sign()` return `-1` and `sig_verify()` succeeds.
**Fix**:
```
static int kat_not_supported_dispatch(const ngcc_api_t *api,
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
    return 1; /* fall back to runtime correctness */
}

#define NGCC_TEST_DISPATCH_TABLE(X) \
    X(TEST_MASK_HASH, NGCC_TEST_HASH, "hash", hash_correctness_dispatch, hash_kat_dispatch, hash_performance_dispatch, msg_len_bytes_per_case) \
    X(TEST_MASK_SIG, NGCC_TEST_SIG, "sig", sig_correctness_dispatch, kat_not_supported_dispatch, NULL, msg_len_bytes_per_case) \
    X(TEST_MASK_KEM, NGCC_TEST_KEM, "kem", kem_correctness_dispatch, kem_kat_dispatch, NULL, kem_bytes_per_case) \
    X(TEST_MASK_KEX, NGCC_TEST_KEX, "kex", kex_correctness_dispatch, kex_kat_dispatch, NULL, kex_bytes_per_case)
```

---

### One-pass KEX correctness can pass with a broken A-side derive
`ngcc_bench/src/bench_kex.c:121-134`
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
**Issue**: For `kex_get_passes_num() == 1`, correctness returns success after only calling `kex_derive_ss_b()`. `kex_derive_ss_a()` is never checked and no shared-secret equality check is performed, so a library with a broken A-side derive is accepted. I reproduced this with a one-pass mock whose `kex_derive_ss_a()` always returns `-1`; correctness still reported `PASS`.
**Fix**:
```
if (mb == NULL) {
    fprintf(stderr, "[kex] error: 1-pass protocols cannot be fully validated by the current API contract\n");
    return -1;
}
```

---


## Medium

### KEX performance reuses mutable protocol state across all iterations
`ngcc_bench/src/bench_kex.c:693-745`
```
/* ── Setup: run the full protocol once to get intermediate state ── */
{
    ...
    if (api->kex_init_a(pka, &pka_len, ska, &ska_len, sta, &sta_len) != 0) { goto cleanup; }
    if (api->kex_init_b(pkb, &pkb_len, skb, &skb_len, stb, &stb_len) != 0) { goto cleanup; }
    ...
}

...
ctx_a.sta = sta;  ctx_a.sta_len = sta_len;
ctx_a.mb  = mb;   ctx_a.mb_len  = mb_len;
if (ngcc_run_performance_op(&local_cfg, kex_derive_ss_a_op, &ctx_a, out_a) != 0) {
    goto cleanup;
}

...
ctx_b.stb = stb;  ctx_b.stb_len = stb_len;
ctx_b.ma  = ma;   ctx_b.ma_len  = ma_len;
if (ngcc_run_performance_op(&local_cfg, kex_derive_ss_b_op, &ctx_b, out_b) != 0) {
    goto cleanup;
}
```
**Issue**: The benchmark runs the full KEX protocol once, then reuses the same `sta`/`stb` and last-message buffers for every `derive_ss` iteration. If `kex_derive_ss_a()` or `kex_derive_ss_b()` consumes or mutates that state, performance either fails after the first iteration or measures an invalid hot state. I reproduced this with a mock that zeroes `sta`/`stb` inside `derive_ss`; correctness passes, but performance immediately fails.
**Fix**:
```
typedef struct {
    const ngcc_api_t *api;
    unsigned char *ska;  unsigned long long ska_len;
    unsigned char *pkb;  unsigned long long pkb_len;
    unsigned char *skb;  unsigned long long skb_len;
    unsigned char *pka;  unsigned long long pka_len;
    unsigned char *sta_seed; unsigned long long sta_len;
    unsigned char *stb_seed; unsigned long long stb_len;
    unsigned char *ma_seed;  unsigned long long ma_len;
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

### Byte-throughput stability metrics are disabled for SIG/KEM/KEX
`ngcc_bench/src/main.c:398-400`
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
**Issue**: `ngcc_run_stability()` now receives `bytes_per_case_fn` only for hash. For `sig`, `kem`, and `kex`, `throughput_mean_bytes`, `throughput_max_bytes`, and the `[...][stability][throughput_bytes]` console line are never populated anymore. This is a behavior regression; for example, `kem` stability no longer prints byte-throughput output.
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
**Issue**: The loader now accepts KEX libraries with up to 20 passes, but KAT verification still hard-codes a scan limit of 10. For an 11-20 pass protocol, the verifier stops at `M10` and derives the secret from incomplete transcript/state, causing false failures against valid vectors.
**Fix**:
```
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

### Stability memory fields now report heap bytes as RSS
`ngcc_bench/src/stability.c:138-140`
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

out_result->memory_start_bytes = memory_start;
out_result->memory_end_bytes = memory_end;
out_result->memory_min_bytes = memory_min;
out_result->memory_max_bytes = memory_max;
out_result->memory_peak_rss_bytes = memory_max;
```
**Issue**: The code switched stability memory sampling from RSS to `ngcc_mem_heap_bytes()`, but the public fields are still named `memory_*_bytes` and `memory_peak_rss_bytes`. This silently changes semantics and breaks portability: `ngcc_mem_heap_bytes()` returns `0` on macOS and on platforms without `mallinfo2`, so memory growth becomes permanently zero and leaks outside `malloc()` are invisible.
**Fix**:
```
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
if (memory_end < memory_min) {
    memory_min = memory_end;
}
if (memory_end > memory_max) {
    memory_max = memory_end;
}

...

out_result->memory_peak_rss_bytes = ngcc_mem_peak_rss_bytes();
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
