# Final Code Review Report
## openHiTLS/ngcc_bench - PR #8

### Summary
- **Total Issues**: 14
- **Critical**: 2
- **High**: 4
- **Medium**: 6
- **Low**: 2
- **Reviewers**: claude, gemini, codex

---


## Critical

### Integer overflow in msg_data_bytes calculation from KAT file
`ngcc_bench/src/bench_hash.c:175`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
msg_data_bytes = (size_t) ((msg_len_bits_val + 7) / 8);
```
**Issue**: When msg_len_bits_val from a KAT file is close to ULLONG_MAX, the expression (msg_len_bits_val + 7) / 8 can overflow, resulting in a small value that passes allocation checks but causes buffer overflow later.
**Fix**:
```
/* Check for overflow before calculation */
if (msg_len_bits_val > (NGCC_MAX_BUFFER_LEN * 8ULL)) {
    fprintf(stderr, "[hash][kat] error: Msg_Len=%llu bits exceeds maximum buffer size\n", msg_len_bits_val);
    any_fail = 1;
    continue;
}
msg_data_bytes = (size_t) ((msg_len_bits_val + 7) / 8);
```

---

### No upper bound check for msg_bytes before malloc
`ngcc_bench/src/bench_hash.c:329`
**Reviewers**: CLAUDE | **置信度**: 可信
```
msg_bytes = (size_t) ((msg_len_bits_val + 7) / 8);

if (msg_bytes == 0 || digest_len == 0 || digest_len > msg_bytes) {
    fprintf(stderr, "[hash][kat_loop] error: invalid Msg_Len=%llu or Dst_Len=%d\n",
            msg_len_bits_val, dst_len_bits_val);
    return -1;
}

msg = (unsigned char *) malloc(msg_bytes);
```
**Issue**: msg_bytes is computed from KAT file data and allocated directly without checking against NGCC_MAX_BUFFER_LEN. A malicious KAT file could cause allocation of arbitrary size, potentially exhausting memory or causing denial of service.
**Fix**:
```
msg_bytes = (size_t) ((msg_len_bits_val + 7) / 8);

/* Add upper bound check */
if (msg_bytes == 0 || msg_bytes > NGCC_MAX_BUFFER_LEN ||
    digest_len == 0 || digest_len > msg_bytes) {
    fprintf(stderr, "[hash][kat_loop] error: invalid Msg_Len=%llu or Dst_Len=%d (msg_bytes=%zu exceeds max)\n",
            msg_len_bits_val, dst_len_bits_val, msg_bytes);
    return -1;
}

msg = (unsigned char *) malloc(msg_bytes);
```

---


## High

### SM3_DRNG_Instantiate doesn't validate nonce_len_bytes before using in malloc/memcpy
`ngcc_bench/src/drng.c:244`
**Reviewers**: CLAUDE | **置信度**: 可信
```
seed_material = (unsigned char *)malloc(MAX_INT(nonce_len_bytes, SEEDLEN));
if (NULL == seed_material)
{
    fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d. \n", __FILE__, __LINE__);
    return DRNG_MEMORY_ALLOCATION_FAILED;
}
memset(seed_material, 0, MAX_INT(nonce_len_bytes, SEEDLEN));
memcpy(seed_material, nonce, nonce_len_bytes);
```
**Issue**: nonce_len_bytes is used directly in malloc without validation. If an attacker-controlled large value is passed, it could cause integer overflow in the malloc size or excessive memory allocation. Additionally, memcpy at line 251 writes into a buffer that might be smaller than nonce_len_bytes if SEEDLEN > nonce_len_bytes.
**Fix**:
```
/* Validate nonce_len_bytes to prevent excessive allocation */
if (nonce_len_bytes > SEEDLEN) {
    fprintf(stderr, "ERROR: nonce_len_bytes %llu exceeds SEEDLEN %d\n", 
            nonce_len_bytes, SEEDLEN);
    return DRNG_MEMORY_ALLOCATION_FAILED;
}
if (nonce == NULL && nonce_len_bytes > 0) {
    fprintf(stderr, "ERROR: nonce is NULL but nonce_len_bytes is non-zero\n");
    return DRNG_MEMORY_ALLOCATION_FAILED;
}

seed_material = (unsigned char *)malloc(SEEDLEN);
if (NULL == seed_material) {
    fprintf(stderr, "ERROR: Memory allocation failed at %s, line %d.\n", __FILE__, __LINE__);
    return DRNG_MEMORY_ALLOCATION_FAILED;
}
memset(seed_material, 0, SEEDLEN);
if (nonce != NULL && nonce_len_bytes > 0) {
    memcpy(seed_material, nonce, nonce_len_bytes);
}
```

---

### KAT parser now rejects previously supported field names and single-file inputs
`ngcc_bench/src/bench_hash.c, ngcc_bench/src/bench_sig.c, ngcc_bench/src/bench_kem.c, ngcc_bench/src/bench_kex.c:`
**Reviewers**: CODEX | **置信度**: 可信
```
/* bench_hash.c - only accepts Msg/Dst fields */
const ngcc_kat_field_t *input = ngcc_kat_get_field(vec, "Msg");
const ngcc_kat_field_t *output = ngcc_kat_get_field(vec, "Dst");

if (!path_is_directory(kat_path)) {
    fprintf(stderr, "[hash][kat] error: --kat path is not a directory: %s\n", kat_path);
    return -1;
}

if (strncmp(entry->d_name, "KAT_2_") != 0 && strncmp(entry->d_name, "KAT_Loop_") != 0) {
    fprintf(stderr, "[hash][kat] error: unrecognized KAT file format: %s\n", entry->d_name);
    closedir(dir);
    rc = -1;
    goto done;
}
```
**Issue**: The new implementation only recognizes specific field names (Msg/Dst, PK/M/Sn, SK/CT/SS, SKa/PKb/PKa/SKb/SS, Init_Sta/Init_Stb) inside files with specific prefixes (KAT_HASH_, KAT_SIG_, KAT_KEM_, KAT_KEX_) under a directory. Previously supported aliases (INPUT/OUTPUT/MSG/DIGEST/PUBLICKEY/SECRETKEY/etc.) and single-file --kat inputs are now rejected or skipped.
**Fix**:
```
static const char *const k_input_alias[] = {"Msg", "INPUT", "MSG", "M", "MESSAGE"};
static const char *const k_output_alias[] = {"Dst", "OUTPUT", "DIGEST", "MD", "HASH"};

const ngcc_kat_field_t *input =
    ngcc_kat_get_field_any(vec, k_input_alias, sizeof(k_input_alias) / sizeof(k_input_alias[0]));
const ngcc_kat_field_t *output =
    ngcc_kat_get_field_any(vec, k_output_alias, sizeof(k_output_alias) / sizeof(k_output_alias[0]));

if (!path_is_directory(kat_path)) {
    ngcc_kat_file_t kat = {0};
    if (ngcc_kat_parse_file(kat_path, &kat) != 0) {
        return -1;
    }
    rc = verify_kat_vectors(api, digest_len_bits, &kat, &total, &passed_count, &failed_count);
    ngcc_kat_free(&kat);
    goto done;
}

ftype = classify_kat_file(entry->d_name);
if (ftype == KAT_TYPE_UNKNOWN) {
    continue; /* allow a shared --kat directory and preserve old file names */
}
```

---

### Public performance CLI flags removed without compatibility path
`ngcc_bench/src/cli_parser.c:19-35`
**Reviewers**: CODEX | **置信度**: 可信
```
static const struct option long_options[] = {
    {"lib", required_argument, NULL, 'l'},
    {"test", required_argument, NULL, 't'},
    {"mode", required_argument, NULL, 'm'},
    {"digest-len-bits", required_argument, NULL, 'b'},
    {"duration-hours", required_argument, NULL, 'd'},
    {"stability-max-cases", required_argument, NULL, 's'},
    {"stability-sample-ms", required_argument, NULL, OPT_STABILITY_SAMPLE_MS},
    {"json-out", required_argument, NULL, 'j'},
    {"kat", required_argument, NULL, 'k'},
    ...
};
```
**Issue**: This removes --iterations, --msg-len, and --cycles from the parser, so existing scripts and tests now fail before any benchmark runs. The branch still has callers that invoke those flags, and users lose the ability to control benchmark size/count from CLI.
**Fix**:
```
static const struct option long_options[] = {
    {"lib", required_argument, NULL, 'l'},
    {"test", required_argument, NULL, 't'},
    {"mode", required_argument, NULL, 'm'},
    {"iterations", required_argument, NULL, 'i'},
    {"duration-hours", required_argument, NULL, 'd'},
    {"stability-max-cases", required_argument, NULL, 's'},
    {"stability-sample-ms", required_argument, NULL, OPT_STABILITY_SAMPLE_MS},
    {"msg-len", required_argument, NULL, 'g'},
    {"digest-len-bits", required_argument, NULL, 'b'},
    {"cycles", required_argument, NULL, 'c'},
    {"json-out", required_argument, NULL, 'j'},
    {"kat", required_argument, NULL, 'k'},
    ...
};

case 'i':
    if (parse_unsigned_ll(optarg, &opts->iterations) != 0 || opts->iterations == 0) {
        fprintf(stderr, "invalid --iterations value: %s\n", optarg);
        return -1;
    }
    break;

case 'g': {
    unsigned long long msg_len_val;
    if (parse_unsigned_ll(optarg, &msg_len_val) != 0 || msg_len_val == 0) {
        fprintf(stderr, "invalid --msg-len value: %s\n", optarg);
        return -1;
    }
    opts->msg_len = (size_t) msg_len_val;
    break;
}

case 'c':
    if (parse_cycles(optarg, &opts->cycles_enabled) != 0) {
        fprintf(stderr, "invalid --cycles value: %s\n", optarg);
        return -1;
    }
    break;
```

---

### JSON writer no longer emits the required v4 option fields
`ngcc_bench/src/json_report.c:256-281`
**Reviewers**: CODEX | **置信度**: 可信
```
jw_begin_object(&w, "options");
jw_key_llu(&w, "test_mask", opts->test_mask);
jw_key_llu(&w, "mode_mask", opts->mode_mask);
jw_key_double(&w, "duration_hours", opts->duration_hours);
jw_key_llu(&w, "stability_max_cases", opts->stability_max_cases);
jw_key_double(&w, "stability_sample_ms", opts->stability_sample_ms);
```
**Issue**: The report now omits options.iterations, options.msg_len, options.digest_len_bits, and options.cycles, so the bundled validator immediately fails with missing key 'iterations'. The generated report is incompatible with the schema shipped in this repo.
**Fix**:
```
jw_begin_object(&w, "options");
jw_key_llu(&w, "test_mask", opts->test_mask);
jw_key_llu(&w, "mode_mask", opts->mode_mask);
jw_key_llu(&w, "iterations", opts->iterations);
jw_key_double(&w, "duration_hours", opts->duration_hours);
jw_key_llu(&w, "stability_max_cases", opts->stability_max_cases);
jw_key_double(&w, "stability_sample_ms", opts->stability_sample_ms);
jw_key_llu(&w, "msg_len", (unsigned long long) opts->msg_len);
jw_key_int(&w, "digest_len_bits", opts->digest_len_bits);
jw_key_str(&w, "cycles", opts->cycles_enabled ? "on" : "off");
```

---


## Medium

### Total test count not incremented on validation failure
`ngcc_bench/src/bench_kem.c:213-221`
**Reviewers**: GEMINI | **置信度**: 可信
```
/* Validate _Len fields match actual data length */
if (kem_check_field_len("SK", sk, ngcc_kat_get_field(vec, "SK_Len")) != 0 ||
    kem_check_field_len("CT", ct, ngcc_kat_get_field(vec, "CT_Len")) != 0 ||
    kem_check_field_len("SS", ss, ngcc_kat_get_field(vec, "SS_Len")) != 0) {
    (*io_failed)++;
    continue;
}

(*io_total)++;
```
**Issue**: When a test vector fails the _Len field validation, (*io_failed) is incremented but (*io_total) is never incremented. This results in inaccurate test statistics where failed can exceed total.
**Fix**:
```
/* Validate _Len fields match actual data length */
if (kem_check_field_len("SK", sk, ngcc_kat_get_field(vec, "SK_Len")) != 0 ||
    kem_check_field_len("CT", ct, ngcc_kat_get_field(vec, "CT_Len")) != 0 ||
    kem_check_field_len("SS", ss, ngcc_kat_get_field(vec, "SS_Len")) != 0) {
    (*io_total)++;
    (*io_failed)++;
    continue;
}

(*io_total)++;
```

---

### Total test count not incremented on validation failure
`ngcc_bench/src/bench_sig.c:341-349`
**Reviewers**: GEMINI | **置信度**: 可信
```
/* Validate _Len fields match actual data length */
if (sig_check_field_len("PK", pk, ngcc_kat_get_field(vec, "PK_Len")) != 0 ||
    sig_check_field_len("M", msg, ngcc_kat_get_field(vec, "M_Len")) != 0 ||
    sig_check_field_len("Sn", sn, ngcc_kat_get_field(vec, "Sn_Len")) != 0) {
    (*io_failed)++;
    continue;
}

(*io_total)++;
```
**Issue**: When a test vector fails the _Len field validation, (*io_failed) is incremented but (*io_total) is never incremented. This results in inaccurate test statistics where failed can exceed total.
**Fix**:
```
/* Validate _Len fields match actual data length */
if (sig_check_field_len("PK", pk, ngcc_kat_get_field(vec, "PK_Len")) != 0 ||
    sig_check_field_len("M", msg, ngcc_kat_get_field(vec, "M_Len")) != 0 ||
    sig_check_field_len("Sn", sn, ngcc_kat_get_field(vec, "Sn_Len")) != 0) {
    (*io_total)++;
    (*io_failed)++;
    continue;
}

(*io_total)++;
```

---

### Total test count not incremented on validation failures
`ngcc_bench/src/bench_kex.c:379-411`
**Reviewers**: GEMINI | **置信度**: 可信
```
if (len_failed) {
    (*io_failed)++;
    continue;
}

/* Validate Init_Sta_Len / Init_Stb_Len if present */
if (kex_field_populated(ngcc_kat_get_field(vec, "Init_Sta"))) {
    if (kex_check_field_len("Init_Sta",
                            ngcc_kat_get_field(vec, "Init_Sta"),
                            ngcc_kat_get_field(vec, "Init_Sta_Len")) != 0) {
        (*io_failed)++;
        continue;
    }
}
```
**Issue**: In verify_kex_kat_vectors, when length validation fails, (*io_failed) is incremented but (*io_total) is not, leading to incorrect statistics where failed vectors are not counted as part of the total cases.
**Fix**:
```
if (len_failed) {
    (*io_total)++;
    (*io_failed)++;
    continue;
}

/* Validate Init_Sta_Len / Init_Stb_Len if present */
if (kex_field_populated(ngcc_kat_get_field(vec, "Init_Sta"))) {
    if (kex_check_field_len("Init_Sta",
                            ngcc_kat_get_field(vec, "Init_Sta"),
                            ngcc_kat_get_field(vec, "Init_Sta_Len")) != 0) {
        (*io_total)++;
        (*io_failed)++;
        continue;
    }
}
```

---

### DSA sign and verify sub-operations only benchmark first message size
`ngcc_bench/src/main.c:399-402`
**Reviewers**: CODEX | **置信度**: 可信
```
/* KEM/KEX/sub-ops don't depend on msg_len, run once only */
if (test->kind != NGCC_TEST_HASH && test->kind != NGCC_TEST_DSA) {
    break;
}
```
**Issue**: The loop break condition treats all sub-operations as message-length-independent, but ngcc_dsa_sig_performance() and ngcc_dsa_verify_performance() both take msg_len and scale bytes_per_op with it. DSA_KEYGEN, DSA_SIG, and DSA_VERIFY only run the 1024-byte case.
**Fix**:
```
/* KEM/KEX don't depend on msg_len, but DSA sub-operations (sig/verify) do */
static int performance_depends_on_msg_len(ngcc_test_kind_t kind) {
    return kind == NGCC_TEST_HASH ||
           kind == NGCC_TEST_DSA ||
           kind == NGCC_TEST_DSA_SIG ||
           kind == NGCC_TEST_DSA_VERIFY;
}

if (!performance_depends_on_msg_len(test->kind)) {
    break;
}
```

---

### KAT_LOOP_ITERATIONS runs 1,000,000 times without progress indication
`ngcc_bench/src/bench_hash.c:357`
**Reviewers**: CLAUDE | **置信度**: 较可信
```
#define KAT_LOOP_ITERATIONS    1000000

/* ... */
for (i = 0; i < KAT_LOOP_ITERATIONS; i++) {
```
**Issue**: The KAT loop test runs 1,000,000 iterations without any progress output. For a slow hash implementation or large message size, this could take hours and appear to be hung. No timeout mechanism exists.
**Fix**:
```
/* Add progress indication every 100,000 iterations */
for (i = 0; i < KAT_LOOP_ITERATIONS; i++) {
    if (i % 100000 == 0) {
        printf("[hash][kat_loop] progress: %d / %d iterations\n", i, KAT_LOOP_ITERATIONS);
    }
    /* ... rest of loop body ... */
}
```

---

### get_random_number doesn't validate input pointers for NULL
`ngcc_bench/src/drng.c:322-324`
**Reviewers**: CLAUDE | **置信度**: 可信
```
int get_random_number(DRNG_ctx *drng, unsigned char *random_number, unsigned long long random_number_len_bits)
{
    return SM3_DRNG_Generate(drng, random_number_len_bits, random_number);
}
```
**Issue**: The function doesn't check if drng or random_number are NULL before dereferencing them. This could cause null pointer dereference crashes.
**Fix**:
```
int get_random_number(DRNG_ctx *drng, unsigned char *random_number, unsigned long long random_number_len_bits)
{
    if (drng == NULL) {
        return -1;
    }
    if (random_number == NULL && random_number_len_bits > 0) {
        return -1;
    }
    return SM3_DRNG_Generate(drng, random_number_len_bits, random_number);
}
```

---


## Low

### Missing newline at end of file
`ngcc_bench/src/drng.c:325`
**Reviewers**: CLAUDE | **置信度**: 可信
```
int get_random_number(DRNG_ctx *drng, unsigned char *random_number, unsigned long long random_number_len_bits)
{
    return SM3_DRNG_Generate(drng, random_number_len_bits, random_number);
}
```
**Issue**: The file ends without a newline character, which violates POSIX standards and can cause issues with some tools and version control systems.
**Fix**:
```
int get_random_number(DRNG_ctx *drng, unsigned char *random_number, unsigned long long random_number_len_bits)
{
    return SM3_DRNG_Generate(drng, random_number_len_bits, random_number);
}
<add newline at end>
```

---

### Missing newline at end of file
`ngcc_bench/include/drng.h:47`
**Reviewers**: CLAUDE | **置信度**: 可信
```
}
#endif
\ No newline at end of file
```
**Issue**: The header file ends without a newline character, which violates POSIX standards and can cause issues with some tools and version control systems.
**Fix**:
```
}
#endif
<add newline at end>
```

---
