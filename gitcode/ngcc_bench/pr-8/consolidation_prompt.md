# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/ngcc_bench
- PR: #8
- Title: 

## Individual Review Reports

## CLAUDE Review

# Code Review: openHiTLS/ngcc_bench#8
**Reviewer**: CLAUDE


## Critical

### Incorrect pointer arithmetic causes endianness issues and potential out-of-bounds reads
`ngcc_bench/src/drng.c:68`
```
W[i] = ((unsigned int)(msg + i * 4)[0] << 24 | (unsigned int)(msg + i * 4)[1] << 16 | (unsigned int)(msg + i * 4)[2] << 8 | (unsigned int)(msg + i * 4)[3]);
```
**Issue**: The expression `(msg + i * 4)[0]` adds byte offset first, then reads single bytes. This relies on pointer arithmetic then byte access, which is confusing but technically correct for reading bytes. However, the more serious issue is that if `msg` is not aligned or if `blocks * 64` exceeds the actual buffer size passed by the caller, this reads beyond bounds. The sm3_bit function calls this with potentially unbounded input.
**Fix**:
```
/* Use explicit byte indexing with bounds check */
if (msg == NULL) return;
for (i = 0; i < 16; i++) {
    size_t byte_offset = i * 4;
    W[i] = ((unsigned int)msg[byte_offset + 0] << 24) |
           ((unsigned int)msg[byte_offset + 1] << 16) |
           ((unsigned int)msg[byte_offset + 2] << 8) |
           ((unsigned int)msg[byte_offset + 3]);
}
```

---

### Integer overflow in msg_data_bytes calculation
`ngcc_bench/src/bench_hash.c:175`
```
msg_data_bytes = (size_t) ((msg_len_bits_val + 7) / 8);
```
**Issue**: When `msg_len_bits_val` is close to ULLONG_MAX, the expression `(msg_len_bits_val + 7) / 8` can overflow, resulting in a small value that passes allocation checks but causes buffer overflow later. The msg_len_bits_val comes from parsed KAT files which can contain arbitrary values.
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

### calloc allocates 1 byte when msg_data_bytes is 0, but later code uses msg_data_bytes size
`ngcc_bench/src/bench_hash.c:180`
```
msg_buf = (unsigned char *) calloc(1, msg_data_bytes > 0 ? msg_data_bytes : 1);
```
**Issue**: When `msg_data_bytes` is 0, the expression `msg_data_bytes > 0 ? msg_data_bytes : 1` allocates 1 byte. Later code at line 216 does `memset(msg_buf, 0xFF, msg_data_bytes)` which would be 0 bytes (no-op), but the buffer is only 1 byte. If msg_data_bytes was calculated as 0 due to overflow but should have been large, this is a buffer overflow.
**Fix**:
```
/* Handle zero-length case properly */
if (msg_data_bytes == 0) {
    fprintf(stderr, "[hash][kat] error: Msg_Len=%llu bits results in zero-byte message\n", msg_len_bits_val);
    any_fail = 1;
    continue;
}
msg_buf = (unsigned char *) calloc(1, msg_data_bytes);
if (msg_buf == NULL) {
    fprintf(stderr, "[hash][kat] error: failed to allocate %zu bytes for message "
            "(Msg_Len=%llu bits)\n", msg_data_bytes, msg_len_bits_val);
    any_fail = 1;
    continue;
}
```

---

### No upper bound check for msg_bytes before malloc
`ngcc_bench/src/bench_hash.c:329`
```
msg_bytes = (size_t) ((msg_len_bits_val + 7) / 8);

if (msg_bytes == 0 || digest_len == 0 || digest_len > msg_bytes) {
    fprintf(stderr, "[hash][kat_loop] error: invalid Msg_Len=%llu or Dst_Len=%d\n",
            msg_len_bits_val, dst_len_bits_val);
    return -1;
}

msg = (unsigned char *) malloc(msg_bytes);
```
**Issue**: The `msg_bytes` variable is computed from KAT file data and allocated directly without checking against `NGCC_MAX_BUFFER_LEN`. A malicious KAT file could cause allocation of arbitrary size, potentially exhausting memory or causing denial of service.
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
`ngcc_bench/src/drng.c:237-262`
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
**Issue**: The `nonce_len_bytes` parameter is used directly in malloc without validation. If an attacker-controlled large value is passed, it could cause integer overflow in the malloc size or excessive memory allocation. Additionally, `memcpy(seed_material, nonce, nonce_len_bytes)` at line 251 writes into a buffer that might be smaller than `nonce_len_bytes` if `SEEDLEN > nonce_len_bytes`.
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
memcpy(seed_material, nonce, nonce_len_bytes);
```

---

### get_random_number doesn't validate input pointers for NULL
`ngcc_bench/src/drng.c:322-324`
```
int get_random_number(DRNG_ctx *drng, unsigned char *random_number, unsigned long long random_number_len_bits)
{
    return SM3_DRNG_Generate(drng, random_number_len_bits, random_number);
}
```
**Issue**: The function doesn't check if `drng` or `random_number` are NULL before dereferencing them. This could cause null pointer dereference crashes.
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


## Medium

### KAT_LOOP_ITERATIONS of 1,000,000 runs without progress indication
`ngcc_bench/src/bench_hash.c:357`
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

### Circular left shift assumes msg_bytes > digest_len without validation
`ngcc_bench/src/bench_hash.c:360-362`
```
if (msg_bytes == 0 || digest_len == 0 || digest_len > msg_bytes) {
    fprintf(stderr, "[hash][kat_loop] error: invalid Msg_Len=%llu or Dst_Len=%d\n",
            msg_len_bits_val, dst_len_bits_val);
    return -1;
}

/* ... */
memcpy(buffer, msg, digest_len);
memmove(msg, msg + digest_len, msg_bytes - digest_len);
```
**Issue**: The circular left shift code at lines 360-362 uses `msg_bytes - digest_len` and `digest_len` without checking that `msg_bytes >= digest_len`. While line 331 checks `digest_len > msg_bytes`, if they are equal, `msg_bytes - digest_len = 0` which is valid. However, the validation at line 331 should also catch the edge case more explicitly.
**Fix**:
```
if (msg_bytes == 0 || digest_len == 0 || digest_len > msg_bytes) {
    fprintf(stderr, "[hash][kat_loop] error: invalid Msg_Len=%llu or Dst_Len=%d (msg_bytes=%zu, digest_len=%zu)\n",
            msg_len_bits_val, dst_len_bits_val, msg_bytes, digest_len);
    return -1;
}

/* ... */
/* Circular left shift is safe now due to validation above */
memcpy(buffer, msg, digest_len);
memmove(msg, msg + digest_len, msg_bytes - digest_len);
```

---

### MAX_INT macro misleadingly named for size types
`ngcc_bench/src/drng.c:244`
```
#define MAX_INT(a, b) ((a) > (b) ? (a) : (b))

seed_material = (unsigned char *)malloc(MAX_INT(nonce_len_bytes, SEEDLEN));
```
**Issue**: The `MAX_INT` macro is used to compare `size_t` values but is named "INT", which is misleading. The macro also has problematic behavior when comparing types of different sizes. This could cause confusion and bugs.
**Fix**:
```
/* Replace with properly typed max macro or use ternary directly */
seed_material = (unsigned char *)malloc((nonce_len_bytes > SEEDLEN) ? nonce_len_bytes : SEEDLEN);
```

---

### DRNG_ctx used without initialization before init_random_number call
`ngcc_bench/src/bench_hash.c:179-193`
```
DRNG_ctx drng;
msg_buf = (unsigned char *) calloc(1, msg_data_bytes > 0 ? msg_data_bytes : 1);
if (msg_buf == NULL) {
    /* ... */
}
if (init_random_number(&drng, msg_seed_f->data, msg_seed_f->len) != 0) {
    /* ... */
}
```
**Issue**: The `DRNG_ctx drng` variable is declared but not initialized before being passed to `init_random_number`. While `init_random_number` calls `SM3_DRNG_Instantiate` which does `memset(drng, 0, sizeof(*drng))`, relying on this is fragile and the caller's intent is unclear. If the API contract changes, this could become a bug.
**Fix**:
```
/* Explicitly initialize to zero for clarity and safety */
DRNG_ctx drng = {0};
msg_buf = (unsigned char *) calloc(1, msg_data_bytes > 0 ? msg_data_bytes : 1);
if (msg_buf == NULL) {
    /* ... */
}
if (init_random_number(&drng, msg_seed_f->data, msg_seed_f->len) != 0) {
    /* ... */
}
```

---

### Inconsistent error handling in check_field_len function
`ngcc_bench/src/bench_sig.c:309-313`
```
static int sig_check_field_len(const char *field_name, const ngcc_kat_field_t *data_field,
                               const ngcc_kat_field_t *len_field) {
    unsigned long long expected;
    if (len_field == NULL || data_field == NULL) {
        return 0;  /* no len field to validate */
    }
    expected = sig_field_to_u64(len_field);
    if (expected == 0) {
        return 0;  /* empty len value, skip */
    }
    if ((unsigned long long) data_field->len != expected) {
        fprintf(stderr, "[sig][kat] error: %s length mismatch: "
                "file says %llu bytes, data has %zu bytes\n",
                field_name, expected, data_field->len);
        return -1;
    }
    return 0;
}
```
**Issue**: The `sig_check_field_len` function returns 0 on success or no len field, but the caller treats the return value inconsistently. When length mismatch is found, it increments failed counter but the error path only continues, potentially leaving inconsistent state.
**Fix**:
```
/* The function is actually correct - returning 0 for "no error" and non-zero
 * for error. The caller handles it correctly by checking the return value.
 * The comment "no len field to validate" is misleading since it returns 0
 * (success) but the caller might interpret it differently. Consider changing
 * to a more explicit pattern. */
```

---


## Low

### Missing newline at end of file
`ngcc_bench/src/drng.c:325`
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

### Incomplete help message after removing options
`ngcc_bench/src/cli_parser.c:29-35`
```
printf("     [--digest-len-bits BITS]\n");
printf("     [--duration-hours H] [--stability-max-cases N] [--stability-sample-ms MS]\n");
printf("     [--json-out PATH] [--kat FILE]\n");
```
**Issue**: The help message was updated to remove `--iterations`, `--msg-len`, and `--cycles` options, but the ordering of remaining options is inconsistent with the implementation where `--digest-len-bits` appears at position 'b' but is listed third in usage.
**Fix**:
```
/* The help text is functionally correct, but could be clearer by grouping
 * related options together for better user experience */
printf("Required:\n");
printf("  --digest-len-bits BITS     Digest length in bits (required for hash tests)\n\n");
printf("Optional:\n");
printf("  --duration-hours H         Stability test duration (default: 6.0)\n");
printf("  --stability-max-cases N    Max cases for stability test (default: 3000)\n");
printf("  --stability-sample-ms MS   Sample interval for stability (default: 1.0)\n");
printf("  --json-out PATH            Write JSON report to file\n");
printf("  --kat FILE|DIR            KAT file or directory for correctness tests\n");
```

---


---

## GEMINI Review

# Code Review: openHiTLS/ngcc_bench#8
**Reviewer**: GEMINI


## Medium

### Total test count not incremented on validation failure
`ngcc_bench/src/bench_kem.c:213-221`
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
**Issue**: When a test vector fails the `_Len` field validation, `(*io_failed)` is incremented and the loop continues, but `(*io_total)` is never incremented. This results in inaccurate test statistics where `failed` can exceed `total`, or the failure rate is incorrectly reported.
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
**Issue**: When a test vector fails the `_Len` field validation, `(*io_failed)` is incremented and the loop continues, but `(*io_total)` is never incremented. This results in inaccurate test statistics where `failed` can exceed `total`.
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
        if (kex_field_populated(ngcc_kat_get_field(vec, "Init_Stb"))) {
            if (kex_check_field_len("Init_Stb",
                                    ngcc_kat_get_field(vec, "Init_Stb"),
                                    ngcc_kat_get_field(vec, "Init_Stb_Len")) != 0) {
                (*io_failed)++;
                continue;
            }
        }

        /* Validate key and SS length fields */
        if (kex_check_field_len("SKa", ska, ngcc_kat_get_field(vec, "SKa_Len")) != 0 ||
            kex_check_field_len("PKb", pkb, ngcc_kat_get_field(vec, "PKb_Len")) != 0 ||
            kex_check_field_len("SKb", skb, ngcc_kat_get_field(vec, "SKb_Len")) != 0 ||
            kex_check_field_len("PKa", pka, ngcc_kat_get_field(vec, "PKa_Len")) != 0 ||
            kex_check_field_len("SS", ss, ngcc_kat_get_field(vec, "SS_Len")) != 0) {
            (*io_failed)++;
            continue;
        }
```
**Issue**: In `verify_kex_kat_vectors`, when length validation fails (such as for keys, states, or messages), `(*io_failed)` is incremented and the vector is skipped. However, `(*io_total)` is not incremented, leading to incorrect statistics where failed vectors are not counted as part of the total cases.
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
        if (kex_field_populated(ngcc_kat_get_field(vec, "Init_Stb"))) {
            if (kex_check_field_len("Init_Stb",
                                    ngcc_kat_get_field(vec, "Init_Stb"),
                                    ngcc_kat_get_field(vec, "Init_Stb_Len")) != 0) {
                (*io_total)++;
                (*io_failed)++;
                continue;
            }
        }

        /* Validate key and SS length fields */
        if (kex_check_field_len("SKa", ska, ngcc_kat_get_field(vec, "SKa_Len")) != 0 ||
            kex_check_field_len("PKb", pkb, ngcc_kat_get_field(vec, "PKb_Len")) != 0 ||
            kex_check_field_len("SKb", skb, ngcc_kat_get_field(vec, "SKb_Len")) != 0 ||
            kex_check_field_len("PKa", pka, ngcc_kat_get_field(vec, "PKa_Len")) != 0 ||
            kex_check_field_len("SS", ss, ngcc_kat_get_field(vec, "SS_Len")) != 0) {
            (*io_total)++;
            (*io_failed)++;
            continue;
        }
```

---


## Low

### Redundant performance loops for KEM/KEX on failure
`ngcc_bench/src/main.c:356-368`
```
if (rc != 0) {
            printf("[%s][performance][%zuB] FAIL\n", test->name, msg_len);
            any_fail = 1;
            continue;
        }
```
**Issue**: When a performance test fails (`rc != 0`), the loop `continue`s. For KEM and KEX tests, which do not depend on message lengths, this skips the `break` statement at the end of the loop. Consequently, the test redundantly repeats the performance execution and failure logging for all remaining `msg_len` values even though they do not apply.
**Fix**:
```
if (rc != 0) {
            printf("[%s][performance][%zuB] FAIL\n", test->name, msg_len);
            any_fail = 1;
            if (test->kind != NGCC_TEST_HASH && test->kind != NGCC_TEST_DSA) {
                break;
            }
            continue;
        }
```

---


---

## CODEX Review

# Code Review: openHiTLS/ngcc_bench#8
**Reviewer**: CODEX


## High

### Public performance CLI flags were removed without a compatibility path
`ngcc_bench/src/cli_parser.c:19-25`
```
void print_usage(const char *prog) {
    printf("ngcc_bench %s\n\n", NGCC_VERSION);
    printf("Usage:\n");
    printf("  %s --lib /path/to/lib.so --test hash|dsa|dsa-keygen|dsa-sig|dsa-verify|kem|kem-keygen|kem-encap|kem-decap|kex|all --mode correctness|performance|memory|stability|all\n", prog);
    printf("     [--digest-len-bits BITS]\n");
    printf("     [--duration-hours H] [--stability-max-cases N] [--stability-sample-ms MS]\n");
    printf("     [--json-out PATH] [--kat FILE]\n");
    ...
}

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
**Issue**: This drops `--iterations`, `--msg-len`, and `--cycles` from the parser, so existing scripts and tests now fail before any benchmark runs. The branch still has callers that invoke those flags, and users also lose the ability to control benchmark size/count from the CLI.
**Fix**:
```
void print_usage(const char *prog) {
    printf("ngcc_bench %s\n\n", NGCC_VERSION);
    printf("Usage:\n");
    printf("  %s --lib /path/to/lib.so --test hash|dsa|dsa-keygen|dsa-sig|dsa-verify|kem|kem-keygen|kem-encap|kem-decap|kex|all --mode correctness|performance|memory|stability|all\n", prog);
    printf("     [--iterations N] [--duration-hours H] [--stability-max-cases N] [--stability-sample-ms MS] [--msg-len BYTES]\n");
    printf("     [--digest-len-bits BITS] [--cycles on|off] [--json-out PATH] [--kat FILE]\n");
    ...
}

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
```
jw_begin_object(&w, "options");
jw_key_llu(&w, "test_mask", opts->test_mask);
jw_key_llu(&w, "mode_mask", opts->mode_mask);
jw_key_double(&w, "duration_hours", opts->duration_hours);
jw_key_llu(&w, "stability_max_cases", opts->stability_max_cases);
jw_key_double(&w, "stability_sample_ms", opts->stability_sample_ms);

jw_begin_object(&w, "stability_thresholds");
...
if (opts->kat_path != NULL) {
    jw_key_str(&w, "kat", opts->kat_path);
} else {
    jw_key_null(&w, "kat");
}
jw_end_object(&w); /* options */
```
**Issue**: The report now omits `options.iterations`, `options.msg_len`, `options.digest_len_bits`, and `options.cycles`, so the bundled validator immediately fails with `missing key 'iterations'`. That makes the generated report incompatible with the schema shipped in this repo.
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

jw_begin_object(&w, "stability_thresholds");
...
if (opts->kat_path != NULL) {
    jw_key_str(&w, "kat", opts->kat_path);
} else {
    jw_key_null(&w, "kat");
}
jw_end_object(&w); /* options */
```

---

### Hash KAT handling now rejects previously supported files and aliases
`ngcc_bench/src/bench_hash.c:139-143`
```
const ngcc_kat_field_t *input = ngcc_kat_get_field(vec, "Msg");
const ngcc_kat_field_t *output = ngcc_kat_get_field(vec, "Dst");
...
if (!path_is_directory(kat_path)) {
    fprintf(stderr, "[hash][kat] error: --kat path is not a directory: %s\n", kat_path);
    return -1;
}
...
ftype = classify_kat_file(entry->d_name);
if (ftype == KAT_TYPE_UNKNOWN) {
    fprintf(stderr, "[hash][kat] error: unrecognized KAT file format: %s\n", entry->d_name);
    closedir(dir);
    rc = -1;
    goto done;
}
...
rc = (total > 0 && failed_count == 0) ? 0 : -1;
```
**Issue**: This path now only accepts directory entries named `KAT_2_*`/`KAT_Loop_*` and only looks for `Msg`/`Dst` fields. Previously supported single-file `--kat` inputs and documented aliases like `INPUT` and `MD` are skipped, and because `total == 0` now returns `-1`, correctness hard-fails instead of taking the existing `KAT_NO_VECTOR` fallback.
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

rc = (total == 0) ? 1 : ((failed_count == 0) ? 0 : -1);
```

---

### KEM KAT reader no longer accepts legacy alias-based inputs
`ngcc_bench/src/bench_kem.c:197-199`
```
const ngcc_kat_field_t *sk = ngcc_kat_get_field(vec, "SK");
const ngcc_kat_field_t *ct = ngcc_kat_get_field(vec, "CT");
const ngcc_kat_field_t *ss = ngcc_kat_get_field(vec, "SS");
...
if (!path_is_directory_kem(kat_path)) {
    fprintf(stderr, "[kem][kat] error: --kat path is not a directory: %s\n", kat_path);
    return -1;
}
...
if (strncmp(entry->d_name, "KAT_KEM_", 8) != 0) {
    fprintf(stderr, "[kem][kat] error: unrecognized KAT file: %s\n", entry->d_name);
    closedir(dir);
    goto done;
}
...
rc = (total > 0 && failed == 0) ? 0 : -1;
```
**Issue**: The new implementation only recognises `SK`/`CT`/`SS` fields inside `KAT_KEM_*` files under a directory. Previously supported `SECRETKEY`/`CIPHERTEXT`/`SHAREDSECRET` vectors, arbitrary filenames, and single-file `--kat` inputs are now skipped or rejected; when nothing matches, the function returns `-1` instead of `1`, so correctness fails rather than falling back.
**Fix**:
```
static const char *const k_sk_alias[] = {"SK", "SECRETKEY"};
static const char *const k_ct_alias[] = {"CT", "CIPHERTEXT"};
static const char *const k_ss_alias[] = {"SS", "SHAREDSECRET", "OUTPUT"};

const ngcc_kat_field_t *sk =
    ngcc_kat_get_field_any(vec, k_sk_alias, sizeof(k_sk_alias) / sizeof(k_sk_alias[0]));
const ngcc_kat_field_t *ct =
    ngcc_kat_get_field_any(vec, k_ct_alias, sizeof(k_ct_alias) / sizeof(k_ct_alias[0]));
const ngcc_kat_field_t *ss =
    ngcc_kat_get_field_any(vec, k_ss_alias, sizeof(k_ss_alias) / sizeof(k_ss_alias[0]));

if (!path_is_directory_kem(kat_path)) {
    ngcc_kat_file_t kat = {0};
    if (ngcc_kat_parse_file(kat_path, &kat) != 0) {
        return -1;
    }
    rc = verify_kem_kat_vectors(api, &kat, &total, &passed, &failed);
    ngcc_kat_free(&kat);
    goto done;
}

if (strncmp(entry->d_name, "KAT_KEM_", 8) != 0) {
    continue; /* ignore unrelated files in a shared --kat directory */
}

rc = (total == 0) ? 1 : ((failed == 0) ? 0 : -1);
```

---

### KEX KAT parsing dropped the existing underscore and PASS2/PASS3 formats
`ngcc_bench/src/bench_kex.c:313-317`
```
const ngcc_kat_field_t *ska = ngcc_kat_get_field(vec, "SKa");
const ngcc_kat_field_t *pkb = ngcc_kat_get_field(vec, "PKb");
const ngcc_kat_field_t *pka = ngcc_kat_get_field(vec, "PKa");
const ngcc_kat_field_t *skb = ngcc_kat_get_field(vec, "SKb");
const ngcc_kat_field_t *ss = ngcc_kat_get_field(vec, "SS");
...
for (pass = 1; pass <= KEX_MAX_PASS_SCAN; ++pass) {
    snprintf(m_name, sizeof(m_name), "M%d", pass);
    msg = ngcc_kat_get_field(vec, m_name);
    if (!kex_field_populated(msg)) {
        break;  /* no more passes */
    }
    ...
}
...
if (!path_is_directory_kex(kat_path)) {
    fprintf(stderr, "[kex][kat] error: --kat path is not a directory: %s\n", kat_path);
    return -1;
}
...
if (strncmp(entry->d_name, "KAT_KEX_", 8) != 0) {
    fprintf(stderr, "[kex][kat] error: unrecognized KAT file: %s\n", entry->d_name);
    closedir(dir);
    goto done;
}
```
**Issue**: This path now assumes the new multi-pass `Init_Sta`/`M1..Mn`/`SS` layout inside `KAT_KEX_*` directory entries. Existing vectors that use `SK_A`, `PK_B`, `PASS2`, `STATEA`, `SHAREDSECRETA` or the corresponding B-side fields are no longer recognised, so previously valid KATs now fail with `total=0 passed=0 failed=0`.
**Fix**:
```
static const char *const k_ska_alias[] = {"SKa", "SK_A"};
static const char *const k_pkb_alias[] = {"PKb", "PK_B"};
static const char *const k_skb_alias[] = {"SKb", "SK_B"};
static const char *const k_pka_alias[] = {"PKa", "PK_A"};
static const char *const k_m2_alias[] = {"M2", "MSG2", "PASS2"};
static const char *const k_m3_alias[] = {"M3", "MSG3", "PASS3"};
static const char *const k_sta_alias[] = {"Init_Sta", "STA", "STATEA", "ST_A"};
static const char *const k_stb_alias[] = {"Init_Stb", "STB", "STATEB", "ST_B"};
static const char *const k_ss_alias[] = {
    "SS", "SSA", "SSA_OUT", "SS_A", "SHAREDSECRETA",
    "SSB", "SSB_OUT", "SS_B", "SHAREDSECRETB"
};

const ngcc_kat_field_t *ska =
    ngcc_kat_get_field_any(vec, k_ska_alias, sizeof(k_ska_alias) / sizeof(k_ska_alias[0]));
const ngcc_kat_field_t *pkb =
    ngcc_kat_get_field_any(vec, k_pkb_alias, sizeof(k_pkb_alias) / sizeof(k_pkb_alias[0]));
const ngcc_kat_field_t *pka =
    ngcc_kat_get_field_any(vec, k_pka_alias, sizeof(k_pka_alias) / sizeof(k_pka_alias[0]));
const ngcc_kat_field_t *skb =
    ngcc_kat_get_field_any(vec, k_skb_alias, sizeof(k_skb_alias) / sizeof(k_skb_alias[0]));
const ngcc_kat_field_t *ss =
    ngcc_kat_get_field_any(vec, k_ss_alias, sizeof(k_ss_alias) / sizeof(k_ss_alias[0]));

if (mb_field == NULL) {
    mb_field = ngcc_kat_get_field_any(vec, k_m2_alias, sizeof(k_m2_alias) / sizeof(k_m2_alias[0]));
}
if (ma_field == NULL) {
    ma_field = ngcc_kat_get_field_any(vec, k_m3_alias, sizeof(k_m3_alias) / sizeof(k_m3_alias[0]));
}
if (sta_field == NULL) {
    sta_field = ngcc_kat_get_field_any(vec, k_sta_alias, sizeof(k_sta_alias) / sizeof(k_sta_alias[0]));
}
if (stb_field == NULL) {
    stb_field = ngcc_kat_get_field_any(vec, k_stb_alias, sizeof(k_stb_alias) / sizeof(k_stb_alias[0]));
}

if (!path_is_directory_kex(kat_path)) {
    ngcc_kat_file_t kat = {0};
    if (ngcc_kat_parse_file(kat_path, &kat) != 0) {
        return -1;
    }
    rc = verify_kex_kat_vectors(api, &kat, &total, &passed, &failed);
    ngcc_kat_free(&kat);
    goto done;
}

if (strncmp(entry->d_name, "KAT_KEX_", 8) != 0) {
    continue;
}

rc = (total == 0) ? 1 : ((failed == 0) ? 0 : -1);
```

---

### DSA-verify KAT support no longer matches the documented alias set
`ngcc_bench/src/bench_sig.c:325-327`
```
const ngcc_kat_field_t *pk = ngcc_kat_get_field(vec, "PK");
const ngcc_kat_field_t *msg = ngcc_kat_get_field(vec, "M");
const ngcc_kat_field_t *sn = ngcc_kat_get_field(vec, "Sn");
...
if (!path_is_directory_sig(kat_path)) {
    fprintf(stderr, "[sig][kat] error: --kat path is not a directory: %s\n", kat_path);
    return -1;
}
...
if (strncmp(entry->d_name, "KAT_SIG_", 8) != 0) {
    fprintf(stderr, "[sig][kat] error: unrecognized KAT file: %s\n", entry->d_name);
    closedir(dir);
    goto done;
}
...
rc = (total > 0 && failed == 0) ? 0 : -1;
```
**Issue**: The reader now only accepts `PK`, `M`, and `SN` fields inside `KAT_SIG_*` directory entries. Previously supported `PUBLICKEY`, `MSG`/`INPUT`/`MESSAGE`, and `SIG`/`SIGNATURE`/`OUTPUT` vectors are silently skipped; because zero matches now return `-1`, correctness reports FAIL instead of falling back.
**Fix**:
```
static const char *const k_pk_alias[] = {"PK", "PUBLICKEY"};
static const char *const k_msg_alias[] = {"M", "MSG", "INPUT", "MESSAGE"};
static const char *const k_sn_alias[] = {"SN", "SIG", "SIGNATURE", "SM", "OUTPUT"};

const ngcc_kat_field_t *pk =
    ngcc_kat_get_field_any(vec, k_pk_alias, sizeof(k_pk_alias) / sizeof(k_pk_alias[0]));
const ngcc_kat_field_t *msg =
    ngcc_kat_get_field_any(vec, k_msg_alias, sizeof(k_msg_alias) / sizeof(k_msg_alias[0]));
const ngcc_kat_field_t *sn =
    ngcc_kat_get_field_any(vec, k_sn_alias, sizeof(k_sn_alias) / sizeof(k_sn_alias[0]));

if (!path_is_directory_sig(kat_path)) {
    ngcc_kat_file_t kat = {0};
    if (ngcc_kat_parse_file(kat_path, &kat) != 0) {
        return -1;
    }
    rc = verify_sig_kat_vectors(api, &kat, &total, &passed, &failed);
    ngcc_kat_free(&kat);
    goto done;
}

if (strncmp(entry->d_name, "KAT_SIG_", 8) != 0) {
    continue;
}

rc = (total == 0) ? 1 : ((failed == 0) ? 0 : -1);
```

---


## Medium

### DSA sign and verify performance only benchmark the first message size
`ngcc_bench/src/main.c:353-401`
```
for (mi = 0; mi < NGCC_NUM_MSG_LENS; ++mi) {
    size_t msg_len = k_msg_lens[mi];

    rc = dispatch->performance_fn(api, digest_bits, msg_len, &cfg, &result);
    ...
    /* KEM/KEX/sub-ops don't depend on msg_len, run once only */
    if (test->kind != NGCC_TEST_HASH && test->kind != NGCC_TEST_DSA) {
        break;
    }
}
```
**Issue**: The loop is meant to run every `k_msg_lens` entry, but the break condition treats all sub-operations as message-length-independent. `ngcc_dsa_sig_performance()` and `ngcc_dsa_verify_performance()` both take `msg_len` and scale `bytes_per_op` with it, so this now reports only the 1024-byte case for those modes.
**Fix**:
```
static int performance_depends_on_msg_len(ngcc_test_kind_t kind) {
    return kind == NGCC_TEST_HASH ||
           kind == NGCC_TEST_DSA ||
           kind == NGCC_TEST_DSA_SIG ||
           kind == NGCC_TEST_DSA_VERIFY;
}

for (mi = 0; mi < NGCC_NUM_MSG_LENS; ++mi) {
    size_t msg_len = k_msg_lens[mi];

    rc = dispatch->performance_fn(api, digest_bits, msg_len, &cfg, &result);
    ...
    if (!performance_depends_on_msg_len(test->kind)) {
        break;
    }
}
```

---


## Low

### Mock KEX regression test still asserts the removed CLI and old output shape
`tests/test_mock_mlkex.c:79-84`
```
{
    char *const cmd[] = {
        argv[1], "--lib", argv[2], "--test", "kex", "--mode", "performance",
        "--iterations", "1000", "--cycles", "off", NULL
    };
    CHECK(run_expect(cmd, "[kex][performance] ops=", "[kex][performance][throughput]", "[kex][performance][time]") == 0,
          "performance failed");
}
```
**Issue**: The updated test still invokes `--iterations` and `--cycles`, and it still searches for the old `[kex][performance] ops=` format. Against this branch the command is rejected by the parser, and even after that is fixed the expected strings still do not match the new `[1024B]` output.
**Fix**:
```
{
    char *const cmd[] = {
        argv[1], "--lib", argv[2], "--test", "kex", "--mode", "performance", NULL
    };
    CHECK(run_expect(cmd,
                     "[kex][performance][1024B] ops=",
                     "[kex][performance][1024B][throughput]",
                     "[kex][performance][1024B][time]") == 0,
          "performance failed");
}
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
