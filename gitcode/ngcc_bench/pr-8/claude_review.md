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
