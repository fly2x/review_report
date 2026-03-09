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
