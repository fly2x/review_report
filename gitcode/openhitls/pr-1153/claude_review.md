# Code Review: openHiTLS/openhitls#1153
**Reviewer**: CLAUDE


## Low

### Inconsistent register naming in PolyzUnpack19Asm
`crypto/mldsa/src/asm/polyz_unpack_armv8.S:145-146`
```
polyz_unpack_19_loop:
    ldr q_buf1, [buf, #16]
    ldr d2, [buf, #32]
    ldr q0, [buf], #40
```
**Issue**: The PolyzUnpack19Asm function uses raw register names (d2, q0) instead of the defined aliases (buf2, buf0) used elsewhere in the code. This is inconsistent with the coding style and could cause confusion during maintenance. The code is functionally correct because d2 is the lower 64 bits of v2 (aliased as buf2), and the index table only accesses bytes 0-7 which are properly loaded.
**Fix**:
```
polyz_unpack_19_loop:
    ldr q_buf1, [buf, #16]
    ldr q_buf2, [buf, #32]
    ldr q_buf0, [buf], #40
```

---
