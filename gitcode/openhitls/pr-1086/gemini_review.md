# Code Review: openHiTLS/openhitls#1086
**Reviewer**: GEMINI


## High

### Command Injection via hkey parameter
`configure.py:521`
```
# Use the openssl command to generate an HMAC file.
            cmake += 'install(CODE "execute_process(COMMAND openssl dgst -hmac \\\"%s\\\" -%s -out lib%s.so.hmac lib%s.so)")\n' % (self._args.hkey, self._hmac, lib_name, lib_name)
```
**Issue**: The `hkey` argument, which can be controlled by the user via `--hkey`, is directly interpolated into a shell command string used in `execute_process`. A malicious user could supply a crafted `hkey` containing shell metacharacters (e.g., `"; rm -rf /; "`) to execute arbitrary commands during the install phase.
**Fix**:
```
# Use the openssl command to generate an HMAC file.
            # Use list format for COMMAND to avoid shell injection
            cmake += 'install(CODE "execute_process(COMMAND openssl dgst -hmac \\\"%s\\\" -%s -out lib%s.so.hmac lib%s.so)")\n' % (self._args.hkey.replace('"', '\\"'), self._hmac, lib_name, lib_name)
            # Ideally validate self._args.hkey contains only safe characters
```

---

### Insecure Memory Clearing (Dead Store Elimination)
`bsl/sal/src/sal_mem.c:112-145`
```
static void CleanSensitiveData(void *buf, uint32_t bufLen)
{
    uint8_t *tmp = (uint8_t *)buf;
    // ... (complex alignment logic) ...
    for (uint32_t i = boundOpt; i < bufLen; ++i) {
        tmp[i] = 0;
    }
}
```
**Issue**: The `CleanSensitiveData` function manually zeroes out memory using a loop and simple assignment. The file also enables `-O3` optimization. Modern compilers can optimize away these write operations (Dead Store Elimination) if the memory is freed immediately afterwards (which `BSL_SAL_ClearFree` does), leaving sensitive data in memory.
**Fix**:
```
static void CleanSensitiveData(void *buf, uint32_t bufLen)
{
    volatile uint8_t *tmp = (volatile uint8_t *)buf;
    for (uint32_t i = 0; i < bufLen; ++i) {
        tmp[i] = 0;
    }
}
```

---


## Medium

### Logic Error: Stdin Closed Prematurely
`apps/src/app_client.c:520`
```
BSL_UIO *rUio = HITLS_APP_UioOpen(NULL, 'r', 1);
    BSL_UIO_SetIsUnderlyingClosedByUio(rUio, true);
    if (rUio == NULL) {
```
**Issue**: In `ConfirmAction` (used for SM mode confirmation), `stdin` is opened via `HITLS_APP_UioOpen(NULL, ...)` and then `BSL_UIO_SetIsUnderlyingClosedByUio(rUio, true)` is called. When `BSL_UIO_Free(rUio)` is called at the end of the function, it closes `stdin`. Subsequent attempts to read from `stdin` in `HandleClientDataExchange` will fail.
**Fix**:
```
BSL_UIO *rUio = HITLS_APP_UioOpen(NULL, 'r', 1);
    BSL_UIO_SetIsUnderlyingClosedByUio(rUio, false); // Do not close stdin when freeing UIO
    if (rUio == NULL) {
```

---
