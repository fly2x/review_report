# Final Code Review Report
## openHiTLS/openhitls - PR #1085

### Summary
- **Total Issues**: 5
- **Critical**: 0
- **High**: 1
- **Medium**: 0
- **Low**: 4
- **Reviewers**: claude, gemini, codex

---


## High

### EMS force check ignores legacy compatibility field, allowing silent downgrade
`tls/handshake/recv/src/recv_server_hello.c:164`
**Reviewers**: CODEX | **置信度**: 较可信
```
if (ctx->config.tlsConfig.emsMode == HITLS_EMS_MODE_FORCE && !serverHello->haveExtendedMasterSecret) {
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17084, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "ExtendedMasterSecret err", 0, 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
    return HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET;
}
```
**Issue**: The new EMS FORCE check only validates `emsMode` without considering the legacy `isSupportExtendedMasterSecret` flag. If existing code sets `isSupportExtendedMasterSecret = true` directly using the old API (HITLS_CFG_SetSupportExtendedMasterSecret), the `emsMode` remains `HITLS_EMS_MODE_PREFER`. Consequently, the client will not enforce EMS and may unexpectedly accept a non-EMS ServerHello, creating a backward compatibility gap that weakens security guarantees.
**Fix**:
```
int32_t emsMode = ctx->config.tlsConfig.emsMode;
/* Backward compatibility: legacy flag true implies FORCE mode. */
if (ctx->config.tlsConfig.isSupportExtendedMasterSecret) {
    emsMode = HITLS_EMS_MODE_FORCE;
}
if (emsMode == HITLS_EMS_MODE_FORCE && !serverHello->haveExtendedMasterSecret) {
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17084, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "ExtendedMasterSecret err", 0, 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
    return HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET;
}
```

---


## Low

### New API documentation omits invalid-mode error return
`include/tls/hitls.h:1804-1806`
**Reviewers**: CODEX | **置信度**: 可信
```
/**
 * @brief   Set extended master secret mode.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   mode [IN] EMS mode. See HITLS_EMS_MODE_*.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, if ctx is NULL.
 */
int32_t HITLS_SetExtendedMasterSecretMode(HITLS_Ctx *ctx, int32_t mode);
```
**Issue**: The public API documentation for `HITLS_SetExtendedMasterSecretMode` does not document `HITLS_INVALID_INPUT` as a possible return value. However, the underlying implementation (`HITLS_CFG_SetExtendedMasterSecretMode` at config.c:1347-1348) returns this error code when an invalid mode value (other than FORBID, PREFER, or FORCE) is passed. Users calling this API with invalid mode values will receive an undocumented error code.
**Fix**:
```
/**
 * @brief   Set extended master secret mode.
 *
 * @param   ctx  [IN] TLS connection handle
 * @param   mode [IN] EMS mode. See HITLS_EMS_MODE_*.
 * @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, if ctx is NULL.
 * @retval  HITLS_INVALID_INPUT, if mode is invalid.
 */
int32_t HITLS_SetExtendedMasterSecretMode(HITLS_Ctx *ctx, int32_t mode);
```

---

### Unnecessary (void) casts for used parameters
`tls/handshake/recv/src/recv_client_hello.c:1216-1217`
**Reviewers**: CLAUDE | **置信度**: 可信
```
static int32_t ServerProcessClientHelloExt(TLS_Ctx *ctx, const ClientHelloMsg *clientHello)
{
#ifdef HITLS_TLS_FEATURE_EXTENDED_MASTER_SECRET
    int32_t ret = HITLS_SUCCESS;
    (void)ret;
    (void)clientHello;  // Parameter IS used below
    (void)ctx;          // Parameter IS used below
    /* Sets the extended master key flag */
    if (ctx->config.tlsConfig.emsMode == HITLS_EMS_MODE_FORCE &&
        !clientHello->extension.flag.haveExtendedMasterSecret) {
```
**Issue**: The function `ServerProcessClientHelloExt` casts `ctx` and `clientHello` parameters to (void) at the beginning to suppress unused parameter warnings. However, both parameters are actually used later in the function at lines 1219-1220. The (void) casts are misleading and should be removed for the parameters that are used.
**Fix**:
```
static int32_t ServerProcessClientHelloExt(TLS_Ctx *ctx, const ClientHelloMsg *clientHello)
{
#ifdef HITLS_TLS_FEATURE_EXTENDED_MASTER_SECRET
    (void)ret;  /* Keep this, ret is intentionally unused */
    /* Sets the extended master key flag */
    if (ctx->config.tlsConfig.emsMode == HITLS_EMS_MODE_FORCE &&
        !clientHello->extension.flag.haveExtendedMasterSecret) {
```

---

### Unnecessary (void) cast for used parameter
`tls/handshake/recv/src/recv_client_hello.c:966`
**Reviewers**: CLAUDE | **置信度**: 可信
```
static int32_t ResumeCheckExtendedMasterScret(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, HITLS_Session **sess)
{
    if (*sess == NULL) {
        return HITLS_SUCCESS;
    }
    (void)clientHello;
    bool haveExtMasterSecret = false;
    HITLS_SESS_GetHaveExtMasterSecret(*sess, &haveExtMasterSecret);
    if (haveExtMasterSecret) {
        if (!clientHello->extension.flag.haveExtendedMasterSecret) {
```
**Issue**: In function `ResumeCheckExtendedMasterScret`, the parameter `clientHello` is cast to (void) at line 966, but is actually used at line 970 to check the `haveExtendedMasterSecret` flag. The (void) cast is misleading and should be removed.
**Fix**:
```
static int32_t ResumeCheckExtendedMasterScret(TLS_Ctx *ctx, const ClientHelloMsg *clientHello, HITLS_Session **sess)
{
    if (*sess == NULL) {
        return HITLS_SUCCESS;
    }
    bool haveExtMasterSecret = false;
    HITLS_SESS_GetHaveExtMasterSecret(*sess, &haveExtMasterSecret);
    if (haveExtMasterSecret) {
        if (!clientHello->extension.flag.haveExtendedMasterSecret) {
```

---

### Default EMS mode changes behavior vs legacy API
`tls/config/src/config_default.c:307-308`
**Reviewers**: CLAUDE | **置信度**: 需评估
```
static void BasicInitConfig(HITLS_Config *config)
{
    config->isSupportExtendedMasterSecret = false;
    config->emsMode = HITLS_EMS_MODE_PREFER;
```
**Issue**: The default initialization sets `emsMode` to `HITLS_EMS_MODE_PREFER` (0), which means clients will send the EMS extension by default (per pack_extensions.c:951: `haveExtendedMasterSecret = (tlsConfig->emsMode != HITLS_EMS_MODE_FORBID)`). The legacy field `isSupportExtendedMasterSecret` is set to false. With PREFER mode, clients WILL send the EMS extension, unlike the previous default behavior. This behavioral change could affect compatibility with servers that do not handle the EMS extension correctly. This needs human evaluation to determine if this is an intentional design change or an unintended side effect.
**Fix**:
```
static void BasicInitConfig(HITLS_Config *config)
{
    config->isSupportExtendedMasterSecret = false;
    config->emsMode = HITLS_EMS_MODE_FORBID;  /* Don't send EMS extension by default for backward compatibility */
```

---
