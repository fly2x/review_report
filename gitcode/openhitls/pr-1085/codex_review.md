# Code Review: openHiTLS/openhitls#1085
**Reviewer**: CODEX


## High

### EMS force check ignores legacy compatibility field, allowing silent downgrade
`tls/handshake/recv/src/recv_server_hello.c:164`
```
if (ctx->config.tlsConfig.emsMode == HITLS_EMS_MODE_FORCE && !serverHello->haveExtendedMasterSecret) {
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17084, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
        "ExtendedMasterSecret err", 0, 0, 0, 0);
    ctx->method.sendAlert(ctx, ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE);
    return HITLS_MSG_HANDLE_INVALID_EXTENDED_MASTER_SECRET;
}
```
**Issue**: The new check uses only `emsMode`. If existing callers set `config->isSupportExtendedMasterSecret = true` directly (legacy/internal usage still present), `emsMode` can remain `HITLS_EMS_MODE_PREFER`, so the client no longer enforces EMS and may accept a non-EMS ServerHello unexpectedly.
**Fix**:
```
int32_t emsMode = ctx->config.tlsConfig.emsMode;
/* Backward compatibility: legacy flag true implies FORCE. */
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
```
* @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, if ctx is NULL.
 */
int32_t HITLS_SetExtendedMasterSecretMode(HITLS_Ctx *ctx, int32_t mode);
```
**Issue**: `HITLS_SetExtendedMasterSecretMode` can return `HITLS_INVALID_INPUT` (via `HITLS_CFG_SetExtendedMasterSecretMode`) for unsupported mode values, but this is not documented in the public API comment.
**Fix**:
```
* @retval  HITLS_SUCCESS, if successful.
 * @retval  HITLS_NULL_INPUT, if ctx is NULL.
 * @retval  HITLS_INVALID_INPUT, if mode is invalid.
 */
int32_t HITLS_SetExtendedMasterSecretMode(HITLS_Ctx *ctx, int32_t mode);
```

---
