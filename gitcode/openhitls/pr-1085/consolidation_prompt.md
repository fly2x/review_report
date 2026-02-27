# Change Review Consolidation Task

You are consolidating change review findings from multiple AI reviewers.

## Context
- Repository: openHiTLS/openhitls
- PR: #1085
- Title: 

## Individual Review Reports

## CODEX Review

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


---

## CLAUDE Review

# Code Review: openHiTLS/openhitls#1085
**Reviewer**: CLAUDE


## Low

### Unnecessary (void) casts for used parameters
`tls/handshake/recv/src/recv_client_hello.c:1216-1217`
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
**Issue**: The function ServerProcessClientHelloExt casts ctx and clientHello to (void) at the beginning, but these parameters are actually used later in the function (lines 1219-1232). The (void) casts are typically used to suppress unused parameter warnings, but here they are unnecessary.
**Fix**:
```
static int32_t ServerProcessClientHelloExt(TLS_Ctx *ctx, const ClientHelloMsg *clientHello)
{
#ifdef HITLS_TLS_FEATURE_EXTENDED_MASTER_SECRET
    (void)ret;  // Keep this, ret is unused
    /* Sets the extended master key flag */
    if (ctx->config.tlsConfig.emsMode == HITLS_EMS_MODE_FORCE &&
        !clientHello->extension.flag.haveExtendedMasterSecret) {
```

---

### Default EMS mode changes behavior vs legacy API
`tls/config/src/config_default.c:307-308`
```
static void BasicInitConfig(HITLS_Config *config)
{
    config->isSupportExtendedMasterSecret = false;
    config->emsMode = HITLS_EMS_MODE_PREFER;
```
**Issue**: The default initialization sets emsMode to HITLS_EMS_MODE_PREFER (0), which means clients will send the EMS extension by default. The legacy field isSupportExtendedMasterSecret is set to false. With PREFER mode, clients WILL send the EMS extension (unlike the previous default behavior). This could be a behavioral change that affects compatibility with servers that don't handle EMS extension correctly.
**Fix**:
```
static void BasicInitConfig(HITLS_Config *config)
{
    config->isSupportExtendedMasterSecret = false;
    config->emsMode = HITLS_EMS_MODE_FORBID;  /* Don't send EMS extension by default */
```

---

### Unnecessary (void) cast for used parameter
`tls/handshake/recv/src/recv_client_hello.c:966`
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
**Issue**: In ResumeCheckExtendedMasterScret, clientHello is cast to (void) but is actually used on line 970 to check haveExtendedMasterSecret flag.
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
