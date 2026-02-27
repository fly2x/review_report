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
