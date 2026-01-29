# Code Review Task

You are reviewing PR #1032 for openHiTLS/openhitls.


## Changed Files (19 files)

**Source** (13 files):
  - include/pki/hitls_pki_errno.h
  - include/pki/hitls_pki_types.h
  - include/tls/hitls_cert.h
  - include/tls/hitls_cert_type.h
  - include/tls/hitls_error.h
  - pki/x509_common/src/hitls_x509_util.c
  - pki/x509_verify/include/hitls_x509_verify.h
  - pki/x509_verify/src/hitls_x509_verify.c
  - tls/cert/hitls_x509_adapt/hitls_x509_cert_store.c
  - tls/config/src/config_cert.c
  - tls/crypt/crypt_self/hitls_crypt.c
  - tls/handshake/parse/src/parse_server_key_exchange.c
  - tls/include/tls_config.h

**Test** (6 files):
  - testcode/framework/tls/callback/src/cert_callback.c
  - testcode/sdv/testcase/tls/interface_tlcp/test_suite_sdv_frame_cert_interface.c
  - testcode/sdv/testcase/tls/interface_tlcp/test_suite_sdv_frame_cert_interface.data
  - testcode/testdata/tls/certificate/der/rsa_with_san_ext/rootca.der
  - testcode/testdata/tls/certificate/der/rsa_with_san_ext/server.der
  - testcode/testdata/tls/certificate/der/rsa_with_san_ext/server.key.der


## Your Task

Perform a thorough code review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat ddc55f85b6b2f3b6a7d657bd9374876e44d20ae7 mr-1032`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff ddc55f85b6b2f3b6a7d657bd9374876e44d20ae7 mr-1032 -- <file>`
   - If you need more context, read the full file or search for related code
   - Look for: security issues, logic errors, edge cases, error handling

3. **Track Dependencies**
   - When you find a changed function, check its callers
   - When you see a new API, verify it's used correctly
   - Use grep/search to find related code

4. **Focus Areas**
   - Security: injection, auth bypass, data exposure, buffer overflow
   - Logic: null/nil checks, boundary conditions, error paths
   - API: breaking changes, compatibility, proper error returns
   - Resources: leaks, proper cleanup, race conditions

## Output Format - CRITICAL

You MUST output each issue in the EXACT format below. Do NOT output summaries, tables, or prose.
Your ONLY output should be ===ISSUE=== blocks. No introduction, no conclusion.

For each issue found, output EXACTLY:

===ISSUE===
FILE: <filepath>
LINE: <line number or range>
SEVERITY: critical|high|medium|low
TITLE: <concise title>
PROBLEM: <what's wrong>
CODE:
```
<problematic code>
```
FIX:
```
<suggested fix>
```
===END===

## Rules

- ONLY output ===ISSUE=== blocks, nothing else
- Do NOT write summaries or conclusions
- Do NOT use markdown headers or bullet points outside of issue blocks
- Only flag issues in CHANGED code (not pre-existing issues)
- Be specific with line numbers
- Provide working fixes, not just descriptions

Start the review now. Output each issue as you find it.
