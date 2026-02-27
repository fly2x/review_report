# Change Review Task

You are reviewing PR #1085 for openHiTLS/openhitls.


## Changed Files (13 files)

**Source** (11 files):
  - include/tls/hitls.h
  - include/tls/hitls_config.h
  - include/tls/hitls_type.h
  - tls/cm/src/conn_common.c
  - tls/config/src/config.c
  - tls/config/src/config_default.c
  - tls/handshake/pack/src/pack_extensions.c
  - tls/handshake/recv/src/recv_client_hello.c
  - tls/handshake/recv/src/recv_server_hello.c
  - tls/handshake/send/src/send_client_hello.c
  - tls/include/tls_config.h

**Test** (2 files):
  - testcode/sdv/testcase/tls/consistency/tls12/test_suite_sdv_frame_tls12_consistency_rfc7627.c
  - testcode/sdv/testcase/tls/consistency/tls12/test_suite_sdv_frame_tls12_consistency_rfc7627.data


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat cbef8b7a53155fee831b26f5f218e6c3f169ed0b mr-1085`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff cbef8b7a53155fee831b26f5f218e6c3f169ed0b mr-1085 -- <file>`
   - If you need more context, read the full file or search for related code
   - Look for: security issues, logic errors, edge cases, error handling
   - For non-code files (docs/config), focus on correctness and safety of the content

3. **Track Dependencies**
   - When you find a changed function, check its callers
   - When you see a new API, verify it's used correctly
   - Use grep/search to find related code

4. **Focus Areas**
   - Security: injection, auth bypass, data exposure, buffer overflow
   - Logic: null/nil checks, boundary conditions, error paths
   - API: breaking changes, compatibility, proper error returns
   - Resources: leaks, proper cleanup, race conditions
   - Documentation (Markdown/docs): incorrect or outdated instructions, wrong flags/paths,
     broken references, misleading examples, missing steps, or unsafe guidance
   - Config/build/CI: insecure defaults, mismatched versions, missing required keys

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
- Only flag issues in CHANGED lines (code or docs, not pre-existing issues)
- Be specific with line numbers
- Provide working fixes, not just descriptions
  - For docs, FIX should be the corrected text/snippet

Start the review now. Output each issue as you find it.
