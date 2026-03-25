# Change Review Task

You are reviewing PR #1032 for openHiTLS/openhitls.


## Local Repository Context

- Repository root: `openhitls-1032/openhitls`
- Base ref: `9d2dc392c81ef0675c050a9bc66f3ca44e60fcb0`
- Head ref: `mr-1032`
- The change under review is already checked out locally in this repository.

## Changed Files (21 files)

**Source** (12 files):
  - bsl/sal/include/sal_ip_util.h
  - bsl/sal/src/sal_ip_util.c
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

**Test** (9 files):
  - testcode/framework/tls/callback/src/cert_callback.c
  - testcode/sdv/testcase/bsl/sal/test_suite_sdv_sal_ip.c
  - testcode/sdv/testcase/bsl/sal/test_suite_sdv_sal_ip.data
  - testcode/sdv/testcase/pki/common/test_suite_sdv_common.c
  - testcode/sdv/testcase/tls/interface_tlcp/test_suite_sdv_frame_cert_interface.c
  - testcode/sdv/testcase/tls/interface_tlcp/test_suite_sdv_frame_cert_interface.data
  - testcode/testdata/tls/certificate/der/rsa_with_san_ext/rootca.der
  - testcode/testdata/tls/certificate/der/rsa_with_san_ext/server.der
  - testcode/testdata/tls/certificate/der/rsa_with_san_ext/server.key.der


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- Do NOT search the web.
- Do NOT open GitHub, GitLab, Gitee, or GitCode pages for this review.
- Do NOT rely on remote PR pages or web search results for code analysis.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 9d2dc392c81ef0675c050a9bc66f3ca44e60fcb0 mr-1032`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 9d2dc392c81ef0675c050a9bc66f3ca44e60fcb0 mr-1032 -- <file>`
   - If you need more context, read the full file or search for related code
   - Look for: security issues, logic errors, edge cases, error handling
   - Treat assembly files (`.S`, `.s`, `.asm`) as source code and review ABI/calling convention,
     register and stack preservation, memory addressing, bounds, and architecture guards
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
   - Assembly: calling convention mismatches, save/restore bugs, bad clobbers,
     stack alignment, incorrect addressing, missing feature/architecture guards
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
