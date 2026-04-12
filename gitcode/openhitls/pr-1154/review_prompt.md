# Change Review Task

You are reviewing PR #1154 for openHiTLS/openhitls.


## Local Repository Context

- Repository root: `openhitls-1154/openhitls`
- Base ref: `9d2dc392c81ef0675c050a9bc66f3ca44e60fcb0`
- Head ref: `mr-1154`
- The change under review is already checked out locally in this repository.

## Changed Files (120 files)

**Source** (8 files):
  - crypto/provider/src/default/crypt_default_provider.c
  - include/tls/hitls_cert_type.h
  - include/tls/hitls_crypt_type.h
  - tls/cert/cert_adapt/cert.c
  - tls/config/src/config_check.c
  - tls/config/src/config_sign.c
  - tls/crypt/include/crypt.h
  - tls/handshake/common/src/hs_cert.c

**Test** (112 files):
  - testcode/framework/tls/include/hlt_type.h
  - testcode/framework/tls/rpc/src/hitls_func.c
  - testcode/sdv/testcase/tls/ciphersuite/test_suite_sdv_hlt_group_signature.c
  - testcode/sdv/testcase/tls/ciphersuite/test_suite_sdv_hlt_group_signature.data
  - testcode/testdata/tls/certificate/der/composite/ca.der
  - testcode/testdata/tls/certificate/der/composite/ca.key.der
  - testcode/testdata/tls/certificate/der/composite/end.der
  - testcode/testdata/tls/certificate/der/composite/end.key.der
  - testcode/testdata/tls/certificate/der/composite/inter.der
  - testcode/testdata/tls/certificate/der/composite/inter.key.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ecdsa_p256_sha256/ca.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ecdsa_p256_sha256/ca.key.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ecdsa_p256_sha256/end.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ecdsa_p256_sha256/end.key.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ecdsa_p256_sha256/inter.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ecdsa_p256_sha256/inter.key.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ed25519_sha512/ca.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ed25519_sha512/ca.key.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ed25519_sha512/end.der
  - testcode/testdata/tls/certificate/der/composite/mldsa44_ed25519_sha512/end.key.der
  - ... and 92 more


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 9d2dc392c81ef0675c050a9bc66f3ca44e60fcb0 mr-1154`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 9d2dc392c81ef0675c050a9bc66f3ca44e60fcb0 mr-1154 -- <file>`
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
