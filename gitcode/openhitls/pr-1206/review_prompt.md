# Change Review Task

You are reviewing PR #1206 for openHiTLS/openhitls.


## Local Repository Context

- Repository root: `openhitls-1206/openhitls`
- Base ref: `66e4ff606a68a762b80d4c4bd8a14ec5f968dbc0`
- Head ref: `mr-1206`
- The change under review is already checked out locally in this repository.

## Changed Files (31 files)

**Source** (13 files):
  - bsl/obj/src/bsl_obj.c
  - include/pki/hitls_pki_cms.h
  - include/pki/hitls_pki_errno.h
  - include/pki/hitls_pki_params.h
  - include/pki/hitls_pki_types.h
  - pki/cms/include/hitls_cms_local.h
  - pki/cms/src/hitls_cms_common.c
  - pki/cms/src/hitls_cms_envelopeddata.c
  - pki/cms/src/hitls_cms_signdata.c
  - pki/cms/src/hitls_cms_util.c
  - pki/x509_common/include/hitls_x509_local.h
  - pki/x509_common/src/hitls_x509_attrs.c
  - pki/x509_common/src/hitls_x509_common.c

**Test** (16 files):
  - testcode/sdv/testcase/pki/cms/test_suite_sdv_cms_envelope.c
  - testcode/sdv/testcase/pki/cms/test_suite_sdv_cms_envelope.data
  - testcode/testdata/cert/asn1/cms/envelopeddata/de_encode_cases/env_case1.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/de_encode_cases/env_case2.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/de_encode_cases/env_case3.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/de_encode_cases/env_case4.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/de_encode_cases/env_case5_originator_crl.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/de_encode_cases/env_case6_originator_crl_attrs.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/de_encode_cases/env_case7_two_recip.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/de_encode_cases/env_case8_ski_rid.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/rsa/envdata_rsa.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/rsa/message.txt
  - testcode/testdata/cert/asn1/cms/envelopeddata/rsa/recip1.crt.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/rsa/recip1.key.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/rsa/rsa_p1.key.der
  - testcode/testdata/cert/asn1/cms/envelopeddata/rsa/rsa_p1_v1.crt.der

**Other** (2 files):
  - cmake/config.h.in
  - cmake/hitls_define_dependencies.cmake


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat 66e4ff606a68a762b80d4c4bd8a14ec5f968dbc0 mr-1206`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff 66e4ff606a68a762b80d4c4bd8a14ec5f968dbc0 mr-1206 -- <file>`
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
