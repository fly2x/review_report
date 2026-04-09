# Change Review Task

You are reviewing PR #1223 for openHiTLS/openhitls.


## Local Repository Context

- Repository root: `openhitls-1223/openhitls`
- Base ref: `e6f9560091967dbcdddde9c74ce5a8aa771cba08`
- Head ref: `mr-1223`
- The change under review is already checked out locally in this repository.

## Changed Files (68 files)

**Source** (17 files):
  - bsl/asn1/src/bsl_asn1.c
  - bsl/obj/src/bsl_obj.c
  - include/bsl/bsl_obj.h
  - include/pki/hitls_pki_cms.h
  - include/pki/hitls_pki_errno.h
  - include/pki/hitls_pki_params.h
  - include/pki/hitls_pki_timestamp.h
  - include/pki/hitls_pki_types.h
  - pki/cms/include/hitls_cms_local.h
  - pki/cms/include/hitls_ts_local.h
  - pki/cms/src/hitls_cms_signdata.c
  - pki/cms/src/hitls_cms_util.c
  - pki/cms/src/hitls_cms_util.h
  - pki/cms/src/hitls_ts_ess.c
  - pki/cms/src/hitls_ts_req.c
  - pki/cms/src/hitls_ts_resp.c
  - pki/cms/src/hitls_ts_token.c

**Test** (51 files):
  - testcode/sdv/testcase/pki/cms/test_suite_sdv_cms_sign.c
  - testcode/sdv/testcase/pki/cms/test_suite_sdv_cms_sign.data
  - testcode/testdata/cert/asn1/cms/ts/certs/cms_signer_cert.pem
  - testcode/testdata/cert/asn1/cms/ts/certs/cms_signer_key.pem
  - testcode/testdata/cert/asn1/cms/ts/certs/intermediate_ca.pem
  - testcode/testdata/cert/asn1/cms/ts/certs/root_ca.pem
  - testcode/testdata/cert/asn1/cms/ts/certs/tsa_cert.pem
  - testcode/testdata/cert/asn1/cms/ts/certs/tsa_chain.pem
  - testcode/testdata/cert/asn1/cms/ts/certs/tsa_key.pem
  - testcode/testdata/cert/asn1/cms/ts/certs/tsa_untrusted.pem
  - testcode/testdata/cert/asn1/cms/ts/cms/attached.cms
  - testcode/testdata/cert/asn1/cms/ts/cms/attached.txt
  - testcode/testdata/cert/asn1/cms/ts/cms/cades.cms
  - testcode/testdata/cert/asn1/cms/ts/cms/cades.txt
  - testcode/testdata/cert/asn1/cms/ts/cms/detached.cms
  - testcode/testdata/cert/asn1/cms/ts/cms/detached.txt
  - testcode/testdata/cert/asn1/cms/ts/cms/noattr.cms
  - testcode/testdata/cert/asn1/cms/ts/cms/noattr.txt
  - testcode/testdata/cert/asn1/cms/ts/input/msg.bin
  - testcode/testdata/cert/asn1/cms/ts/input/msg.sha256.hex
  - ... and 31 more


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat e6f9560091967dbcdddde9c74ce5a8aa771cba08 mr-1223`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff e6f9560091967dbcdddde9c74ce5a8aa771cba08 mr-1223 -- <file>`
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
