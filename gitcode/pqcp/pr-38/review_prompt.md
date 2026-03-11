# Change Review Task

You are reviewing PR #38 for openHiTLS/pqcp.


## Changed Files (83 files)

**Source** (22 files):
  - include/pqcp_err.h
  - include/pqcp_types.h
  - src/composite_sign/include/crypt_composite_sign.h
  - src/composite_sign/src/crypt_composite_sign.c
  - src/composite_sign/src/crypt_composite_sign_encdec.c
  - src/polarlac/include/crypt_polarlac.h
  - src/polarlac/src/polarlac.c
  - src/polarlac/src/polarlac_kem.c
  - src/polarlac/src/polarlac_local.h
  - src/polarlac/src/polarlac_ntt.c
  - src/polarlac/src/polarlac_ntt1024.c
  - src/polarlac/src/polarlac_pke.c
  - src/polarlac/src/polarlac_polar.c
  - src/polarlac/src/polarlac_poly.c
  - src/polarlac/src/polarlac_rand.c
  - src/provider/pqcp_pkey.c
  - src/provider/pqcp_provider.c
  - src/provider/pqcp_provider_impl.h
  - src/scloudplus/include/scloudplus.h
  - src/scloudplus/src/scloudplus.c
  - ... and 2 more

**Test** (58 files):
  - test/README.md
  - test/common/pqcp_fuzz.c
  - test/common/pqcp_fuzz.h
  - test/common/pqcp_perf.c
  - test/common/pqcp_perf.h
  - test/common/pqcp_test.c
  - test/common/pqcp_test.h
  - test/fuzz/fuzz_test.c
  - test/perf/perf_kem.c
  - test/perf/perf_kem.h
  - test/perf/perf_test.c
  - test/script/build.sh
  - test/script/run_fuzz.sh
  - test/script/run_perf.sh
  - test/script/run_sdv.sh
  - test/sdv/integration/integration_test.c
  - test/sdv/kem/kem_test.c
  - test/sdv/kem/kem_test.h
  - test/sdv/kem/scloudplus_test.c
  - test/sdv/kem/scloudplus_testvector.zip
  - ... and 38 more

**Docs** (1 files):
  - CMakeLists.txt

**Other** (2 files):
  - .clang-format
  - build_pqcp.sh


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat d42fbf507d1e4ddf1c182996aea76bb0cf3635ed mr-38`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff d42fbf507d1e4ddf1c182996aea76bb0cf3635ed mr-38 -- <file>`
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
