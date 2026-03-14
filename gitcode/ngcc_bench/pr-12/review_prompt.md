# Change Review Task

You are reviewing PR #12 for openHiTLS/ngcc_bench.


## Changed Files (25 files)

**Source** (12 files):
  - ngcc_bench/include/bench_kex.h
  - ngcc_bench/include/bench_sig.h
  - ngcc_bench/include/cli_types.h
  - ngcc_bench/include/ngcc_api.h
  - ngcc_bench/include/stability.h
  - ngcc_bench/src/bench_kex.c
  - ngcc_bench/src/bench_sig.c
  - ngcc_bench/src/cli_parser.c
  - ngcc_bench/src/interactive.c
  - ngcc_bench/src/loader.c
  - ngcc_bench/src/main.c
  - ngcc_bench/src/stability.c

**Test** (6 files):
  - tests/compare_stability_reports.py
  - tests/test_cli_regression.c
  - tests/test_mock_mldsa.c
  - tests/test_mock_mlkem.c
  - tests/test_unit.c
  - tests/validate_json_report.py

**Config** (2 files):
  - docs/json_schema_v3.json
  - docs/json_schema_v4.json

**Docs** (5 files):
  - README.md
  - docs/architecture.md
  - docs/cli.md
  - docs/design_alignment.md
  - docs/json_schema.md


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat df3a25672230e3b85fd3e2fda26cf8b888434a99 mr-12`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff df3a25672230e3b85fd3e2fda26cf8b888434a99 mr-12 -- <file>`
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
