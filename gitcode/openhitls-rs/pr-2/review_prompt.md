# Change Review Task

You are reviewing PR #2 for openHiTLS/openhitls-rs.


## Changed Files (27 files)

**Source** (18 files):
  - bsl/src/bsl_obj.rs
  - bsl/src/lib.rs
  - configure.py
  - crypto/src/aes.rs
  - crypto/src/crypt_algid.rs
  - crypto/src/crypt_types.rs
  - crypto/src/ecc_pkey_crypt.rs
  - crypto/src/ecc_pkey_gen.rs
  - crypto/src/ecdsa.rs
  - crypto/src/lib.rs
  - crypto/src/rng.rs
  - crypto/src/sha2_256.rs
  - openhitls/src/aes.rs
  - openhitls/src/ecc_pkey_crypt.rs
  - openhitls/src/ecc_pkey_gen.rs
  - openhitls/src/ecdsa.rs
  - openhitls/src/lib.rs
  - openhitls/src/sha2_256.rs

**Test** (2 files):
  - test/Cargo.toml
  - test/src/main.rs

**Config** (4 files):
  - Cargo.toml
  - bsl/Cargo.toml
  - crypto/Cargo.toml
  - openhitls/Cargo.toml

**Docs** (1 files):
  - README.md

**Other** (2 files):
  - .gitignore
  - Cargo.lock


## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat ef142a9ac9ee30c4bdf633fcdce6c02453cd08ef mr-2`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff ef142a9ac9ee30c4bdf633fcdce6c02453cd08ef mr-2 -- <file>`
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
