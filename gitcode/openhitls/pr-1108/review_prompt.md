# Change Review Task

You are reviewing PR #1108 for openHiTLS/openhitls.


## Local Repository Context

- Repository root: `openhitls-1108/openhitls`
- Base ref: `de23ecd19189f4a0203f9586aa42953ed6b58057`
- Head ref: `mr-1108`
- The change under review is already checked out locally in this repository.

## Changed Files (87 files)

**Source** (26 files):
  - bsl/obj/src/bsl_cid_op.c
  - bsl/obj/src/bsl_obj.c
  - config/macro_config/hitls_config_check.h
  - config/macro_config/hitls_config_layer_crypto.h
  - crypto/codecskey/include/crypt_decoder.h
  - crypto/codecskey/src/crypt_codecskey_local.c
  - crypto/codecskey/src/crypt_codecskey_local.h
  - crypto/codecskey/src/crypt_decoder_composite.c
  - crypto/codecskey/src/crypt_decoder_der2key.c
  - crypto/composite/include/crypt_composite.h
  - crypto/composite/src/composite.c
  - crypto/composite/src/composite_encdec.c
  - crypto/composite/src/composite_local.h
  - crypto/eal/src/eal_pkey_method.c
  - crypto/eal/src/eal_pkey_params.c
  - crypto/provider/include/crypt_default_provderimpl.h
  - crypto/provider/src/default/crypt_default_decode.c
  - crypto/provider/src/default/crypt_default_keymgmt.c
  - crypto/provider/src/default/crypt_default_provider.c
  - crypto/provider/src/default/crypt_default_sign.c
  - ... and 6 more

**Test** (58 files):
  - testcode/sdv/CMakeLists.txt
  - testcode/sdv/testcase/crypto/composite/test_suite_sdv_composite.c
  - testcode/sdv/testcase/crypto/composite/test_suite_sdv_composite.data
  - testcode/sdv/testcase/pki/cert/test_suite_sdv_x509_cert.data
  - testcode/test_config/crypto_test_config.json
  - testcode/testdata/cert/asn1/composite_cert/mldsa44_ecdsa_p256_sha256_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa44_ed25519_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa44_rsa2048_pkcs15_sha256_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa44_rsa2048_pss_sha256_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa65_ecdsa_brainpoolp256r1_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa65_ecdsa_p256_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa65_ecdsa_p384_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa65_ed25519_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa65_rsa3072_pkcs15_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa65_rsa3072_pss_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa65_rsa4096_pkcs15_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa65_rsa4096_pss_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa87_ecdsa_brainpoolp384r1_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa87_ecdsa_p384_sha512_cert.pem
  - testcode/testdata/cert/asn1/composite_cert/mldsa87_ecdsa_p521_sha512_cert.pem
  - ... and 38 more

**Config** (3 files):
  - config/json/compile.json
  - config/json/complete_options.json
  - config/json/feature.json


## Hard Constraints

- Review ONLY the local repository checkout in the current working directory.
- Use local git/file inspection only.
- If a git command fails, retry with another local command or inspect the changed files directly.
- If local tooling is limited, continue from the checked-out files and changed-file list instead of switching to network search.

## Your Task

Perform a thorough change review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat de23ecd19189f4a0203f9586aa42953ed6b58057 mr-1108`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff de23ecd19189f4a0203f9586aa42953ed6b58057 mr-1108 -- <file>`
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
