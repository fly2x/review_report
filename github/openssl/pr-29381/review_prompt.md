# Code Review Task

You are reviewing PR #29381 for openssl/openssl.
**Title**:  Added LMS support for OpenSSL commandline signature verification using pkeyutl.

## Changed Files (61 files)

**Source** (15 files):
  - crypto/encode_decode/decoder_lib.c
  - crypto/encode_decode/decoder_pkey.c
  - crypto/lms/lms_key.c
  - crypto/lms/lms_params.c
  - include/crypto/lms.h
  - include/openssl/evp.h
  - providers/implementations/encode_decode/decode_der2key.c
  - providers/implementations/encode_decode/encode_key2any.c
  - providers/implementations/encode_decode/encode_key2text.c
  - providers/implementations/encode_decode/lms_codecs.c
  - providers/implementations/include/prov/implementations.h
  - providers/implementations/include/prov/lms_codecs.h
  - providers/implementations/include/prov/names.h
  - providers/implementations/keymgmt/lms_kmgmt.c
  - providers/implementations/signature/lms_signature.c

**Test** (37 files):
  - test/lms_test.c
  - test/recipes/15-test_lms_codecs.t
  - test/recipes/15-test_lms_codecs_data/sha256_n24_w1_msg.bin
  - test/recipes/15-test_lms_codecs_data/sha256_n24_w1_pub.der
  - test/recipes/15-test_lms_codecs_data/sha256_n24_w1_pub.pem
  - test/recipes/15-test_lms_codecs_data/sha256_n24_w1_pub.txt
  - test/recipes/15-test_lms_codecs_data/sha256_n24_w1_sig.bin
  - test/recipes/15-test_lms_codecs_data/shake_n24_w1_msg.bin
  - test/recipes/15-test_lms_codecs_data/shake_n24_w1_pub.der
  - test/recipes/15-test_lms_codecs_data/shake_n24_w1_pub.pem
  - test/recipes/15-test_lms_codecs_data/shake_n24_w1_pub.txt
  - test/recipes/15-test_lms_codecs_data/shake_n24_w1_sig.bin
  - test/recipes/15-test_lms_codecs_data/shake_n24_w2_msg.bin
  - test/recipes/15-test_lms_codecs_data/shake_n24_w2_pub.der
  - test/recipes/15-test_lms_codecs_data/shake_n24_w2_pub.pem
  - test/recipes/15-test_lms_codecs_data/shake_n24_w2_pub.txt
  - test/recipes/15-test_lms_codecs_data/shake_n24_w2_sig.bin
  - test/recipes/15-test_lms_codecs_data/shake_n24_w4_msg.bin
  - test/recipes/15-test_lms_codecs_data/shake_n24_w4_pub.der
  - test/recipes/15-test_lms_codecs_data/shake_n24_w4_pub.pem
  - ... and 17 more

**Docs** (1 files):
  - CHANGES.md

**Other** (8 files):
  - doc/man7/EVP_PKEY-LMS.pod
  - doc/man7/EVP_SIGNATURE-LMS.pod
  - doc/man7/OSSL_PROVIDER-base.pod
  - doc/man7/OSSL_PROVIDER-default.pod
  - providers/decoders.inc
  - providers/encoders.inc
  - providers/implementations/encode_decode/build.info
  - providers/implementations/keymgmt/lms_kmgmt.inc.in


## Your Task

Perform a thorough code review by:

1. **Understand the Change**
   - Read the diff stats: `git diff --stat bcc33dfcd9038d46be3bd84b32d14942977f1c38 pr-29381`
   - Understand what this PR is trying to achieve

2. **Review Each File**
   - For each changed file, view its diff: `git diff bcc33dfcd9038d46be3bd84b32d14942977f1c38 pr-29381 -- <file>`
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
