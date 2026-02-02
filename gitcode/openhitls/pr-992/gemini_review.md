# Code Review: openhitls/openhitls#992
**Reviewer**: GEMINI


## Critical

### HSS Tree Index Calculation Uses Wrong Level Height
`crypto/lms/src/hss_utils.c:274`
```
for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
        uint32_t childHeight = para->levelPara[i + 1].height;
        sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << childHeight);
    }
```
**Issue**: The calculation of `sigsPerTree[i]` incorrectly uses the height of the child level (`i + 1`) instead of the current level (`i`). `sigsPerTree[i]` represents the capacity (number of bottom-level signatures) covered by a tree at level `i`. It should be `sigsPerTree[i + 1] * (1 << height_of_level_i)`. The current code computes `sigsPerTree[i + 1] * (1 << height_of_level_i_plus_1)`, effectively using the child's height twice. This results in incorrect tree and leaf indices when different levels have different heights (e.g., h=10 at level 0, h=20 at level 1).
**Fix**:
```
for (int32_t i = (int32_t)para->levels - 2; i >= 0; i--) {
        uint32_t height = para->levelPara[i].height;
        sigsPerTree[i] = sigsPerTree[i + 1] * (1ULL << height);
    }
```

---


## Medium

### Unsafe Memory Allocation for Large Merkle Trees
`crypto/lms/src/lms_core.c:133`
```
uint32_t numLeaves = 1u << para->height;
    size_t treeSize = 2 * numLeaves * para->n;
    uint8_t *tree = BSL_SAL_Calloc(treeSize, 1);
```
**Issue**: `LmsComputeRoot` allocates memory for the entire Merkle tree (`2 * numLeaves * n`). While `LmsParaInit` restricts height to 15 (max ~1MB), `LmsLookupParamSet` supports heights up to 25. If `LmsComputeRoot` is called with a valid parameter set for h=20 (1M leaves) or h=25 (32M leaves) — which is permitted by `LmsLookupParamSet` — it will attempt to allocate 64MB or 2GB of contiguous memory, potentially causing Denial of Service or OOM on constrained systems. The implementation should either support large trees using a low-memory algorithm (e.g., TreeHash) or explicitly validate `height` within `LmsComputeRoot` against the implementation's limit.
**Fix**:
```
// Validate height to prevent excessive memory allocation
    if (para->height > LMS_MAX_PRACTICAL_HEIGHT) {
        return CRYPT_LMS_INVALID_PARAM;
    }

    uint32_t numLeaves = 1u << para->height;
    size_t treeSize = 2 * numLeaves * para->n;
    uint8_t *tree = BSL_SAL_Calloc(treeSize, 1);
```

---
