# Code Review: openHiTLS/openhitls#1004
**Reviewer**: CODEX


## High

### RegisterFd can leave a freed node in the list
`bsl/async/src/async_notify.c:142-161`
```
newFd->next = ctx->fds;
ctx->fds = newFd;

if (ctx->fdChangeList != NULL) {
    struct AsyncFdEvent *event = (struct AsyncFdEvent *)BSL_SAL_Calloc(1, sizeof(struct AsyncFdEvent));
    if (event == NULL) {
        BSL_SAL_FREE(newFd);
        ...
    }
    ...
    if (BSL_LIST_AddElement(ctx->fdChangeList, event, BSL_LIST_POS_END) != BSL_SUCCESS) {
        BSL_SAL_FREE(event);
        BSL_SAL_FREE(newFd);
        return BSL_ASYNC_ERR;
    }
}
```
**Issue**: The new FD node is linked into `ctx->fds` before the change event is created. If event allocation or list insertion fails, the node is freed but `ctx->fds` still points to it, causing list corruption and use-after-free.
**Fix**:
```
struct AsyncFdEvent *event = NULL;
if (ctx->fdChangeList != NULL) {
    event = (struct AsyncFdEvent *)BSL_SAL_Calloc(1, sizeof(struct AsyncFdEvent));
    if (event == NULL) {
        BSL_SAL_FREE(newFd);
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }
    event->fd = fd;
    event->type = ASYNC_EVENT_ADD;
    if (BSL_LIST_AddElement(ctx->fdChangeList, event, BSL_LIST_POS_END) != BSL_SUCCESS) {
        BSL_SAL_FREE(event);
        BSL_SAL_FREE(newFd);
        return BSL_ASYNC_ERR;
    }
}

newFd->next = ctx->fds;
ctx->fds = newFd;
```

---


## Medium

### Coroutine ID generation never updates the shared counter
`bsl/async/src/async.c:108-116`
```
BSL_SAL_RefCount threadStartNum = {
    .count = ScheduleGet()->idGen
};
ret = BSL_SAL_AtomicUpReferences(&threadStartNum, &ref);
```
**Issue**: The atomic increment is applied to a local copy of `idGen`, so the shared counter in the scheduler is never updated. This returns duplicate IDs and is not thread-safe.
**Fix**:
```
/* async_local.h */
struct AsyncSchedule {
    int32_t state;
    BSL_SAL_RefCount idGen;
    size_t stackSize;
    unsigned int corpoolCoroutineNum;
    bool stackProtect;
    struct CoroutinePool pool;
    BSL_SAL_ThreadLockHandle poolLock;
};

/* async.c */
static struct AsyncSchedule *ScheduleAlloc(void)
{
    struct AsyncSchedule *schedule = (struct AsyncSchedule *)BSL_SAL_Calloc(1, sizeof(struct AsyncSchedule));
    if (schedule == NULL) {
        ...
    }
    (void)BSL_SAL_ReferencesInit(&schedule->idGen);
    schedule->state = SCHEDULE_INIT;
    return schedule;
}

static int32_t CoroutineNewid(void)
{
    int32_t ref = 0;
    struct AsyncSchedule *schedule = ScheduleGet();
    if (schedule == NULL) {
        return 0;
    }
    (void)BSL_SAL_AtomicUpReferences(&schedule->idGen, &ref);
    return ref;
}

void BSL_ASYNC_ScheduleFree(void)
{
    struct AsyncSchedule *schedule = ScheduleGet();
    if (schedule == NULL) {
        return;
    }
    schedule->state = SCHEDULE_EXITING;
    CoroutinePoolDestroy(schedule);
    BSL_SAL_ReferencesFree(&schedule->idGen);
    BSL_SAL_FREE(schedule);
    ScheduleSet(NULL);
}
```

---

### Swapcontext failure check is inverted
`bsl/async/src/async.c:553-560`
```
job->status = ASYNC_JOB_STOPPING;
if (AsyncSwapcontext(&job->ctx, &ctx->dispatcher) == 0) {
    BSL_ERR_PUSH_ERROR(BSL_ASYNC_UCONTEXT_SWAP_FAIL);
    BSL_LOG_BINLOG_FIXLEN(...);
}
```
**Issue**: `AsyncSwapcontext` returns `BSL_SUCCESS` (0) on success, but the code logs an error when it succeeds and ignores real failures. On failure, the coroutine continues looping and re-executes the job.
**Fix**:
```
job->status = ASYNC_JOB_STOPPING;
int32_t swapRet = AsyncSwapcontext(&job->ctx, &ctx->dispatcher);
if (swapRet != BSL_SUCCESS) {
    BSL_ERR_PUSH_ERROR(BSL_ASYNC_UCONTEXT_SWAP_FAIL);
    BSL_LOG_BINLOG_FIXLEN(BINLOG_ID05103, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                          "async start run func swap context fail.", 0, 0, 0, 0);
}
```

---

### Missing status handling causes infinite loop
`bsl/async/src/async.c:636-669`
```
while (true) {
    int status = ctx->currjob->status;
    if (status == ASYNC_JOB_STOPPING) { ... }
    if (status == ASYNC_JOB_READY) { ... }
    if (status == ASYNC_JOB_PAUSING) { ... }
    if (status == ASYNC_JOB_PAUSED) { ... }
}
```
**Issue**: If `status` is `ASYNC_JOB_RUNNING` or any unexpected value, the loop never changes state and spins forever. This can deadlock a caller that accidentally re-enters `BSL_ASYNC_Start`.
**Fix**:
```
while (true) {
    int status = ctx->currjob->status;
    switch (status) {
        case ASYNC_JOB_STOPPING:
            ...
            return BSL_ASYNC_FINISH;
        case ASYNC_JOB_READY:
            ...
            continue;
        case ASYNC_JOB_PAUSING:
            ...
            return BSL_ASYNC_PAUSE;
        case ASYNC_JOB_PAUSED:
            ...
            continue;
        default:
            BSL_ERR_PUSH_ERROR(BSL_ASYNC_ERR);
            ctx->currjob = NULL;
            return BSL_ASYNC_ERR;
    }
}
```

---

### Removed FDs are still visible to Lookup and Collect
`bsl/async/src/async_notify.c:168-214`
```
while (curr != NULL) {
    if (curr->key == key) {
        *fd = curr->fd;
        ...
        return BSL_SUCCESS;
    }
    curr = curr->next;
}
```
**Issue**: `RemoveFd` only marks entries as deleted, but `BSL_NOTIFY_CTX_LookupFd` and `BSL_NOTIFY_CTX_CollectAllFds` ignore `del`, so removed FDs remain visible and contradict the expected behavior (tests expect NOT_FOUND after removal).
**Fix**:
```
while (curr != NULL) {
    if (curr->del) {
        curr = curr->next;
        continue;
    }
    if (curr->key == key) {
        *fd = curr->fd;
        if (customData != NULL) {
            *customData = curr->customData;
        }
        return BSL_SUCCESS;
    }
    curr = curr->next;
}
```

---

### PollFdChanges never consumes the change list
`bsl/async/src/async_notify.c:218-259`
```
*addedCount = addTotal;
*removedCount = delTotal;

return BSL_SUCCESS;
```
**Issue**: The function returns the same events on every call and the list grows unbounded. This contradicts the API comment (consume when arrays are provided) and keeps deleted entries from being finalized unless a coroutine yield occurs.
**Fix**:
```
*addedCount = addTotal;
*removedCount = delTotal;

if (addedFds != NULL || removedFds != NULL) {
    AsyncCleanupFdChanges(ctx);
}

return BSL_SUCCESS;
```

---


## Low

### RemoveFd path skips cleanup callback
`bsl/async/src/async_notify.c:314-319`
```
if (*pp == target) {
    *pp = target->next;
    BSL_SAL_FREE(target);
    return true;
}
```
**Issue**: When a newly-added FD is removed before being polled, `NotifyCtxDetachFdNode` frees the node without calling the cleanup callback, leaking resources such as the FD or associated data.
**Fix**:
```
if (*pp == target) {
    if (target->cleanup != NULL) {
        target->cleanup(ctx, target->fd);
    }
    *pp = target->next;
    BSL_SAL_FREE(target);
    return true;
}
```

---
