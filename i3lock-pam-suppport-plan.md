# Sequential PAM conversations for i3lock

## Summary

Implement sequential PAM support in five reviewable milestones. The first product target is Himmelblau/Entra; the
architecture supports standard Linux-PAM conversations and leaves room for a later explicit automatic biometric flow.

The external harness remains the end-to-end test suite. OpenBSD bsd_auth remains unchanged.

## 1. Strengthen the external harness

- Extend the bridge protocol with one genuine multi-message pam_conv batch command, preserving each message’s original
  index.

- Add passing baseline characterisation tests against current i3lock:
  - repeated hidden prompts replay one submitted buffer;
  - a mixed TEXT_INFO / ECHO_OFF / ECHO_ON batch reaches one callback;
  - the Himmelblau replay remains reproducible.

- Add controllable backend-delay scenarios so cancellation can be tested both while PAM is waiting for input and while
  pam_authenticate() is between callbacks.

Gate: make test passes against unmodified local i3lock.

## 2. Add the fork-safe controller foundation

- Remove early PAM initialization. Do not create controller state, synchronization primitives, pipe descriptors, or
  threads before both existing forks are complete.

- Start the controller exactly once in the first XCB_MAP_NOTIFY handler:
  - if daemonizing is enabled, only at the end of the child continuation after fork() and ev_loop_fork(EV_DEFAULT);
  - if --nofork is set, at the same point after that skipped-fork conditional;
  - use a dedicated controller_started guard, not dont_fork, to make this explicit.

- The earlier raise-loop fork has already completed by this point. No i3lock fork may occur after controller
  initialization.

- The worker owns pam_start, pam_set_item, pam_authenticate, pam_setcred, and pam_end. It creates a fresh PAM handle for
  each explicit authentication attempt and ends that handle before accepting another attempt.

- Add the fundamental safety mechanisms now:
  - monotonic transaction IDs and prompt IDs;
  - mutex-protected event queue plus libev-watched wake-up pipe;
  - one bounded secure-storage region for UI input, deferred input, and pending responses; mlock() it once and abort if
    locking fails, matching i3lock's existing password-memory policy;
  - immediate wiping of i3lock-owned copies on transfer, failure, and cancellation;
  - removal of credential values from debug output.

Gate: Ordinary hidden-password success/failure remains functional in both normal daemonizing and --nofork harness runs; no
worker exists before the final process is established.

## 3. Implement the sequential PAM state machine

Use these explicit controller states:

State                Meaning and allowed transition
━━━━━━━━━━━━━━━━━━━  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
IDLE                 Controller ready; user may type. Enter stages one deferred submission and moves to AUTH_STARTING.
───────────────────  ─────────────────────────────────────────────────────────────────────────────────────────────────────
AUTH_STARTING        Worker begins pam_authenticate(). It moves to AUTH_RUNNING or WAITING_PROMPT. Escape moves to
AUTH_CANCELLING.
───────────────────  ─────────────────────────────────────────────────────────────────────────────────────────────────────
AUTH_RUNNING         PAM is active without an outstanding input prompt. It may emit status, request a prompt, complete,
or receive cancellation.
───────────────────  ─────────────────────────────────────────────────────────────────────────────────────────────────────
WAITING_PROMPT       One identified prompt waits for a matching fresh answer. Submit moves to AUTH_RUNNING; Escape moves
to AUTH_CANCELLING.
───────────────────  ─────────────────────────────────────────────────────────────────────────────────────────────────────
AUTH_CANCELLING      Transaction is invalidated and UI is idle-looking; worker cleanup is outstanding. A later Enter is
rejected and its input is cleared. The user must submit again after cleanup completes.
───────────────────  ─────────────────────────────────────────────────────────────────────────────────────────────────────
AUTH_FAILED_DELAY    Active transaction has completed unsuccessfully; existing Wrong! delay applies. Input/Enter queues
one retry. Timer expiry moves to IDLE or starts the queued retry.
───────────────────  ─────────────────────────────────────────────────────────────────────────────────────────────────────
AUTH_SUCCEEDED       Active transaction completed successfully; worker refreshes credentials and cleans up, then the
main loop exits.
───────────────────  ─────────────────────────────────────────────────────────────────────────────────────────────────────
AUTH_FATAL           PAM_ABORT ended the handle. i3lock stays locked with a fatal authentication-service error and does
not retry.

- Every worker event includes transaction_id; prompt events and submitted answers include prompt_id.
  - The UI accepts only events for the active transaction and prompt.
  - Retired transaction events, including late success, can never update UI or unlock.

- Enter starts pam_authenticate() only for an explicit user submission.
  - The deferred value answers only the first actual PAM_PROMPT_ECHO_OFF.
  - If the first input prompt is PAM_PROMPT_ECHO_ON, securely discard the deferred masked value, display the visible
    prompt, and require visible re-entry.

  - Every later prompt requires fresh input.

- Escape invalidates transaction authority immediately.
  - If the worker is waiting in pam_conv, signal its condition variable and return PAM_CONV_ERR.
  - If the worker is inside backend work between callbacks, set cancellation requested but do not attempt to interrupt
    PAM; the worker checks cancellation before the next prompt and again after pam_authenticate() returns.

  - A cancelled transaction never refreshes credentials or unlocks, even if PAM later returns success.
  - The UI does not block waiting for worker termination.
  - A submission made while cancellation cleanup is still pending is not queued. i3lock clears that input and requires a
    fresh Enter after cleanup completes. Retaining a post-cancel submission would require a separate mlocked snapshot
    buffer and is intentionally out of scope for this branch.

- Map controller states onto the existing indicator enums without replacing their current meaning: AUTH_STARTING and
  AUTH_RUNNING use STATE_AUTH_VERIFY; WAITING_PROMPT uses normal input/STATE_AUTH_IDLE presentation; AUTH_FAILED_DELAY
  uses STATE_AUTH_WRONG; AUTH_FATAL uses STATE_I3LOCK_LOCK_FAILED. Existing unlock states continue to drive keypress,
  backspace, and input highlighting.

Gate: Harness proves wrong Himmelblau PIN followed by a fresh correct PIN succeeds, prompt IDs reject stale answers, and
cancellation during both prompt wait and backend delay cannot unlock.

## 4. Implement complete PAM batches and presentation

- Process each pam_conv(num_msg, ...) call atomically in the worker:
  1. Allocate one zeroed pam_response[num_msg].
  2. Process messages in index order.
  3. For PAM_TEXT_INFO and PAM_ERROR_MSG, enqueue status and retain resp[index] = NULL.
  4. For every ECHO_OFF or ECHO_ON prompt, wait for its matching prompt ID and write the response at the same index.
  5. Return success only after all prompts are answered.
  6. On cancellation, unsupported style, or allocation failure, wipe/free values still owned by i3lock and return
     PAM_CONV_ERR. After successful callback return, never touch PAM-owned response strings.

- Maintain prompt presentation metadata, not separate semantics:
  - LATENT means an active first standalone hidden prompt whose provider label is not rendered; i3lock keeps its
    ordinary masked-input indicator with no grey label or additional waiting state;
  - only a first standalone hidden prompt may be LATENT;
  - all prompts remain real active prompts regardless of visibility;
  - preceding info/error, visible input, or any later prompt forces visible presentation;
  - never infer prompt meaning from text.

- Render retained provider status and active prompt below the indicator:
  - up to two wrapped UTF-8 status lines plus one prompt line;
  - ellipsis truncate excess text;
  - style PAM_ERROR_MSG as error without treating it as a terminal failure;
  - persist status until superseded or transaction completion;
  - visibly echo ECHO_ON; mask ECHO_OFF.

- On terminal failure, clear provider text and retain the current Wrong! delay and retry behaviour.

Gate: Harness validates response index ordering for a mixed batch; Xephyr confirms ordinary password stays visually quiet
while Himmelblau PIN/password/MFA text is understandable and survives retry delays.

## 5. Stabilize and document

### Approved authentication policy

- A completed PAM attempt is always retired with `pam_end()` before i3lock
  accepts another submission. This includes `PAM_MAXTRIES`; it terminates the
  current transaction, not i3lock itself.
- `PAM_MAXTRIES` follows the normal failed-attempt path: i3lock remains locked,
  clears the submitted input, applies the existing retry delay, and requires a
  new explicit Enter to create a fresh PAM transaction. It never reuses the
  exhausted handle or queues input while cleanup is pending. This preserves
  recovery when a provider or one of its methods reaches a transaction-local
  limit, while provider-wide lockout and rate-limiting policy remain enforced
  by the configured PAM stack.
- `PAM_ABORT` remains fatal: i3lock stays locked and does not start another
  transaction.
- `pam_authenticate()` and `pam_acct_mgmt()` must both succeed before i3lock
  can unlock. Their failures are fail-closed.
- After those checks succeed, `pam_setcred(PAM_REFRESH_CRED)` is best-effort.
  A refresh failure is logged and supplied as the status to `pam_end()`, but it
  does not revoke the successful unlock. This availability policy is approved
  for the organization’s supported PAM profiles.
- Harness coverage must keep asserting these decisions: a fresh handle after
  `PAM_MAXTRIES`, no retained submission during cancellation cleanup,
  fail-closed account-management failure, and successful unlock after a
  credential-refresh failure.

- Exercise daemonizing, --nofork, cancellation, late completion, retry, and repeated cleanup paths.
- The worker exclusively owns every PAM handle. On successful, non-cancelled authentication it calls
  pam_setcred(PAM_REFRESH_CRED) before posting success, then calls pam_end; the main thread never accesses that handle.
  Preserve current behaviour by not downgrading a successful authentication solely because credential refresh fails.
- Define terminal PAM errors explicitly: PAM_ABORT ends its handle and enters AUTH_FATAL, leaving i3lock locked with a
  fatal service-error display and no retry. PAM_SYSTEM_ERR and PAM_SERVICE_ERR end and discard the handle, display an
  error through the normal failure delay, and permit a fresh transaction afterwards.
- Follow-up cleanup: avoid exporting PAM display globals directly through `unlock_indicator.h`. Prefer a narrow
  renderer-facing boundary, either a `struct pam_display_state` passed to the renderer or a small setter/getter API owned
  by `i3lock.c`. This is architectural cleanup, not a correctness gate for the sequential PAM work.
- Follow-up UI improvement: replace the current one-line ellipsized PAM prompt/status rendering with a real bounded
  multi-line text layout. A practical next iteration is to reserve a rectangular text region below the indicator, split
  provider text on UTF-8 word boundaries, render at most two status lines plus one prompt line, and ellipsize only the
  final visible line. This should be implemented together with the renderer-boundary cleanup so layout decisions are not
  spread across exported PAM globals.
- Review each terminal path for pam_end status, transaction retirement, worker cleanup, and secret wiping.
- Update i3lock documentation for:
  - sequential standard PAM conversations;
  - visible-input prompts;
  - Escape cancellation semantics;
  - no credential logging.

- Update harness documentation with the final Himmelblau and mixed-batch regression coverage.

Gate: Full harness suite passes against a clean local i3lock build, with no changes to system PAM configuration,
Himmelblau, Entra, or host lock state.

## Non-negotiable invariants

- No controller thread or synchronization primitive exists before i3lock’s final fork point.
- Exactly one PAM transaction is active at a time.
- Every UI-affecting event and answer is transaction/prompt identified.
- PAM batch response indexes exactly match PAM message indexes.
- Cancellation removes unlock/UI authority immediately, even if backend PAM work continues.
- The worker exclusively owns each PAM handle, including pam_setcred and pam_end.
- i3lock wipes every credential copy it controls and never logs entered credentials.
