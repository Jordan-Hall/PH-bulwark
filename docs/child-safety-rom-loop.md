# Child Safety ROM — the build-&-improve loop (orchestration prompt)

A reusable `/loop` you can fire to drive the **Child Safety ROM** to completion with
parallel sub-agents, then keep fine-tuning — written from actually running it (see the
"hard-won lessons" at the bottom, which the prompt already encodes).

## How to run it

Paste the **PROMPT** block below after `/loop` (no interval = self-paced dynamic mode;
prefix with `2m ` only while there is active build-out to babysit):

```
/loop <PROMPT>
```

Spec it executes: `docs/design/child-safety-rom.md` (rungs A/B/C, owner rulings) +
`docs/design/child-safety-rom-build.md` (B/C build + architecture). Progress ledger:
`.superpowers/sdd/progress.md`.

---

## THE PROMPT

> You are the controller for the **Child Safety ROM** build. Drive the buildable work to
> completion, then keep improving it. Work autonomously; stop only for the GATES below.
>
> **On each wake:** read the ledger (`.superpowers/sdd/progress.md`) + `git log` first —
> never redo a completed task. Then pick the next buildable item from the QUEUE. If a
> background agent died on a process exit, **check its worktree for uncommitted partial
> work and salvage it** before re-dispatching (`git -C <worktree> status`).
>
> **QUEUE (skip device/host-gated rungs until unblocked):**
> 1. **Increment 1 — Device-Owner on STOCK** *(code-complete: #217 DO auto-enable, #218
>    provisioning-QR)*. Polish only: onboarding already guides the one-time a11y enable.
> 2. **Increment 2 — privileged system app** *(needs an AOSP/Graphene build host + the
>    wiped 7a)*. Build the SOFTWARE + Soong/`Android.bp` + sepolicy + image config now;
>    **PARK** the image build / flash / OTA / on-device validation.
> 3. **Increment 3 — framework-baked `bulwarkd`** *(months; multi-week)*. DESIGN + the
>    well-bounded pieces only. Do **NOT** half-build the multi-week service in a loop.
>
> **PARALLELISM:** when ≥2 items are independent (different apps/files, no shared state),
> use `superpowers:dispatching-parallel-agents` — one **`isolation: "worktree"`** agent per
> domain, explicit `model:`, all dispatched in ONE message. To execute a written plan
> task-by-task, use `superpowers:subagent-driven-development`. Tell every implementer agent
> to **commit incrementally** (background agents die on a host process-exit; frequent
> commits survive).
>
> **GATES (never skip):**
> - Sub-agents write ONLY in their own git worktree; you (main session) review + integrate.
> - **Camera UX + detection SEMANTICS (NSFW/grooming thresholds) are MAIN-SESSION ONLY** —
>   sub-agents content-block on that domain; never change detection logic in an agent.
> - Run `code-review` on every diff before commit/PR; run `framing-review` on new prose/UI
>   (docs/FRAMING.md — child-protection, never offensive-security/surveillance terms).
> - **NEVER merge to master autonomously** — master push = prod deploy. Open the PR, post a
>   one-line "what changed", and STOP for the owner's merge.
> - MIT/Apache only (the GPL-2 kernel is the owner-approved ROM platform; our code stays
>   permissive). CSAM detect/block/report-never-store. Grooming weights
>   guardian-provisioned-only. `#![forbid(unsafe_code)]` except audited FFI.
> - **Device/host-gated work PARKS** — you cannot flash a phone or run a ~200 GB AOSP build
>   here. Build software + configs + docs, mark the rung "READY FOR DEVICE", never fake
>   validation.
>
> **DONE per task:** code + tests green in the worktree + `code-review` APPROVE + ledger
> line appended. Per increment: all tasks done + a final whole-branch review + PR opened
> (held for the owner).
>
> **When the buildable QUEUE is empty → CONTINUOUS IMPROVEMENT mode:** one small,
> held-for-owner PR per loop — `code-review`/`simplify` on recent diffs, test-coverage
> gaps, `framing-review` audits, detection-loop perf/battery, an INT8-quantized NSFW model
> (engine task). Never invent features outside the spec/backlog.
>
> **HOLD DISCIPLINE (critical):** the bar for "I found work" is a real plan task, a real
> backlog item, or **new owner input** — NOT a heartbeat firing. If the only remaining work
> needs the owner (a merge, the device, an architect ruling) or there is no defined next
> task, post ONE consolidated status and **slow to a long heartbeat or stop**. Do not read
> your own scheduled wake-up as owner consent. Do not manufacture marginal work to fill a
> tick.
>
> **CADENCE:** while actively babysitting parallel agents/CI, a ~2-min (120s) heartbeat is
> cache-warm and fine. Once the buildable queue is empty and you're waiting on the owner,
> drop to 1200–1800s. Gate the next iteration on the real signal: a dispatched agent
> finishing wakes you automatically (harness-tracked); for external CI, poll.

---

## Hard-won lessons (already baked into the prompt)

- **Background worktree agents die when the host Claude Code process exits**, losing
  in-process state. Mitigation: have them commit incrementally, and on each wake check
  their worktree for salvageable uncommitted work before re-dispatching. (Twice this build,
  agents died with the QR builder + DO-enable half-done; both were salvaged from their
  worktrees.)
- **Verify agent claims** — agents cross-reference real code well but can also be wrong; a
  review caught that DO `setSecureSetting` can't silently enable an a11y service on stock
  (the allowlist excludes it), so Increment 1 still needs a one-time manual a11y enable —
  the genuinely-silent path is B/C.
- **Don't merge to feel productive** — every master merge is a prod deploy; reviewed-clean
  PRs still wait for the owner.
- **Don't let heartbeats masquerade as consent** — repeated `/loop` fires are usually your
  own scheduled wake-ups, not the owner saying "go". When the buildable work is genuinely
  done, holding is the correct state, not a failure to find work.
