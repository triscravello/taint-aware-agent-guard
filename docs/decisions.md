# Decision Log

## ADR-001: Local command hooks instead of an inference service

Use project-scoped Claude Code command hooks and a local Go binary. This keeps the exercise local, inspectable, and free of incremental infrastructure. It does not provide a server-side policy boundary.

## ADR-002: Session identifier hashing

Use SHA-256 of `session_id` as the state filename. This separates ordinary sessions without placing raw identifiers in paths or audit records.

When `session_id` is absent, hash `missing:` plus `cwd` and mark the state degraded. This fallback is intentionally conservative. Two missing-ID sessions in the same working directory can share taint and create extra prompts.

## ADR-003: Pass, ask, and deny

A pass means TaintGuard emits no authorization decision. Claude Code's normal permission system still applies.

An ask escalates the action to the normal user permission prompt. Approval can still permit the action.

A deny tells Claude Code not to execute the matched tool call. It is reserved here for the synthetic credential-egress shape when state is tainted or degraded.

Detection is separate. PostToolUse detection records provenance and shows telemetry, but the source action already completed.

## ADR-004: Conservative state failure

Missing, invalid, mismatched, or unreadable state is degraded. Recognized sensitive reads ask. The high-risk synthetic credential-egress shape denies. Ordinary development actions remain subject to native permissions.

The PreToolUse hook also sets `onFailure` to `block`, so a missing binary, crash, invalid output, or timeout does not silently execute a matched Read or Bash call on supported Claude Code versions.

## Known limitations

- This is not a sandbox or universal prompt-injection detector.
- It observes only tool calls delivered to its configured hooks.
- PostToolUse cannot undo a completed tool action.
- String matching can miss transformed, split, aliased, or indirect operations.
- An `ask` outcome is an approval gate, not guaranteed prevention.
- The demo policy protects only named synthetic patterns.
- State updates use atomic replacement but no cross-process lock, so simultaneous PostToolUse writers can still create last-write-wins behavior.
- The checked-in replay corpus is small, synthetic, and author-written. Its rates do not estimate real-world protection.
- Native Claude Code permissions and sandboxing remain separate defense layers and should stay enabled.