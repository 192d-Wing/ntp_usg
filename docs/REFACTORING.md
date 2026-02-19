# Refactoring Guide

All large-module decompositions identified below have been completed. This document is retained for reference.

## Large Modules (All Complete)

| File | Lines | Suggested Split | Status |
|------|-------|-----------------|--------|
| `server_common.rs` | ~1,350 | Extract `rate_limit.rs`, `access_control.rs`, `interleaved.rs` | **Done** — split into `server_common/` (9 files) |
| `protocol.rs` | ~1,293 | Split into `protocol/types.rs`, `protocol/traits.rs`, `protocol/io.rs`, `protocol/buf.rs`, `protocol/mod.rs` (re-exports) | **Done** — split into `protocol/` (5 files) |
| `client.rs` | ~1,006 | Extract poll interval management and interleaved state machine | **Done** — shared code extracted to `client_common.rs` |
| `smol_client.rs` | ~953 | Consider shared trait/macro with `client.rs` to reduce duplication | **Done** — ~840 lines deduplicated into `client_common.rs` |
| `lib.rs` (client) | ~897 | Move networking functions to `request.rs` or `sntp_core.rs` | **Done** — extracted to `request.rs` |

## Tokio/Smol Duplication

v4.7.0 extracted ~1,300 lines of high-value shared logic into `_common` modules and macros. The remaining ~570 lines of thin async I/O glue (timeouts, state publication, task spawning, timers) are documented in [DUPLICATION_AUDIT.md](DUPLICATION_AUDIT.md).

## Guidelines

- **Preserve public API**: All splits should be internal reorganization with re-exports from the original module path.
- **One module per PR**: Avoid splitting multiple large modules in a single PR to keep reviews manageable.
- **Test coverage first**: Ensure adequate test coverage exists before splitting — the existing 290+ tests and property-based tests provide a good safety net.
- **Feature gates**: When splitting feature-gated code, keep feature boundaries aligned with module boundaries where possible.
