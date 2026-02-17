# Refactoring Guide

Advisory notes on large modules that may benefit from decomposition as the codebase grows. None of these are urgent — the current code is well-structured and functional. These are suggestions for when modules become harder to navigate or when adding new features creates merge conflicts in large files.

## Large Modules

| File | Lines | Suggested Split |
|------|-------|-----------------|
| `server_common.rs` | ~1,350 | Extract `rate_limit.rs`, `access_control.rs`, `interleaved.rs` |
| `protocol.rs` | ~1,293 | Split into `protocol/types.rs`, `protocol/traits.rs`, `protocol/io.rs`, `protocol/buf.rs`, `protocol/mod.rs` (re-exports) |
| `client.rs` | ~1,006 | Extract poll interval management and interleaved state machine |
| `smol_client.rs` | ~953 | Consider shared trait/macro with `client.rs` to reduce duplication |
| `lib.rs` (client) | ~897 | Move networking functions to `request.rs` or `sntp_core.rs` |

## Guidelines

- **Preserve public API**: All splits should be internal reorganization with re-exports from the original module path.
- **One module per PR**: Avoid splitting multiple large modules in a single PR to keep reviews manageable.
- **Test coverage first**: Ensure adequate test coverage exists before splitting — the existing 290+ tests and property-based tests provide a good safety net.
- **Feature gates**: When splitting feature-gated code, keep feature boundaries aligned with module boundaries where possible.
