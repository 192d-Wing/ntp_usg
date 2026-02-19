# Tokio/Smol Duplication Audit

Audited after v4.7.0, which eliminated ~1,300 lines of high-value duplication by extracting shared logic into `_common` modules and macros.

## Remaining Duplication (~570 lines)

| Component | Tokio File | Smol File | Lines | Similarity |
|-----------|-----------|----------|-------|------------|
| Server `run()` | `server.rs` | `smol_server.rs` | ~48 | 98% |
| Client `poll_peer()` | `client.rs` | `smol_client.rs` | ~65 | 89% |
| Client `poll_peer_nts()` | `client.rs` | `smol_client.rs` | ~90 | 94% |
| Client `poll_peer_v5()` | `client.rs` | `smol_client.rs` | ~230 | 96% |
| Client `run()` loop | `client.rs` | `smol_client.rs` | ~140 | 90% |
| NTS `request_inner()` | `nts.rs` | `smol_nts.rs` | ~58 | 81% |
| NTS-KE server handler | `nts_ke_server.rs` | `smol_nts_ke_server.rs` | ~60 | 88% |

## What Differs (Runtime-Specific Code)

The differences between tokio and smol versions are almost entirely in 4 categories:

**1. Timeout mechanism** (3-4 lines per method)
```rust
// Tokio:
tokio::time::timeout(dur, fut).await??

// Smol:
futures_lite::future::or(fut, async {
    smol::Timer::after(dur).await;
    Err(io::Error::new(io::ErrorKind::TimedOut, "..."))
}).await?
```

**2. State publication** (2-3 lines)
```rust
// Tokio: watch channel
self.state_tx.send(state).ok();

// Smol: Arc<RwLock<>>
*self.state.write().unwrap() = state;
```

**3. Task spawning** (1-2 lines)
```rust
// Tokio:
tokio::spawn(async { ... });

// Smol:
smol::spawn(async { ... }).detach();
```

**4. Timer/sleep** (2-3 lines)
```rust
// Tokio:
tokio::time::sleep_until(deadline).await;

// Smol:
smol::Timer::after(remaining).await;
```

## Why Further Extraction Is Not Worthwhile

Extracting these would require:

- A **timeout trait** (e.g., `trait AsyncTimeout`) with different impls per runtime
- A **state publisher trait** for watch vs RwLock state propagation
- A **timer trait** wrapping both tokio::time and smol::Timer
- Generic type parameters threaded through every async method

**Cost**: ~80-100 lines of trait definitions + type parameter complexity throughout async call chains.

**Savings**: ~200-250 lines of structural deduplication.

**Trade-offs**:
- Loss of concrete types in function signatures (harder to read and debug)
- Potential async trait object safety issues
- Adding a dependency like `tokio-util::compat` to bridge trait incompatibilities
- Every new contributor must understand the trait abstraction before modifying I/O code

The remaining duplication is thin async I/O glue that changes rarely. The high-value shared logic (protocol parsing, builder configuration, NTS-KE negotiation, peer selection) was already extracted in v4.7.0.

## Maintenance Guidelines

When modifying the remaining duplicated code:

1. **Update both files** — search for the paired file and apply the same change
2. **Keep parallel structure** — the files are laid out identically for easy diffing
3. **New shared logic goes in `_common` modules** — if you find yourself writing identical non-I/O code in both files, extract it
4. **Consider trait abstraction only if a third runtime is added** — at that point the duplication triples and extraction becomes cost-effective
