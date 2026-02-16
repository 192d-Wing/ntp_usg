# NTP Algorithms Documentation

This document describes the advanced NTP algorithms implemented in `ntp_usg` v3.1.0 for achieving full RFC 5905 compliance.

## Table of Contents

1. [Clock Filter Algorithm](#clock-filter-algorithm)
2. [Selection Algorithm](#selection-algorithm)
3. [Clustering Algorithm](#clustering-algorithm)
4. [Combine Algorithm](#combine-algorithm)
5. [Clock Discipline Algorithm](#clock-discipline-algorithm)
6. [Integration](#integration)

---

## Clock Filter Algorithm

**Module**: [`crates/ntp_usg-client/src/filter.rs`](crates/ntp_usg-client/src/filter.rs)
**RFC**: RFC 5905 Section 10

The clock filter algorithm maintains a sliding window of recent time samples from a single peer and selects the best estimate.

### Purpose

- Reduce jitter from network variability
- Track dispersion (uncertainty) growth over time
- Provide stable offset and delay estimates

### Implementation

```rust
pub struct SampleFilter {
    samples: [Option<ClockSample>; 8],  // Circular buffer of 8 samples
    next_idx: usize,
}

pub struct ClockSample {
    pub offset: f64,       // Clock offset (seconds)
    pub delay: f64,        // Round-trip delay (seconds)
    pub dispersion: f64,   // Sample dispersion (seconds)
    pub epoch: Instant,    // When sample was recorded
    pub age: f64,          // Time since recording (seconds)
}
```

### Key Operations

1. **Adding Samples**: `add_with_dispersion(offset, delay, dispersion)`
   - Stores sample in circular buffer
   - Records timestamp for age tracking

2. **Age Updates**: `update_ages()`
   - Recalculates age for all samples: `age = now - epoch`
   - Increments dispersion: `dispersion += TOLERANCE * delta_age`
   - `TOLERANCE = 15 ppm` (protocol precision)

3. **Best Sample Selection**: `best_sample()`
   - Sorts samples by **synchronization distance**: `delay/2 + dispersion`
   - Returns sample with minimum distance
   - Lower distance = more reliable sample

4. **Jitter Calculation**: `jitter()`
   - RMS (root mean square) of offset differences
   - Formula: `sqrt(sum((offset[i] - best_offset)^2) / (N-1))`

### Example

```rust
use ntp_client::filter::SampleFilter;

let mut filter = SampleFilter::new();

// Add samples over time
filter.add_with_dispersion(0.010, 0.050, 0.001);  // offset, delay, dispersion
filter.add_with_dispersion(0.012, 0.048, 0.001);
filter.add_with_dispersion(0.009, 0.052, 0.001);

// Update ages and get best estimate
filter.update_ages();
let best = filter.best_sample().unwrap();
let jitter = filter.jitter();

println!("Best offset: {:.6}s, jitter: {:.6}s", best.offset, jitter);
```

---

## Selection Algorithm

**Module**: [`crates/ntp_usg-client/src/selection.rs`](crates/ntp_usg-client/src/selection.rs)
**RFC**: RFC 5905 Section 11.2.1
**Algorithm**: Marzullo's algorithm

The selection algorithm identifies **truechimers** (correct time sources) from a set of peer candidates using interval intersection.

### Purpose

- Detect and exclude **falsetickers** (incorrect or malicious sources)
- Identify peers with mutually consistent time
- First stage of the three-stage pipeline

### Theory

Each peer provides a **correctness interval**:
```
[offset - root_distance, offset + root_distance]
```

Where `root_distance = delay/2 + dispersion + root_dispersion`

Truechimers are peers whose intervals all intersect at a common point.

### Implementation

```rust
pub fn select_truechimers(candidates: &[PeerCandidate]) -> Vec<usize>
```

**Steps**:

1. Build interval endpoints for each peer
2. Sort all endpoints by position
3. Count overlapping intervals using Marzullo's sweep algorithm
4. Find the point with maximum overlap (m)
5. Peers intersecting at m are truechimers

### Example

```
Peer A: [10ms, 20ms]  ─────────
Peer B: [12ms, 22ms]      ─────────
Peer C: [15ms, 25ms]         ─────────
Peer D: [50ms, 60ms]                    ──────────

Overlap count:
  10-12:  1  (A)
  12-15:  2  (A, B)
  15-20:  3  (A, B, C)  ← maximum = 3
  20-22:  2  (B, C)
  22-25:  1  (C)

Truechimers: A, B, C (all intersect at 15-20ms range)
Falseticker: D (outlier)
```

### Code Example

```rust
use ntp_client::selection::{PeerCandidate, select_truechimers};

let candidates = vec![
    PeerCandidate {
        peer_index: 0,
        offset: 0.015,
        root_delay: 0.010,
        root_dispersion: 0.005,
        jitter: 0.001,
        stratum: 2,
    },
    // ... more peers
];

let truechimers = select_truechimers(&candidates);
println!("Truechimers: {:?}", truechimers);
```

---

## Clustering Algorithm

**Module**: [`crates/ntp_usg-client/src/selection.rs`](crates/ntp_usg-client/src/selection.rs)
**RFC**: RFC 5905 Section 11.2.2

The clustering algorithm further refines the truechimer set by removing statistical outliers.

### Purpose

- Reduce the truechimer set to the most consistent subset
- Remove peers with high selection jitter
- Ensure at least `NMIN = 3` survivors for redundancy

### Algorithm

```rust
pub fn cluster_survivors(candidates: &mut Vec<PeerCandidate>)
```

**Iterative process**:

1. Compute **selection jitter** for each peer:
   - RMS of offset differences to all other peers
   - Formula: `sqrt(sum((offset[i] - offset[j])^2) / (N-1))`

2. Find peer with **maximum selection jitter**

3. Compare to **minimum peer jitter**:
   - If `max_selection_jitter > min_peer_jitter`, remove the peer
   - Otherwise, stop (cluster is tight enough)

4. Repeat until:
   - Only `NMIN` peers remain (minimum redundancy), OR
   - Max selection jitter ≤ min peer jitter (cluster is converged)

### Example

```
Initial: 5 truechimers

Iteration 1:
  Peer A: selection_jitter = 0.005, peer_jitter = 0.001
  Peer B: selection_jitter = 0.003, peer_jitter = 0.001
  Peer C: selection_jitter = 0.002, peer_jitter = 0.001
  Peer D: selection_jitter = 0.008, peer_jitter = 0.001  ← max
  Peer E: selection_jitter = 0.003, peer_jitter = 0.001

  Max selection jitter (0.008) > min peer jitter (0.001)
  → Remove Peer D

Iteration 2:
  Peer A: selection_jitter = 0.002, peer_jitter = 0.001
  Peer B: selection_jitter = 0.001, peer_jitter = 0.001
  Peer C: selection_jitter = 0.001, peer_jitter = 0.001
  Peer E: selection_jitter = 0.001, peer_jitter = 0.001

  Max selection jitter (0.002) > min peer jitter (0.001)
  → But only 4 peers left, close to NMIN=3
  → Continue to check if we should remove one more

Result: 3-4 survivors (depending on convergence)
```

---

## Combine Algorithm

**Module**: [`crates/ntp_usg-client/src/selection.rs`](crates/ntp_usg-client/src/selection.rs)
**RFC**: RFC 5905 Section 11.2.3

The combine algorithm produces a single time estimate from the survivors using weighted averaging.

### Purpose

- Combine multiple time sources into a single estimate
- Weight more reliable sources (lower root distance) more heavily
- Select the **system peer** (most reliable source)

### Implementation

```rust
pub fn combine(survivors: &[PeerCandidate]) -> Option<CombinedEstimate>
```

**Weighted Average**:

```
weight[i] = 1 / root_distance[i]

offset = sum(offset[i] * weight[i]) / sum(weight[i])
```

**System Peer**: Survivor with minimum root distance

**Combined Jitter**: Weighted RMS of offset differences

### Example

```
Survivors:
  Peer A: offset=0.010s, root_distance=0.020s → weight=50.0
  Peer B: offset=0.012s, root_distance=0.025s → weight=40.0
  Peer C: offset=0.009s, root_distance=0.030s → weight=33.3

Combined offset = (0.010*50 + 0.012*40 + 0.009*33.3) / (50+40+33.3)
                = (0.5 + 0.48 + 0.3) / 123.3
                = 0.0104s

System peer: Peer A (minimum root_distance)
```

### Code Example

```rust
use ntp_client::selection::{combine, CombinedEstimate};

let survivors = vec![/* filtered candidates */];
let estimate = combine(&survivors).unwrap();

println!("Combined offset: {:.6}s", estimate.offset);
println!("System peer: {}", estimate.system_peer_index);
```

---

## Clock Discipline Algorithm

**Module**: [`crates/ntp_usg-client/src/discipline.rs`](crates/ntp_usg-client/src/discipline.rs)
**RFC**: RFC 5905 Section 11.3

The clock discipline algorithm implements a **PLL/FLL hybrid** feedback loop to correct both phase (offset) and frequency errors.

### Purpose

- Track and correct **phase error** (clock offset)
- Estimate and correct **frequency error** (clock drift rate)
- Adapt to changing network conditions
- Decide when to step vs. slew the clock

### State Machine

```
NSET (Not Set)
  ↓ First offset measurement
FSET (Frequency Set)
  ↓ Second offset measurement (compute initial frequency)
SYNC (Synchronized)
  ↓ Large offset detected
SPIK (Spike detected - possible outlier)
  ↓ Either return to SYNC or step and reset to NSET
```

### Key Parameters

| Constant | Value | Description |
|----------|-------|-------------|
| `STEPT` | 0.128s | Step threshold (128ms) |
| `WATCH` | 900s | Spike timeout (15 minutes) |
| `PGATE` | 4.0 | PLL gate multiplier |
| `ALLAN` | 2048s | Allan intercept |
| `PLL_SCALE` | 65536 | PLL gain factor |
| `FLL_SCALE` | 256 | FLL gain factor |

### PLL (Phase-Locked Loop)

Corrects **phase error** proportionally:

```
phase_correction = offset * (PLL_SCALE / tc) / (2^tc)

where tc = time constant (poll exponent)
```

### FLL (Frequency-Locked Loop)

Corrects **frequency error** based on offset rate of change:

```
freq_correction = (offset - last_offset) / (mu * FLL_SCALE)

where mu = time since last update
```

### Adaptive Time Constant

```
If |offset| < PGATE * jitter:
    tc = min(tc + 1, poll_exponent)  // Increase (more smoothing)
Else:
    tc = max(tc - 1, 0)              // Decrease (faster response)
```

### Step vs. Slew Decision

```
If |offset| > STEPT (128ms):
    If time_since_last_update < WATCH (15min):
        Enter SPIK state (might be outlier)
    Else:
        STEP the clock immediately
        Reset to NSET state
Else:
    SLEW the clock gradually
```

### Example

```rust
use ntp_client::discipline::ClockDiscipline;

let mut discipline = ClockDiscipline::new();

// Feed measurements over time
let output1 = discipline.update(0.010, 0.001, 60.0, 6);
if let Some(out) = output1 {
    if out.step {
        clock::step_clock(out.phase_correction)?;
    } else {
        clock::slew_clock(out.phase_correction)?;
    }
}

// Discipline adapts over time, tracking frequency drift
let output2 = discipline.update(0.005, 0.001, 64.0, 6);
// Frequency correction is now non-zero, compensating for drift
```

---

## Integration

### Full Pipeline

The complete NTP client pipeline (when using `NtpClient` with multiple peers):

```
1. Poll multiple NTP servers
2. For each server:
   └─> Clock Filter: Select best sample from recent measurements
3. Selection: Identify truechimers (Marzullo's algorithm)
4. Clustering: Remove statistical outliers
5. Combine: Weighted average of survivors
6. Clock Discipline: PLL/FLL feedback loop
7. Clock Adjustment: Apply slew/step via OS API
```

### Single-Peer Fallback

For backward compatibility, single-peer clients skip steps 3-5:

```
1. Poll single server
2. Clock Filter: Select best sample
3. Clock Discipline (optional, if enabled)
4. Clock Adjustment
```

### Feature Flags

- **`discipline`**: Enable clock discipline PLL/FLL (requires `clock` feature)
- **`clock`**: Enable system clock adjustment primitives

### Performance Characteristics

| Operation | Complexity | Typical Time |
|-----------|-----------|--------------|
| Clock Filter (add sample) | O(1) | < 1μs |
| Clock Filter (best sample) | O(N log N), N=8 | < 10μs |
| Selection (Marzullo) | O(M log M), M=peers | 10-50μs for 5-10 peers |
| Clustering | O(M²) worst case | 20-100μs for 5-10 peers |
| Combine | O(M) | < 5μs |
| Discipline update | O(1) | < 1μs |

### Memory Usage

| Structure | Size per Instance | Notes |
|-----------|------------------|-------|
| `SampleFilter` | ~200 bytes | 8 samples × 24 bytes |
| `ClockDiscipline` | ~80 bytes | State + accumulators |
| `PeerCandidate` | ~48 bytes | Temporary during selection |

### Configuration Recommendations

**For minimal jitter (low-latency networks)**:
```rust
NtpClient::builder()
    .min_poll(4)   // 16 seconds
    .max_poll(6)   // 64 seconds
    .build()
```

**For stable frequency tracking (high-latency or mobile networks)**:
```rust
NtpClient::builder()
    .min_poll(6)   // 64 seconds
    .max_poll(10)  // 1024 seconds (~17 minutes)
    .build()
```

**Multi-peer deployment (3-5 peers recommended)**:
```rust
NtpClient::builder()
    .server("time1.nist.gov:123")
    .server("time2.nist.gov:123")
    .server("time3.nist.gov:123")
    .min_poll(6)
    .max_poll(10)
    .build()
```

---

## References

- **RFC 5905**: Network Time Protocol Version 4: Protocol and Algorithms Specification
  - Section 10: Clock Filter Algorithm
  - Section 11.2: Peer Process (Selection, Clustering, Combine)
  - Section 11.3: Clock Discipline Algorithm

- **RFC 1305**: Network Time Protocol Version 3 (historical reference for algorithm origins)

- **Mills, D. L.** "Computer Network Time Synchronization: The Network Time Protocol" (2006)
  - Chapter 9: Clock Filter Algorithm
  - Chapter 10: Selection and Clustering Algorithms
  - Chapter 11: Clock Discipline Algorithm

---

## See Also

- [`RFC_COMPLIANCE.md`](RFC_COMPLIANCE.md) - Full RFC compliance documentation
- [`crates/ntp_usg-client/README.md`](crates/ntp_usg-client/README.md) - Client API documentation
- [RFC 5905 Full Text](https://www.rfc-editor.org/rfc/rfc5905.html)
