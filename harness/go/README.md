# A11 Type-Witnessed Transition Lattice

## Purpose

Implement the **constitutional verification engine** that proves semantic boundaries cannot be crossed at the compiler and type-checker boundary.

Not a test suite in the traditional sense. **A falsification harness** that systematically attempts to violate gate rules and proves they cannot be violated.

## Architecture

### `lattice/` Package

Core type definitions and transition functions:
- `GraphValidationReceipt` — Structural integrity state
- `ProofPlaneReceipt` — Proof conformance state
- `AttestationReceipt` — Witnessed attestation state
- `AuthorityReceipt` — Authority grant state
- `TerminalRejectionReceipt` — Explicit non-execution signal

Transition functions enforce three non-negotiable invariants:
1. **Digest Re-Verification** — Every receipt's hash is recomputed
2. **Structural Admissibility** — Only valid predecessors proceed
3. **Chain Continuity** — Dependency digests must match

### `harness/` Package

Test suite implementing T1-T5 falsification vectors:
- `T1_StructuralCircularity` — Cycle injection halts proof plane
- `T2_PredecessorDigestTampering` — Bit flip stops transition
- `T3_StateForgery` — Inconsistent state rejected
- `T4_DependencyDesync` — Broken chain blocks authority
- `T5_TerminalProofFailure` — Partial success → RELEASE_DENIED

## Building

```bash
cd harness/go
go mod tidy
go test -v ./...
```

## Expected Output

All tests must PASS:

```
✓ TestT1_StructuralCircularity_SuppressesProofPlane
✓ TestT2_PredecessorDigestTampering_AbortsTransition
✓ TestT3_StateForgery_RejectedByConsistencyCheck
✓ TestT4_DependencyDesync_BreaksAuthorityChain
✓ TestT5_TerminalProofFailure_SuppressesAuthority
✓ TestFullPipeline_SuccessPath

Constitutional Integrity: 100%
```

If any test FAILs, the constitutional boundary has been breached.

## Type Safety as Governance

This implementation enforces governance **at the type level**:

```go
// You cannot call this function with:
// - a bool
// - a string
// - nil
// - an unatested proof
// - a raw assertion

func EvaluateAuthority(attestation AttestationReceipt) (*AuthorityReceipt, error)
```

The compiler rejects invalid calls at build time. Runtime validation provides cryptographic proof of chain integrity.

## No Phantom Receipts

When any gate fails, there is **no downstream receipt initialized**. An explicit `TerminalRejectionReceipt` is returned:

```go
&TerminalRejectionReceipt{
    FailedAtPhase:    "GRAPH_VALIDATION",
    RootCause:        "Cycles detected",
    DownstreamStatus: "NOT_EXECUTED",  // ← Explicit signal
}
```

Downstream gates check this signal and refuse to proceed.

## Integration with CI/CD

The release pipeline reads:

```go
if authReceipt.State != AuthorityGranted {
    return RELEASE_DENIED  // Terminal halt
}
```

No fallthrough. No "try again." No escape hatch.

## The Central A11 Claim

**Mechanically enforced and independently verifiable:**

```
The system can continue operating without having to lie about why it operated.
```
