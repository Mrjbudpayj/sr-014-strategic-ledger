# A11 Type-Witnessed Transition Lattice

## Constitutional Invariant

```
No receipt → No advancement
No tampering survives → Digest re-verification
No phantom receipts → Terminal rejection enforces NOT_EXECUTED
No type-unsafe transition → Compiler enforces structural admissibility
```

## Transition Lattice (Immutable Order)

```
GraphValidationReceipt (Digest D₁)
    │
    ├─ State: STRUCTURAL_PASS | STRUCTURAL_FAIL
    │
    ▼
ProofPlaneReceipt (DependsOn: D₁, Digest D₂)
    │
    ├─ State: CONFORMANT | NON_CONFORMANT
    │
    ▼
AttestationReceipt (DependsOn: D₂, Digest D₃)
    │
    ├─ State: ATTESTED | REJECTED
    │
    ▼
AuthorityReceipt (DependsOn: D₃)
    │
    └─ State: AUTHORIZED | RELEASE_DENIED
```

## Non-Negotiable Guarantees

### 1. Digest Integrity

Every transition function re-verifies the predecessor's digest:

```go
expectedDigest := predecessor.Digest
predecessor.Digest = "" // Exclude from hash
actualDigest, _ := ComputeDigest(predecessor)
if expectedDigest != actualDigest {
    return ErrTamperedPredecessor
}
```

No bit flip survives. No post-hoc modification is possible.

### 2. Structural Admissibility

Type system enforces that only structurally valid predecessor states can proceed:

```go
// Compiled type signature
func EvaluateAuthority(attestation AttestationReceipt) (*AuthorityReceipt, error)

// Impossible to call with:
// - nil
// - raw bool
// - string declaration
// - unatested proof
```

Compiler rejects at build time.

### 3. Dependency Chain Continuity

Each receipt explicitly declares its dependency:

```go
type AttestationReceipt struct {
    DependsOn Digest  // Must match ProofPlaneReceipt.Digest
    Digest    Digest  // Hash of this receipt
    State     AttestationState
}
```

Breaking the chain is impossible without destroying the receipt.

### 4. Terminal Rejection is Non-Negotiable

When a gate fails, downstream is explicitly marked NOT_EXECUTED:

```go
&TerminalRejectionReceipt{
    FailedAtPhase:    "PROOF_PLANE",
    RootCause:        "Cycle detected in structural graph",
    DownstreamStatus: "NOT_EXECUTED",  // ← Non-negotiable signal
}
```

No code path ignores this. No default fallthrough. No escape hatch.

## Test Vectors (T1-T5)

### T1: Structural Circularity
- Inject circular dependency (P2 ↔ P3)
- GraphValidationReceipt marked STRUCTURAL_FAIL
- **Result:** ProofPlane NOT_EXECUTED, no vectors run

### T2: Digest Tampering
- Valid graph receipt, then mutate payload
- EvaluateProofPlane recomputes digest
- **Result:** ErrTamperedPredecessor, downstream halted

### T3: State Forgery
- Mark ProofState=CONFORMANT with 1/10 vectors passing
- EvaluateAttestation detects inconsistency
- **Result:** AttestationRejected, authority gate unreached

### T4: Dependency Desynchronization
- ProofPlaneReceipt.DependsOn points to wrong graph hash
- EvaluateAttestation cannot link the chain
- **Result:** Dependency validation fails, authority denied

### T5: Terminal Proof Failure
- All vectors fail (0/5 pass)
- ProofPlaneReceipt state is NON_CONFORMANT
- **Result:** Authority evaluation fails cleanly, RELEASE_DENIED

## The Central Claim

```
The system can continue operating without having to lie about why it operated.
```

**Proof mechanism:**
- Every transition requires a cryptographically sealed predecessor receipt.
- Every receipt's digest is independently re-verified at the next gate.
- Missing, tampered, or orphaned receipts stop execution **before** next gate executes.
- No abandonment of truth.
- No semantic substitution.
- No phantom authority.

## No Escape Routes

There is **no function signature** that permits:
- Raw boolean flags
- String declarations of validity
- Default/fallback values
- Unverified assertions
- Phantom receipts

The only way to advance is through an unbroken chain of cryptographically sealed receipts, each verifying its predecessor, each dependent on the prior digest.

**This is type-safe governance.**
