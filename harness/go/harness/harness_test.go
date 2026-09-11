package harness_test

import (
	"testing"
	"lattice"
)

// T1: Structurally invalid graph must completely suppress downstream execution
func TestT1_StructuralCircularity_SuppressesProofPlane(t *testing.T) {
	// Construct circular graph: P2 <-> P3
	graphReceipt := lattice.GraphValidationReceipt{
		State:         lattice.StructuralFail,
		CycleDetected: true,
		CycleMembers:  []string{"P2", "P3"},
	}
	d, _ := lattice.ComputeDigest(graphReceipt)
	graphReceipt.Digest = d

	vectorExecuted := false
	dummyRunner := func() (int, int, error) {
		vectorExecuted = true
		return 10, 10, nil
	}

	proofReceipt, terminal, err := lattice.EvaluateProofPlane(graphReceipt, dummyRunner)

	if err != lattice.ErrInadmissiblePredecessor {
		t.Fatalf("expected ErrInadmissiblePredecessor, got: %v", err)
	}
	if vectorExecuted {
		t.Fatal("CRITICAL INVARIANT VIOLATION: Proof plane executed despite structural failure")
	}
	if proofReceipt != nil {
		t.Fatal("CRITICAL INVARIANT VIOLATION: ProofPlaneReceipt manufactured on structural failure")
	}
	if terminal.DownstreamStatus != "NOT_EXECUTED" {
		t.Fatalf("expected NOT_EXECUTED, got %s", terminal.DownstreamStatus)
	}
}

// T2: Tampered predecessor digest must halt evaluation immediately
func TestT2_PredecessorDigestTampering_AbortsTransition(t *testing.T) {
	graphReceipt := lattice.GraphValidationReceipt{
		State:         lattice.StructuralPass,
		CycleDetected: false,
	}
	d, _ := lattice.ComputeDigest(graphReceipt)
	graphReceipt.Digest = d

	// Malicious actor modifies payload after computing digest
	graphReceipt.CycleMembers = []string{"P99_FORGED"}

	_, terminal, err := lattice.EvaluateProofPlane(graphReceipt, func() (int, int, error) {
		return 10, 10, nil
	})

	if err != lattice.ErrTamperedPredecessor {
		t.Fatalf("expected ErrTamperedPredecessor, got: %v", err)
	}
	if terminal == nil || terminal.DownstreamStatus != "NOT_EXECUTED" {
		t.Fatal("failed to emit proper terminal evidence on digest tampering")
	}
}

// T3: State Forgery - inconsistent vector counts should be rejected
func TestT3_StateForgery_RejectedByConsistencyCheck(t *testing.T) {
	// Create a conformant proof receipt with mismatched vector counts (forgery)
	proofReceipt := lattice.ProofPlaneReceipt{
		State:              lattice.ProofConformant,
		PassedVectorsCount: 1,  // Only 1 passed
		TotalVectorsCount:  10, // But 10 total
	}
	d, _ := lattice.ComputeDigest(proofReceipt)
	proofReceipt.Digest = d

	// Attempt to attest this forged proof
	attestation, _, err := lattice.EvaluateAttestation(proofReceipt, "commit123", []string{})

	if err != lattice.ErrInadmissiblePredecessor {
		t.Fatalf("expected ErrInadmissiblePredecessor for forged proof, got: %v", err)
	}
	if attestation != nil && attestation.State == lattice.AttestationSealed {
		t.Fatal("CRITICAL: Attestation granted to forged proof state")
	}
}

// T4: Dependency Desynchronization - broken chain should halt authority grant
func TestT4_DependencyDesync_BreaksAuthorityChain(t *testing.T) {
	// Create an attestation with a mismatched dependency pointer
	attestation := lattice.AttestationReceipt{
		DependsOn: "sha256:0000000000000000000000000000000000000000000000000000000099999999",
		State:     lattice.AttestationSealed,
	}
	d, _ := lattice.ComputeDigest(attestation)
	attestation.Digest = d

	// Attempt authority evaluation
	auth, err := lattice.EvaluateAuthority(attestation)

	if err != lattice.ErrInadmissiblePredecessor {
		t.Fatalf("expected error for broken dependency, got: %v", err)
	}
	if auth.State == lattice.AuthorityGranted {
		t.Fatal("CRITICAL: Authority granted despite broken dependency chain")
	}
}

// T5: Terminal Proof Failure - partial vector success should result in non-conformant state
func TestT5_TerminalProofFailure_SuppressesAuthority(t *testing.T) {
	// Simulate a graph that passes validation
	graphReceipt := lattice.GraphValidationReceipt{
		State:         lattice.StructuralPass,
		CycleDetected: false,
	}
	d, _ := lattice.ComputeDigest(graphReceipt)
	graphReceipt.Digest = d

	// Run vectors that fail (1 of 10 pass)
	failingRunner := func() (int, int, error) {
		return 1, 10, nil // Only 1 of 10 vectors passed
	}

	proofReceipt, terminal, _ := lattice.EvaluateProofPlane(graphReceipt, failingRunner)

	// Verify proof is non-conformant
	if proofReceipt.State != lattice.ProofNonConformant {
		t.Fatalf("expected ProofNonConformant, got: %s", proofReceipt.State)
	}

	// Attempt to attest the failing proof
	attestation, _, _ := lattice.EvaluateAttestation(*proofReceipt, "commit123", []string{})

	// Attestation should be rejected
	if attestation.State == lattice.AttestationSealed {
		t.Fatal("CRITICAL: Attestation granted to non-conformant proof")
	}

	// Authority evaluation should be blocked
	auth, _ := lattice.EvaluateAuthority(*attestation)
	if auth.State == lattice.AuthorityGranted {
		t.Fatal("CRITICAL: Authority granted after proof failure")
	}
}

// Integration Test: Full Pipeline Success Path
func TestFullPipeline_SuccessPath(t *testing.T) {
	// 1. Create valid graph
	graphReceipt := lattice.GraphValidationReceipt{
		State:         lattice.StructuralPass,
		CycleDetected: false,
	}
	d, _ := lattice.ComputeDigest(graphReceipt)
	graphReceipt.Digest = d

	// 2. Run all vectors successfully
	proofReceipt, terminal, err := lattice.EvaluateProofPlane(graphReceipt, func() (int, int, error) {
		return 5, 5, nil // All vectors pass
	})

	if terminal != nil || err != nil {
		t.Fatalf("proof plane evaluation failed: terminal=%v, err=%v", terminal, err)
	}
	if proofReceipt.State != lattice.ProofConformant {
		t.Fatalf("expected ProofConformant, got: %s", proofReceipt.State)
	}

	// 3. Attest the proof
	attestation, _, err := lattice.EvaluateAttestation(*proofReceipt, "commit123", []string{"artifact1", "artifact2"})

	if err != nil {
		t.Fatalf("attestation evaluation failed: %v", err)
	}
	if attestation.State != lattice.AttestationSealed {
		t.Fatalf("expected AttestationSealed, got: %s", attestation.State)
	}

	// 4. Grant authority
	auth, err := lattice.EvaluateAuthority(*attestation)

	if err != nil {
		t.Fatalf("authority evaluation failed: %v", err)
	}
	if auth.State != lattice.AuthorityGranted {
		t.Fatalf("expected AuthorityGranted, got: %s", auth.State)
	}
}
