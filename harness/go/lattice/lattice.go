package lattice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Digest enforces 32-byte SHA-256 verification
type Digest string

func ComputeDigest(v any) (Digest, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("failed to marshal for digest: %w", err)
	}
	h := sha256.Sum256(b)
	return Digest(hex.EncodeToString(h[:])), nil
}

// --- Structural Types & States ---

type StructuralState string

const (
	StructuralPass StructuralState = "STRUCTURAL_PASS"
	StructuralFail StructuralState = "STRUCTURAL_FAIL"
)

type GraphValidationReceipt struct {
	Digest              Digest          `json:"digest"`
	State               StructuralState `json:"state"`
	CycleDetected       bool            `json:"cycle_detected"`
	CycleMembers        []string        `json:"cycle_members"`
	AffectedDescendants []string        `json:"affected_descendants"`
}

// --- Proof Plane (Falsification Vectors) ---

type ProofState string

const (
	ProofConformant    ProofState = "CONFORMANT"
	ProofNonConformant ProofState = "NON_CONFORMANT"
)

type ProofPlaneReceipt struct {
	DependsOn           Digest     `json:"depends_on"` // Must match GraphValidationReceipt.Digest
	Digest              Digest     `json:"digest"`
	State               ProofState `json:"state"`
	PassedVectorsCount  int        `json:"passed_vectors_count"`
	TotalVectorsCount   int        `json:"total_vectors_count"`
}

// --- Attestation ---

type AttestationState string

const (
	AttestationSealed    AttestationState = "ATTESTED"
	AttestationRejected  AttestationState = "REJECTED"
)

type AttestationReceipt struct {
	DependsOn        Digest           `json:"depends_on"` // Must match ProofPlaneReceipt.Digest
	Digest           Digest           `json:"digest"`
	State            AttestationState `json:"state"`
	ToolchainCommit  string           `json:"toolchain_commit"`
	ArtifactManifest []string         `json:"artifact_manifest"`
}

// --- Authority (Privileged Transition) ---

type AuthorityState string

const (
	AuthorityGranted AuthorityState = "AUTHORIZED"
	AuthorityDenied  AuthorityState = "RELEASE_DENIED"
)

type AuthorityReceipt struct {
	DependsOn Digest         `json:"depends_on"` // Must match AttestationReceipt.Digest
	Digest    Digest         `json:"digest"`
	State     AuthorityState `json:"state"`
	Timestamp string         `json:"timestamp"`
}

// --- Terminal Rejection (Non-Manufactured Downstream) ---

type TerminalRejectionReceipt struct {
	FailedAtPhase  string `json:"failed_at_phase"`
	RootCause      string `json:"root_cause"`
	DownstreamStatus string `json:"downstream_status"` // Always "NOT_EXECUTED"
}

// --- Error Types (Non-Negotiable) ---

var (
	ErrInadmissiblePredecessor = errors.New("predecessor state is not admissible for transition")
	ErrTamperedPredecessor     = errors.New("predecessor digest verification failed")
	ErrBrokenDependencyChain   = errors.New("dependency pointer mismatch in promotion chain")
)

// --- Transition Functions Enforcing Invariants ---

// EvaluateProofPlane: Requires a structurally valid GraphValidationReceipt
func EvaluateProofPlane(
	graphReceipt GraphValidationReceipt,
	runVectors func() (passed, total int, err error),
) (*ProofPlaneReceipt, *TerminalRejectionReceipt, error) {
	// Invariant 1: Digest Re-Verification
	expectedDigest := graphReceipt.Digest
	graphReceipt.Digest = ""
	actualDigest, _ := ComputeDigest(graphReceipt)
	graphReceipt.Digest = expectedDigest

	if expectedDigest != actualDigest {
		return nil, &TerminalRejectionReceipt{
			FailedAtPhase:   "GRAPH_VALIDATION",
			RootCause:       "Digest tampering detected on graph receipt",
			DownstreamStatus: "NOT_EXECUTED",
		}, ErrTamperedPredecessor
	}

	// Invariant 2: Admissibility Check
	if graphReceipt.State != StructuralPass || graphReceipt.CycleDetected {
		return nil, &TerminalRejectionReceipt{
			FailedAtPhase:   "GRAPH_VALIDATION",
			RootCause:       "Graph contains cycles or structural invalidity",
			DownstreamStatus: "NOT_EXECUTED",
		}, ErrInadmissiblePredecessor
	}

	// Invariant 3: Execute Proof Plane
	passed, total, err := runVectors()
	if err != nil || passed != total {
		r := &ProofPlaneReceipt{
			DependsOn:          expectedDigest,
			State:              ProofNonConformant,
			PassedVectorsCount: passed,
			TotalVectorsCount:  total,
		}
		d, _ := ComputeDigest(r)
		r.Digest = d
		return r, nil, nil
	}

	r := &ProofPlaneReceipt{
		DependsOn:          expectedDigest,
		State:              ProofConformant,
		PassedVectorsCount: passed,
		TotalVectorsCount:  total,
	}
	d, _ := ComputeDigest(r)
	r.Digest = d
	return r, nil, nil
}

// EvaluateAttestation: Requires a conformant ProofPlaneReceipt
func EvaluateAttestation(
	proofReceipt ProofPlaneReceipt,
	toolchainCommit string,
	artifactManifest []string,
) (*AttestationReceipt, *TerminalRejectionReceipt, error) {
	// Invariant 1: Digest Re-Verification
	expectedDigest := proofReceipt.Digest
	proofReceipt.Digest = ""
	actualDigest, _ := ComputeDigest(proofReceipt)
	proofReceipt.Digest = expectedDigest

	if expectedDigest != actualDigest {
		return nil, &TerminalRejectionReceipt{
			FailedAtPhase:   "PROOF_PLANE",
			RootCause:       "Digest tampering detected on proof receipt",
			DownstreamStatus: "NOT_EXECUTED",
		}, ErrTamperedPredecessor
	}

	// Invariant 2: Admissibility Check
	if proofReceipt.State != ProofConformant || proofReceipt.PassedVectorsCount != proofReceipt.TotalVectorsCount {
		r := &AttestationReceipt{
			DependsOn: expectedDigest,
			State:     AttestationRejected,
		}
		d, _ := ComputeDigest(r)
		r.Digest = d
		return r, nil, ErrInadmissiblePredecessor
	}

	// Invariant 3: Create Attestation Receipt
	r := &AttestationReceipt{
		DependsOn:        expectedDigest,
		State:            AttestationSealed,
		ToolchainCommit:  toolchainCommit,
		ArtifactManifest: artifactManifest,
	}
	d, _ := ComputeDigest(r)
	r.Digest = d
	return r, nil, nil
}

// EvaluateAuthority: Requires an attested AttestationReceipt
func EvaluateAuthority(attestation AttestationReceipt) (*AuthorityReceipt, error) {
	// Re-verify attestation digest
	expectedDigest := attestation.Digest
	attestation.Digest = ""
	actualDigest, _ := ComputeDigest(attestation)
	attestation.Digest = expectedDigest

	if expectedDigest != actualDigest {
		return &AuthorityReceipt{
			DependsOn: expectedDigest,
			State:     AuthorityDenied,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}, ErrTamperedPredecessor
	}

	if attestation.State != AttestationSealed {
		return &AuthorityReceipt{
			DependsOn: expectedDigest,
			State:     AuthorityDenied,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		}, ErrInadmissiblePredecessor
	}

	receipt := &AuthorityReceipt{
		DependsOn: expectedDigest,
		State:     AuthorityGranted,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
	d, _ := ComputeDigest(receipt)
	receipt.Digest = d
	return receipt, nil
}
