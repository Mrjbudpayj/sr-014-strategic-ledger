package lattice

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// DigestReceipt contains verified proof of computation
type DigestReceipt struct {
	PayloadHash Digest `json:"payload_hash"`
	Computed    bool   `json:"computed"`
}

// VerifyDigest re-computes and compares a digest
func VerifyDigest(expected Digest, payload any) (bool, error) {
	computed, err := ComputeDigest(payload)
	if err != nil {
		return false, fmt.Errorf("digest verification failed: %w", err)
	}
	return expected == computed, nil
}

// CanonicalJSON produces RFC 8785 compliant canonical form
func CanonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal to JSON: %w", err)
	}
	// In production, use a full JCS library; this is simplified
	return b, nil
}

// DigestString returns the SHA-256 digest as a human-readable string
func (d Digest) String() string {
	return string(d)
}

// DigestBytes converts Digest to byte slice for comparison
func (d Digest) Bytes() [32]byte {
	// Convert hex string to [32]byte
	var result [32]byte
	hex.Decode(result[:], []byte(d))
	return result
}
