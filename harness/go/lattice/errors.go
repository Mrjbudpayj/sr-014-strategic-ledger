package lattice

import "fmt"

// PhantomReceiptError indicates a downstream receipt was manufactured without proper precondition
type PhantomReceiptError struct {
	Phase  string
	Reason string
}

func (e *PhantomReceiptError) Error() string {
	return fmt.Sprintf("phantom receipt detected at %s: %s", e.Phase, e.Reason)
}

// DownstreamSuppressionViolation indicates code attempted to proceed despite failed precondition
type DownstreamSuppressionViolation struct {
	FailedPhase  string
	AttemptedPhase string
}

func (e *DownstreamSuppressionViolation) Error() string {
	return fmt.Sprintf("critical invariant violation: phase %s attempted to execute after %s failed", e.AttemptedPhase, e.FailedPhase)
}
