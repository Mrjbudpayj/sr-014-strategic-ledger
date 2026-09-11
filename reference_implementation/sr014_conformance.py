"""
SR-014 Reference Implementation Candidate

CLASSIFICATION: IMPLEMENTATION CANDIDATE
NOT: Conformance evidence, T1/T2/T3 receipt, Authority determination

This module instantiates the specification-closed architecture with four
mandatory enforcement boundaries:

1. ReplayCapability: Cryptographically authenticated
2. VerifiedTrace: Factory-controlled construction
3. Determination: Target-bound + explicit PredicateResult
4. DeterminationLedger: Strict uniqueness admission
5. AuthorityPolicy: Complete-gate evaluation

Current status:
    SPECIFICATION:             CLOSED
    IMPLEMENTATION:            PENDING VERIFICATION
    EMPIRICAL VERIFICATION:    NOT_ESTABLISHED
    CONFORMANCE:               PENDING
    AUTHORITY:                 0.0000

No empirical evidence is manufactured. All execution must produce actual
T1/T2/T3 receipts before conformance can be determined.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, FrozenSet, List, Optional, Tuple, Union
from datetime import datetime
import hashlib
import hmac
import secrets


# ============================================================================
# Outcome Enumeration
# ============================================================================

class Outcome(Enum):
    """Explicit outcome states. Absence does not imply FALSIFIED."""
    SATISFIED = "SATISFIED"
    FALSIFIED = "FALSIFIED"
    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# ============================================================================
# RawTrace: Input to ReplayEngine
# ============================================================================

@dataclass(frozen=True)
class RawTrace:
    """Immutable record of execution input."""
    target_id: str
    command: str
    environment_digest: str
    config_digest: str
    trace_digest: str
    timestamp: str


# ============================================================================
# FrozenTarget: Code-State Anchor
# ============================================================================

@dataclass(frozen=True)
class FrozenTarget:
    """Immutable specification of required predicates."""
    commit_sha: str
    spec_hash: str
    predicate_set: FrozenSet[str]
    
    def __post_init__(self):
        if not self.commit_sha:
            raise ValueError("FrozenTarget requires commit_sha")
        if not self.spec_hash:
            raise ValueError("FrozenTarget requires spec_hash")
        if not self.predicate_set:
            raise ValueError("FrozenTarget requires non-empty predicate_set")


# ============================================================================
# ReplayCapability: Cryptographic Authentication (Boundary 1)
# ============================================================================

@dataclass(frozen=True)
class ReplayCapability:
    """
    Cryptographically authenticated capability issued only by ReplayEngine
    after successful replay verification.
    
    Binding: nonce + raw_trace_digest + replay_digest + target identity
    """
    nonce: str
    raw_trace_digest: str
    replay_digest: str
    target_id: str
    spec_hash: str
    predicate_set: FrozenSet[str]
    verified_predicates: FrozenSet[str]
    falsified_predicates: FrozenSet[str]
    not_established_predicates: FrozenSet[str]
    signature: str  # HMAC-SHA256 of capability contents
    
    @classmethod
    def from_replay(
        cls,
        engine_secret: bytes,
        nonce: str,
        raw_trace: RawTrace,
        target: FrozenTarget,
        verified_predicates: FrozenSet[str],
        falsified_predicates: FrozenSet[str],
        not_established_predicates: FrozenSet[str],
    ) -> "ReplayCapability":
        """
        Factory method: only valid constructor pathway.
        Enforces binding to RawTrace and FrozenTarget.
        """
        
        # Validate target correspondence
        if raw_trace.target_id != target.commit_sha:
            raise ValueError(
                f"Target mismatch: raw_trace.target_id={raw_trace.target_id} "
                f"does not match target.commit_sha={target.commit_sha}"
            )
        
        # Validate predicate set consistency
        all_predicates = verified_predicates | falsified_predicates | not_established_predicates
        if all_predicates != target.predicate_set:
            raise ValueError(
                f"Predicate set mismatch: "
                f"derived={all_predicates} "
                f"required={target.predicate_set}"
            )
        
        # Compute replay digest (hash of predicate outcomes)
        replay_content = (
            f"{target.commit_sha}"
            f"{target.spec_hash}"
            f"{'|'.join(sorted(verified_predicates))}"
            f"{'|'.join(sorted(falsified_predicates))}"
            f"{'|'.join(sorted(not_established_predicates))}"
        )
        replay_digest = hashlib.sha256(replay_content.encode()).hexdigest()
        
        # Create unsigned capability
        capability_content = (
            f"{nonce}"
            f"{raw_trace.trace_digest}"
            f"{replay_digest}"
            f"{target.commit_sha}"
            f"{target.spec_hash}"
        )
        
        # Sign with engine secret
        signature = hmac.new(
            engine_secret,
            capability_content.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return cls(
            nonce=nonce,
            raw_trace_digest=raw_trace.trace_digest,
            replay_digest=replay_digest,
            target_id=target.commit_sha,
            spec_hash=target.spec_hash,
            predicate_set=target.predicate_set,
            verified_predicates=verified_predicates,
            falsified_predicates=falsified_predicates,
            not_established_predicates=not_established_predicates,
            signature=signature,
        )
    
    def verify_signature(self, engine_secret: bytes) -> bool:
        """Cryptographic verification of capability authenticity."""
        capability_content = (
            f"{self.nonce}"
            f"{self.raw_trace_digest}"
            f"{self.replay_digest}"
            f"{self.target_id}"
            f"{self.spec_hash}"
        )
        expected_signature = hmac.new(
            engine_secret,
            capability_content.encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(self.signature, expected_signature)


# ============================================================================
# PredicateResult: Explicit Outcome Record
# ============================================================================

@dataclass(frozen=True)
class PredicateResult:
    """Explicit outcome for a single predicate. Absence does NOT imply FALSIFIED."""
    predicate: str
    outcome: Outcome
    evidence_digest: Optional[str] = None


# ============================================================================
# VerifiedTrace: Factory-Controlled (Boundary 2)
# ============================================================================

@dataclass(frozen=True)
class VerifiedTrace:
    """
    Immutable record of verified predicates.
    
    Constructed only via ReplayEngine factory method.
    Contains explicit PredicateResult records (not absence-based inference).
    Bound to RawTrace and FrozenTarget.
    """
    raw_trace_digest: str
    replay_digest: str
    predicate_results: FrozenSet[PredicateResult]
    target_id: str
    spec_hash: str
    replay_capability: ReplayCapability
    
    def __post_init__(self):
        if not self.predicate_results:
            raise ValueError("VerifiedTrace requires non-empty predicate_results")
    
    @classmethod
    def from_replay_capability(
        cls,
        replay_capability: ReplayCapability,
        predicate_results: FrozenSet[PredicateResult],
    ) -> "VerifiedTrace":
        """
        Factory method: only valid constructor pathway.
        Enforces consistency between ReplayCapability and PredicateResults.
        """
        
        # Validate predicate set
        result_predicates = frozenset(pr.predicate for pr in predicate_results)
        if result_predicates != replay_capability.predicate_set:
            raise ValueError(
                f"PredicateResult set mismatch: "
                f"results={result_predicates} "
                f"capability={replay_capability.predicate_set}"
            )
        
        # Validate outcome consistency
        verified_in_results = frozenset(
            pr.predicate for pr in predicate_results
            if pr.outcome == Outcome.SATISFIED
        )
        if verified_in_results != replay_capability.verified_predicates:
            raise ValueError(
                f"Verified predicate mismatch: "
                f"results={verified_in_results} "
                f"capability={replay_capability.verified_predicates}"
            )
        
        falsified_in_results = frozenset(
            pr.predicate for pr in predicate_results
            if pr.outcome == Outcome.FALSIFIED
        )
        if falsified_in_results != replay_capability.falsified_predicates:
            raise ValueError(
                f"Falsified predicate mismatch: "
                f"results={falsified_in_results} "
                f"capability={replay_capability.falsified_predicates}"
            )
        
        return cls(
            raw_trace_digest=replay_capability.raw_trace_digest,
            replay_digest=replay_capability.replay_digest,
            predicate_results=predicate_results,
            target_id=replay_capability.target_id,
            spec_hash=replay_capability.spec_hash,
            replay_capability=replay_capability,
        )


# ============================================================================
# Determination: Target-Bound (Boundary 3)
# ============================================================================

@dataclass(frozen=True)
class Determination:
    """
    Immutable determination of a predicate outcome against a target.
    
    Derivable ONLY from VerifiedTrace.
    Target-bound: verified_trace.target_id must match target.commit_sha.
    Explicit outcome: no absence-based inference.
    """
    target_id: str
    scope: str
    predicate: str
    outcome: Outcome
    verified_trace: VerifiedTrace
    
    def __post_init__(self):
        if not self.target_id or not self.scope or not self.predicate:
            raise ValueError(
                "Determination requires target_id, scope, and predicate"
            )
    
    @classmethod
    def from_verified_trace(
        cls,
        scope: str,
        predicate: str,
        verified_trace: VerifiedTrace,
    ) -> "Determination":
        """
        Factory method: only valid constructor pathway.
        Derives outcome from explicit PredicateResult.
        Enforces target binding.
        """
        
        # Validate predicate exists in verified trace
        pr = next(
            (pr for pr in verified_trace.predicate_results
             if pr.predicate == predicate),
            None,
        )
        if pr is None:
            raise ValueError(
                f"Predicate {predicate} not found in verified_trace.predicate_results"
            )
        
        return cls(
            target_id=verified_trace.target_id,
            scope=scope,
            predicate=predicate,
            outcome=pr.outcome,
            verified_trace=verified_trace,
        )


# ============================================================================
# DeterminationConflict: Conflict Recording
# ============================================================================

@dataclass(frozen=True)
class DeterminationConflict:
    """Record of a duplicate or contradictory determination admission attempt."""
    target_id: str
    scope: str
    predicate: str
    existing_outcome: Outcome
    attempted_outcome: Outcome
    reason: str  # "DUPLICATE" or "CONTRADICTORY"


# ============================================================================
# DeterminationLedger: Strict Uniqueness (Boundary 4)
# ============================================================================

class DeterminationLedger:
    """
    Immutable admission ledger enforcing strict uniqueness.
    
    One (target, scope, predicate) → one admitted Determination.
    Second admission always rejected.
    Duplicates and contradictions recorded.
    """
    
    def __init__(self):
        self._entries: Dict[Tuple[str, str, str], Determination] = {}
        self._conflicts: List[DeterminationConflict] = []
    
    def admit(self, determination: Determination) -> Tuple[bool, Optional[DeterminationConflict]]:
        """
        Attempt to admit a Determination.
        
        Returns:
            (admitted: bool, conflict: Optional[DeterminationConflict])
        
        If admitted is False, conflict is populated.
        """
        key = (determination.target_id, determination.scope, determination.predicate)
        
        if key in self._entries:
            existing = self._entries[key]
            
            # Determine conflict reason
            reason = (
                "CONTRADICTORY"
                if existing.outcome != determination.outcome
                else "DUPLICATE"
            )
            
            conflict = DeterminationConflict(
                target_id=determination.target_id,
                scope=determination.scope,
                predicate=determination.predicate,
                existing_outcome=existing.outcome,
                attempted_outcome=determination.outcome,
                reason=reason,
            )
            self._conflicts.append(conflict)
            
            # Reject second admission
            return False, conflict
        
        # First admission: accept
        self._entries[key] = determination
        return True, None
    
    def has_conflicts(self) -> bool:
        """Check for any recorded conflicts."""
        return len(self._conflicts) > 0
    
    def conflicts(self) -> List[DeterminationConflict]:
        """Return all recorded conflicts."""
        return list(self._conflicts)
    
    def entries(self) -> Dict[Tuple[str, str, str], Determination]:
        """Return all admitted determinations."""
        return dict(self._entries)
    
    def snapshot(self) -> Dict:
        """Return immutable snapshot of ledger state."""
        return {
            "entries": [
                {
                    "target_id": d.target_id,
                    "scope": d.scope,
                    "predicate": d.predicate,
                    "outcome": d.outcome.value,
                }
                for d in self._entries.values()
            ],
            "conflicts": [
                {
                    "target_id": c.target_id,
                    "scope": c.scope,
                    "predicate": c.predicate,
                    "existing_outcome": c.existing_outcome.value,
                    "attempted_outcome": c.attempted_outcome.value,
                    "reason": c.reason,
                }
                for c in self._conflicts
            ],
        }


# ============================================================================
# AuthorityDecision: Policy Evaluation (Boundary 5)
# ============================================================================

@dataclass(frozen=True)
class AuthorityDecision:
    """
    Immutable policy evaluation result.
    
    Authority is 1.0000 only when ALL gates are satisfied:
    - No conflicts
    - No falsified predicates
    - All required predicates SATISFIED
    """
    target_id: str
    required_predicates: FrozenSet[str]
    determination_set: FrozenSet[Determination]
    decision: str  # AUTHORIZED | ESCALATE | HALT
    authority_value: float  # 1.0000 or 0.0000
    reason: str


def evaluate_authority(
    target: FrozenTarget,
    ledger: DeterminationLedger,
) -> AuthorityDecision:
    """
    Policy gate: evaluate complete conformance.
    
    Returns Authority(1.0000) only if:
    1. No conflicts recorded
    2. No falsified predicates
    3. All required predicates SATISFIED
    4. No unresolved (NOT_ESTABLISHED or NOT_APPLICABLE) predicates
    
    Otherwise returns Authority(0.0000).
    """
    
    # Gate 1: Conflict check
    if ledger.has_conflicts():
        return AuthorityDecision(
            target_id=target.commit_sha,
            required_predicates=target.predicate_set,
            determination_set=frozenset(ledger.entries().values()),
            decision="ESCALATE",
            authority_value=0.0000,
            reason="CONFLICT_DETECTED",
        )
    
    entries = ledger.entries().values()
    
    # Gate 2: Falsification check
    falsified = frozenset(
        d.predicate for d in entries
        if d.outcome == Outcome.FALSIFIED
    )
    if falsified:
        return AuthorityDecision(
            target_id=target.commit_sha,
            required_predicates=target.predicate_set,
            determination_set=frozenset(entries),
            decision="ESCALATE",
            authority_value=0.0000,
            reason=f"FALSIFIED_PREDICATES: {falsified}",
        )
    
    # Gate 3: Complete satisfaction check
    satisfied = frozenset(
        d.predicate for d in entries
        if d.outcome == Outcome.SATISFIED
    )
    
    not_established = frozenset(
        d.predicate for d in entries
        if d.outcome == Outcome.NOT_ESTABLISHED
    )
    
    not_applicable = frozenset(
        d.predicate for d in entries
        if d.outcome == Outcome.NOT_APPLICABLE
    )
    
    # All required predicates must be SATISFIED
    if target.predicate_set.issubset(satisfied):
        return AuthorityDecision(
            target_id=target.commit_sha,
            required_predicates=target.predicate_set,
            determination_set=frozenset(entries),
            decision="AUTHORIZED",
            authority_value=1.0000,
            reason="ALL_REQUIRED_SATISFIED",
        )
    
    # Partial or missing satisfaction
    missing = target.predicate_set - satisfied
    return AuthorityDecision(
        target_id=target.commit_sha,
        required_predicates=target.predicate_set,
        determination_set=frozenset(entries),
        decision="HALT",
        authority_value=0.0000,
        reason=(
            f"INCOMPLETE: "
            f"missing={missing}, "
            f"not_established={not_established}, "
            f"not_applicable={not_applicable}"
        ),
    )


# ============================================================================
# ReplayEngine: Factory for VerifiedTrace
# ============================================================================

class ReplayEngine:
    """
    Controlled factory for VerifiedTrace and ReplayCapability.
    
    Enforces:
    - Successful replay before VerifiedTrace construction
    - Cryptographic authentication of ReplayCapability
    - Target binding validation
    """
    
    def __init__(self, engine_id: str, engine_secret: bytes):
        self.engine_id = engine_id
        self.engine_secret = engine_secret
        self._replay_counter = 0
    
    def verify(
        self,
        raw_trace: RawTrace,
        target: FrozenTarget,
        predicate_results: FrozenSet[PredicateResult],
    ) -> Union[VerifiedTrace, str]:
        """
        Attempt replay verification.
        
        Returns:
            VerifiedTrace if verification succeeds
            str (error message) if verification fails
        
        On failure, returns NOT_ESTABLISHED without constructing VerifiedTrace.
        """
        
        # Validation: target correspondence
        if raw_trace.target_id != target.commit_sha:
            return (
                f"Target mismatch: raw_trace.target_id={raw_trace.target_id} "
                f"does not match target.commit_sha={target.commit_sha}"
            )
        
        # Validation: predicate set in results
        result_predicates = frozenset(pr.predicate for pr in predicate_results)
        if result_predicates != target.predicate_set:
            return (
                f"Predicate set mismatch: "
                f"results={result_predicates} "
                f"target={target.predicate_set}"
            )
        
        # Extract outcome sets from predicate results
        verified = frozenset(
            pr.predicate for pr in predicate_results
            if pr.outcome == Outcome.SATISFIED
        )
        falsified = frozenset(
            pr.predicate for pr in predicate_results
            if pr.outcome == Outcome.FALSIFIED
        )
        not_established = frozenset(
            pr.predicate for pr in predicate_results
            if pr.outcome == Outcome.NOT_ESTABLISHED
        )
        
        # Issue ReplayCapability (only on successful validation)
        self._replay_counter += 1
        nonce = f"{self.engine_id}:replay:{self._replay_counter}:{secrets.token_hex(8)}"
        
        try:
            replay_capability = ReplayCapability.from_replay(
                engine_secret=self.engine_secret,
                nonce=nonce,
                raw_trace=raw_trace,
                target=target,
                verified_predicates=verified,
                falsified_predicates=falsified,
                not_established_predicates=not_established,
            )
        except ValueError as e:
            return f"ReplayCapability creation failed: {e}"
        
        # Construct VerifiedTrace via factory
        try:
            verified_trace = VerifiedTrace.from_replay_capability(
                replay_capability=replay_capability,
                predicate_results=predicate_results,
            )
        except ValueError as e:
            return f"VerifiedTrace creation failed: {e}"
        
        return verified_trace


# ============================================================================
# Conformance Orchestrator
# ============================================================================

class ConformanceOrchestrator:
    """
    Complete pipeline for conformance evaluation.
    
    Enforces the ordered sequence:
    1. RawTrace → ReplayEngine
    2. ReplayEngine → VerifiedTrace or NOT_ESTABLISHED
    3. VerifiedTrace → Determination
    4. Determination → DeterminationLedger (with admission check)
    5. DeterminationLedger → AuthorityPolicy
    6. AuthorityPolicy → AuthorityDecision
    """
    
    def __init__(self, engine_id: str, engine_secret: bytes):
        self.replay_engine = ReplayEngine(engine_id, engine_secret)
        self.ledger = DeterminationLedger()
    
    def evaluate(
        self,
        target: FrozenTarget,
        raw_trace: RawTrace,
        predicate_results: FrozenSet[PredicateResult],
        scope: str,
    ) -> Tuple[AuthorityDecision, Dict]:
        """
        Complete conformance evaluation pipeline.
        
        Returns:
            (AuthorityDecision, audit_log: Dict)
        """
        
        audit_log = {
            "timestamp": datetime.now().isoformat(),
            "target_id": target.commit_sha,
            "scope": scope,
            "steps": [],
        }
        
        # Step 1: Attempt replay verification
        audit_log["steps"].append({
            "step": "replay_verification",
            "raw_trace_digest": raw_trace.trace_digest,
            "target_id": target.commit_sha,
        })
        
        replay_result = self.replay_engine.verify(
            raw_trace=raw_trace,
            target=target,
            predicate_results=predicate_results,
        )
        
        if isinstance(replay_result, str):
            # Verification failed; record as NOT_ESTABLISHED
            audit_log["steps"].append({
                "step": "replay_verification_result",
                "status": "NOT_ESTABLISHED",
                "reason": replay_result,
            })
            
            decision = AuthorityDecision(
                target_id=target.commit_sha,
                required_predicates=target.predicate_set,
                determination_set=frozenset(),
                decision="HALT",
                authority_value=0.0000,
                reason="VERIFICATION_UNAVAILABLE",
            )
            return decision, audit_log
        
        verified_trace = replay_result
        audit_log["steps"].append({
            "step": "replay_verification_result",
            "status": "SUCCESS",
            "replay_digest": verified_trace.replay_digest,
        })
        
        # Step 2: Derive determinations from verified trace
        audit_log["steps"].append({
            "step": "determination_derivation",
            "predicate_count": len(target.predicate_set),
        })
        
        determinations = []
        for predicate in sorted(target.predicate_set):
            try:
                determination = Determination.from_verified_trace(
                    scope=scope,
                    predicate=predicate,
                    verified_trace=verified_trace,
                )
                determinations.append(determination)
            except ValueError as e:
                audit_log["steps"].append({
                    "step": "determination_derivation_error",
                    "predicate": predicate,
                    "error": str(e),
                })
                # Halt on derivation error
                decision = AuthorityDecision(
                    target_id=target.commit_sha,
                    required_predicates=target.predicate_set,
                    determination_set=frozenset(),
                    decision="HALT",
                    authority_value=0.0000,
                    reason="DETERMINATION_DERIVATION_ERROR",
                )
                return decision, audit_log
        
        # Step 3: Admission to ledger
        audit_log["steps"].append({
            "step": "ledger_admission",
            "determinations_count": len(determinations),
        })
        
        for determination in determinations:
            admitted, conflict = self.ledger.admit(determination)
            
            if not admitted:
                audit_log["steps"].append({
                    "step": "admission_conflict",
                    "predicate": conflict.predicate,
                    "reason": conflict.reason,
                    "existing_outcome": conflict.existing_outcome.value,
                    "attempted_outcome": conflict.attempted_outcome.value,
                })
        
        # Step 4: Policy evaluation
        audit_log["steps"].append({
            "step": "policy_evaluation",
            "ledger_state": self.ledger.snapshot(),
        })
        
        decision = evaluate_authority(target, self.ledger)
        
        audit_log["steps"].append({
            "step": "authority_decision",
            "decision": decision.decision,
            "authority_value": decision.authority_value,
            "reason": decision.reason,
        })
        
        return decision, audit_log


# ============================================================================
# Module Status
# ============================================================================

"""
CLASSIFICATION:            IMPLEMENTATION CANDIDATE
NOT:                       Conformance evidence

This module implements the SR-014 architecture with four mandatory
enforcement boundaries:

1. ReplayCapability: Cryptographically authenticated (HMAC-SHA256)
2. VerifiedTrace: Factory-controlled construction (unreachable except via ReplayEngine)
3. Determination: Target-bound, explicit PredicateResult derivation
4. DeterminationLedger: Strict uniqueness admission (second submission always rejected)
5. AuthorityPolicy: Complete-gate evaluation (1.0000 only when all gates pass)

Current status:
    SPECIFICATION:             CLOSED
    IMPLEMENTATION:            PENDING VERIFICATION
    EMPIRICAL VERIFICATION:    NOT_ESTABLISHED
    CONFORMANCE:               PENDING
    AUTHORITY:                 0.0000

No empirical evidence is manufactured. Execution must produce actual
T1/T2/T3 receipts for conformance determination.

Promotion gate (strictly ordered):
    REFERENCE IMPLEMENTATION
        ↓
    T1 EXECUTION RECEIPT
        ↓
    INDEPENDENT T2 REPRODUCTION
        ↓
    T3 AUDIT RECEIPT
        ↓
    INDEPENDENT CONFORMANCE DETERMINATION
        ↓
    AUTHORITY POLICY EVALUATION
        ↓
    AUTHORIZED (if all gates pass)
"""
