package metadata

import (
	"errors"
	"strings"
	"time"
)

// Observation states (CV-01/CV-03). Execution state and verification state
// are separate: an operation can be "completed" at the execution layer and
// "contradicted" at the outcome layer. Consumers must read both.
const (
	ObsSatisfied         = "satisfied"
	ObsContradicted      = "contradicted"
	ObsInconclusive      = "inconclusive"
	ObsCheckFailed       = "check-failed"
	ObsResponseValidated = "response_validated"
)

func validObservationState(s string) bool {
	switch s {
	case ObsSatisfied, ObsContradicted, ObsInconclusive, ObsCheckFailed, ObsResponseValidated:
		return true
	}
	return false
}

// Evidence kinds (G07) separate a verifier's bare assertion from
// corroborating material a reviewer can re-check. "assertion" means the
// digest covers the verifier's identity + claim only; the other kinds
// point at independently retained, redacted evidence.
const (
	EvidenceAssertion = "assertion"
	EvidenceReceipt   = "receipt"
	EvidenceRecipient = "recipient"
	EvidenceExternal  = "external"
)

func validEvidenceKind(s string) bool {
	switch s {
	case EvidenceAssertion, EvidenceReceipt, EvidenceRecipient, EvidenceExternal:
		return true
	}
	return false
}

// Observation is one durable, typed verification observation (CV-03).
// Append-only: conflicting observations coexist and the latest wins by
// (observed_at, rowid); a stale observation can never silently overwrite
// a newer one because rows are never updated.
type Observation struct {
	ID              string
	OperationID     string
	AttemptID       string
	VerifierID      string
	VerifierVersion string
	State           string
	// ObservedAt is the actual external observation time (G07): set by
	// the caller from the verifier's report, never defaulted to
	// invocation time when a real observation instant is known.
	ObservedAt time.Time
	// RecordedAt is the commit time, stamped at insert. History order
	// uses ObservedAt; RecordedAt shows when the broker learned it.
	RecordedAt     time.Time
	EvidenceDigest string
	EvidenceKind   string
	Source         string
	Details        string
}

// RecordObservation appends one observation. Details are bounded and
// sanitized like verifier output; unknown states are rejected.
func (d *DB) RecordObservation(o *Observation) error {
	if o == nil {
		return errors.New("nil observation")
	}
	if !validObservationState(o.State) {
		return errors.New("unknown observation state")
	}
	if len(o.Details) > 4096 {
		return errors.New("observation details too large")
	}
	for _, r := range o.Details {
		if r < 32 && r != '\n' && r != '\t' || r == 127 {
			return errors.New("observation details have control characters")
		}
	}
	if o.ID == "" {
		o.ID = "obs-" + generateID()[:12]
	}
	if o.ObservedAt.IsZero() {
		o.ObservedAt = time.Now()
	}
	o.RecordedAt = time.Now()
	if o.EvidenceKind == "" {
		o.EvidenceKind = EvidenceAssertion
	}
	if !validEvidenceKind(o.EvidenceKind) {
		return errors.New("unknown evidence kind")
	}
	_, err := d.db.Exec(`
		INSERT INTO outcome_observations
		  (observation_id, operation_id, attempt_id, verifier_id, verifier_version,
		   state, observed_at, recorded_at, evidence_digest, evidence_kind,
		   observation_source, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, o.ID, o.OperationID, o.AttemptID, o.VerifierID, o.VerifierVersion,
		o.State, o.ObservedAt, o.RecordedAt, o.EvidenceDigest, o.EvidenceKind,
		o.Source, o.Details)
	return err
}

// LatestObservation returns the newest observation for an operation, or
// nil when nothing has been observed. Ordering is by observation time,
// then insertion order: two observations with the same timestamp resolve
// deterministically and the newer insert wins.
func (d *DB) LatestObservation(opID string) (*Observation, error) {
	o := &Observation{}
	err := d.db.QueryRow(`
		SELECT observation_id, operation_id, attempt_id, verifier_id, verifier_version,
		       state, observed_at, recorded_at, evidence_digest, evidence_kind,
		       observation_source, details
		FROM outcome_observations WHERE operation_id = ?
		ORDER BY observed_at DESC, rowid DESC LIMIT 1
	`, opID).Scan(&o.ID, &o.OperationID, &o.AttemptID, &o.VerifierID, &o.VerifierVersion,
		&o.State, &o.ObservedAt, &o.RecordedAt, &o.EvidenceDigest, &o.EvidenceKind,
		&o.Source, &o.Details)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}
	return o, nil
}

// ListObservations returns the full history for an operation, oldest
// first, so a reviewer can see whether later evidence contradicted an
// earlier conclusion (CV-03).
func (d *DB) ListObservations(opID string) ([]*Observation, error) {
	rows, err := d.db.Query(`
		SELECT observation_id, operation_id, attempt_id, verifier_id, verifier_version,
		       state, observed_at, recorded_at, evidence_digest, evidence_kind,
		       observation_source, details
		FROM outcome_observations WHERE operation_id = ?
		ORDER BY observed_at ASC, rowid ASC
	`, opID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Observation
	for rows.Next() {
		o := &Observation{}
		if err := rows.Scan(&o.ID, &o.OperationID, &o.AttemptID, &o.VerifierID,
			&o.VerifierVersion, &o.State, &o.ObservedAt, &o.RecordedAt,
			&o.EvidenceDigest, &o.EvidenceKind, &o.Source, &o.Details); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// LatestAttemptID returns the most recent execution attempt for an op,
// or "" when none exists. Observations bind to the assessed attempt so a
// retry's observation cannot be mistaken for the original attempt's.
func (d *DB) LatestAttemptID(opID string) (string, error) {
	var id string
	err := d.db.QueryRow(`
		SELECT id FROM execution_attempts WHERE op_id = ?
		ORDER BY started_at DESC LIMIT 1
	`, opID).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return "", nil
		}
		return "", err
	}
	return id, nil
}
