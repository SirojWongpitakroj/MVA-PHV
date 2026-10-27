package phv

import (
	"errors"
	"fmt"
)

var (
	ErrInvalidQueryScope      = errors.New("PHV: invalid authenticated query scope")
	ErrInvalidHPBFProof       = errors.New("PHV: invalid HPBF proof")
	ErrInvalidMVAProof        = errors.New("PHV: invalid MVA proof")
	ErrCheckpointMismatch     = errors.New("PHV: checkpoint mismatch")
	ErrWrongEpoch             = fmt.Errorf("%w: wrong finalized epoch", ErrEvidence)
	ErrRepositoryFailure      = errors.New("PHV: repository failure")
	ErrMissingEvidence        = fmt.Errorf("%w: missing evidence", ErrEvidence)
	ErrDuplicateEvidence      = fmt.Errorf("%w: duplicate evidence", ErrEvidence)
	ErrUnexpectedEvidence     = fmt.Errorf("%w: unexpected evidence", ErrEvidence)
	ErrMalformedProof         = fmt.Errorf("%w: malformed proof", ErrEvidence)
	ErrHMFRootMismatch        = errors.New("PHV: HMF root mismatch")
	ErrRecordInconsistency    = errors.New("PHV: record commitment mismatch")
	ErrLocalizationUnresolved = errors.New("PHV: localization evidence unavailable")
)
