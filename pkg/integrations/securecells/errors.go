package securecells

import "errors"

var (
	// ErrCellNotFound indicates that a secure cell with the requested ID does
	// not exist in the service state.
	ErrCellNotFound = errors.New("secure cell not found")

	// ErrParticipantNotFound indicates that a member with the requested DID does
	// not exist in the secure cell state.
	ErrParticipantNotFound = errors.New("secure cell participant not found")

	// ErrParticipantExists indicates that a member is already present in the
	// secure cell state.
	ErrParticipantExists = errors.New("secure cell participant already exists")

	// ErrCellImmutable indicates that the secure cell cannot be mutated from its
	// current lifecycle status.
	ErrCellImmutable = errors.New("secure cell is immutable")

	// ErrPolicyDenied indicates that the secure-cell policy engine denied the
	// requested lifecycle transition.
	ErrPolicyDenied = errors.New("secure cell lifecycle transition denied by policy")
)
