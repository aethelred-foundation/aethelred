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

	// ErrSessionNotFound indicates that a collaboration session with the
	// requested ID does not exist in the secure cell state.
	ErrSessionNotFound = errors.New("secure cell session not found")

	// ErrSessionNotActive indicates that a requested collaboration session is
	// not currently active.
	ErrSessionNotActive = errors.New("secure cell session is not active")

	// ErrSessionImmutable indicates that a requested session lifecycle mutation
	// is not permitted from the current session posture.
	ErrSessionImmutable = errors.New("secure cell session is immutable")

	// ErrSessionParticipantExists indicates that a participant is already part
	// of the requested collaboration session.
	ErrSessionParticipantExists = errors.New("secure cell session participant already exists")

	// ErrSessionParticipantNotFound indicates that a participant is not part of
	// the requested collaboration session.
	ErrSessionParticipantNotFound = errors.New("secure cell session participant not found")

	// ErrThreadNotFound indicates that a collaboration thread does not exist in
	// the secure cell state.
	ErrThreadNotFound = errors.New("secure cell thread not found")

	// ErrThreadNotActive indicates that a requested collaboration thread is not
	// currently active.
	ErrThreadNotActive = errors.New("secure cell thread is not active")

	// ErrThreadImmutable indicates that a requested thread lifecycle mutation is
	// not permitted from the current thread posture.
	ErrThreadImmutable = errors.New("secure cell thread is immutable")

	// ErrCellImmutable indicates that the secure cell cannot be mutated from its
	// current lifecycle status.
	ErrCellImmutable = errors.New("secure cell is immutable")

	// ErrPolicyDenied indicates that the secure-cell policy engine denied the
	// requested lifecycle transition.
	ErrPolicyDenied = errors.New("secure cell lifecycle transition denied by policy")
)
