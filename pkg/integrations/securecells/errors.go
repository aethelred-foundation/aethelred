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

	// ErrDecisionNotFound indicates that a governed thread decision does not
	// exist in the secure cell state.
	ErrDecisionNotFound = errors.New("secure cell thread decision not found")

	// ErrDecisionNotActive indicates that a governed thread decision is not
	// currently in a mutable active posture.
	ErrDecisionNotActive = errors.New("secure cell thread decision is not active")

	// ErrDecisionImmutable indicates that a requested decision lifecycle
	// mutation is not permitted from the current decision posture.
	ErrDecisionImmutable = errors.New("secure cell thread decision is immutable")

	// ErrCellImmutable indicates that the secure cell cannot be mutated from its
	// current lifecycle status.
	ErrCellImmutable = errors.New("secure cell is immutable")

	// ErrFederationInvitationNotFound indicates that a federation invitation
	// does not exist in the secure cell state.
	ErrFederationInvitationNotFound = errors.New("secure cell federation invitation not found")

	// ErrFederationOrganizationNotFound indicates that a federation
	// organization does not exist in the secure cell state.
	ErrFederationOrganizationNotFound = errors.New("secure cell federation organization not found")

	// ErrFederationContractNotFound indicates that a federation contract does
	// not exist in the secure cell state.
	ErrFederationContractNotFound = errors.New("secure cell federation contract not found")

	// ErrFederationInvitationImmutable indicates that a federation invitation
	// cannot be mutated from its current lifecycle posture.
	ErrFederationInvitationImmutable = errors.New("secure cell federation invitation is immutable")

	// ErrFederationCounterproposalNotFound indicates that a federation
	// counterproposal does not exist in the secure cell state.
	ErrFederationCounterproposalNotFound = errors.New("secure cell federation counterproposal not found")

	// ErrFederationCounterproposalImmutable indicates that a federation
	// counterproposal cannot be mutated from its current lifecycle posture.
	ErrFederationCounterproposalImmutable = errors.New("secure cell federation counterproposal is immutable")

	// ErrFederationContractImmutable indicates that a federation contract
	// cannot be mutated from its current lifecycle posture.
	ErrFederationContractImmutable = errors.New("secure cell federation contract is immutable")

	// ErrFederationContractRequired indicates that one or more cross-organization
	// actions require an active federation contract before they can proceed.
	ErrFederationContractRequired = errors.New("secure cell federation contract is required")

	// ErrFederationExchangePolicyDenied indicates that an active federation
	// contract exists but does not authorize the requested exchange scope.
	ErrFederationExchangePolicyDenied = errors.New("secure cell federation exchange policy denied")

	// ErrFederationContractSuspended indicates that a federation contract exists
	// for the requested organization, but it is currently suspended.
	ErrFederationContractSuspended = errors.New("secure cell federation contract is suspended")

	// ErrFederationIncidentResponseNotFound indicates that a bilateral
	// incident-response case does not exist in the secure cell state.
	ErrFederationIncidentResponseNotFound = errors.New("secure cell federation incident response not found")

	// ErrFederationIncidentResponseImmutable indicates that a bilateral
	// incident-response case cannot be mutated from its current lifecycle
	// posture.
	ErrFederationIncidentResponseImmutable = errors.New("secure cell federation incident response is immutable")

	// ErrFederationIncidentDirectiveNotFound indicates that an incident
	// directive does not exist in the secure cell state.
	ErrFederationIncidentDirectiveNotFound = errors.New("secure cell federation incident directive not found")

	// ErrFederationIncidentDirectiveImmutable indicates that an incident
	// directive cannot be mutated from its current lifecycle posture.
	ErrFederationIncidentDirectiveImmutable = errors.New("secure cell federation incident directive is immutable")

	// ErrFederationNegotiationConflict indicates that the owner-authored
	// invitation/renewal terms and the counterparty-offered terms do not yield a
	// mutually valid federation contract.
	ErrFederationNegotiationConflict = errors.New("secure cell federation negotiation conflict")

	// ErrPolicyDenied indicates that the secure-cell policy engine denied the
	// requested lifecycle transition.
	ErrPolicyDenied = errors.New("secure cell lifecycle transition denied by policy")
)
