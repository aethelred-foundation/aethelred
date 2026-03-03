"""
Aethelred Exception Hierarchy

Provides a comprehensive exception hierarchy for the Aethelred Sovereign AI Platform.
All exceptions are designed for enterprise-grade error handling with detailed
context, error codes, and recovery suggestions.

Example:
    >>> try:
    ...     sovereign_data.access()
    ... except JurisdictionViolationError as e:
    ...     print(f"Error {e.error_code}: {e.message}")
    ...     print(f"Required: {e.required_jurisdiction}")
    ...     print(f"Current: {e.current_jurisdiction}")
    ...     print(f"Suggestion: {e.recovery_suggestion}")
"""

from __future__ import annotations

import traceback
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any, Dict, List, Optional, Type, TypeVar


class ErrorSeverity(IntEnum):
    """Severity levels for errors."""

    DEBUG = 0       # Development-only errors
    INFO = 1        # Informational, not actionable
    WARNING = 2     # Degraded functionality
    ERROR = 3       # Operation failed
    CRITICAL = 4    # System-level failure
    FATAL = 5       # Unrecoverable, requires restart


class ErrorCategory(IntEnum):
    """Categories of errors for filtering and handling."""

    UNKNOWN = 0
    ATTESTATION = 100     # TEE attestation failures
    COMPLIANCE = 200      # Regulatory compliance violations
    JURISDICTION = 300    # Data residency violations
    HARDWARE = 400        # Hardware capability issues
    CRYPTOGRAPHY = 500    # Encryption/signing failures
    NETWORK = 600         # Network/RPC errors
    AUTHORIZATION = 700   # Permission/access control
    VALIDATION = 800      # Input validation errors
    RESOURCE = 900        # Resource exhaustion
    INTERNAL = 1000       # Internal errors


@dataclass
class ErrorContext:
    """
    Rich context for error diagnostics.

    Provides detailed information for debugging and audit trails.
    """

    # Timestamp when error occurred
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Unique error instance ID for tracking
    instance_id: str = field(default_factory=lambda: __import__('uuid').uuid4().hex[:12])

    # Operation that was being performed
    operation: Optional[str] = None

    # Component/module where error originated
    component: Optional[str] = None

    # Stack trace (if enabled)
    stack_trace: Optional[str] = None

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Related errors (for error chains)
    related_errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "instance_id": self.instance_id,
            "operation": self.operation,
            "component": self.component,
            "stack_trace": self.stack_trace,
            "metadata": self.metadata,
            "related_errors": self.related_errors,
        }


class AethelredError(Exception):
    """
    Base exception for all Aethelred errors.

    Provides a rich exception base with:
    - Error codes for programmatic handling
    - Severity levels for alerting
    - Recovery suggestions
    - Full context for debugging
    - Audit trail support

    Example:
        >>> raise AethelredError(
        ...     message="Operation failed",
        ...     error_code="AETHEL-1001",
        ...     severity=ErrorSeverity.ERROR,
        ...     recovery_suggestion="Retry with valid credentials",
        ... )
    """

    # Default error code prefix
    ERROR_PREFIX = "AETHEL"

    # Default category
    CATEGORY = ErrorCategory.UNKNOWN

    def __init__(
        self,
        message: str,
        error_code: Optional[str] = None,
        severity: ErrorSeverity = ErrorSeverity.ERROR,
        recovery_suggestion: Optional[str] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
        include_trace: bool = True,
    ):
        """
        Initialize the exception.

        Args:
            message: Human-readable error message
            error_code: Unique error code (e.g., "AETHEL-1001")
            severity: Error severity level
            recovery_suggestion: Suggested action to resolve
            context: Rich error context
            cause: Original exception that caused this error
            include_trace: Whether to capture stack trace
        """
        super().__init__(message)

        self.message = message
        self.error_code = error_code or f"{self.ERROR_PREFIX}-0000"
        self.severity = severity
        self.recovery_suggestion = recovery_suggestion
        self.cause = cause

        # Create context if not provided
        self.context = context or ErrorContext()

        # Capture stack trace if enabled
        if include_trace:
            self.context.stack_trace = traceback.format_exc()

        # Link to cause
        if cause:
            self.__cause__ = cause

    @property
    def category(self) -> ErrorCategory:
        """Get error category."""
        return self.CATEGORY

    def is_retryable(self) -> bool:
        """Check if the operation that caused this error can be retried."""
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization/logging."""
        return {
            "error_type": self.__class__.__name__,
            "message": self.message,
            "error_code": self.error_code,
            "severity": self.severity.name,
            "category": self.category.name,
            "recovery_suggestion": self.recovery_suggestion,
            "is_retryable": self.is_retryable(),
            "context": self.context.to_dict(),
            "cause": str(self.cause) if self.cause else None,
        }

    def __str__(self) -> str:
        """Format error for display."""
        parts = [f"[{self.error_code}] {self.message}"]
        if self.recovery_suggestion:
            parts.append(f"\nSuggestion: {self.recovery_suggestion}")
        return "".join(parts)

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, "
            f"error_code={self.error_code!r}, "
            f"severity={self.severity.name})"
        )


# =============================================================================
# Attestation Errors (100-199)
# =============================================================================

class AttestationError(AethelredError):
    """Base exception for attestation-related errors."""

    ERROR_PREFIX = "AETHEL-ATT"
    CATEGORY = ErrorCategory.ATTESTATION


class AttestationNotAvailableError(AttestationError):
    """
    Raised when attestation is required but TEE is not available.

    This typically occurs when:
    - Running on non-TEE hardware
    - TEE driver is not installed
    - TEE enclave failed to initialize
    """

    def __init__(
        self,
        message: str = "Hardware attestation is not available",
        required_hardware: Optional[str] = None,
        detected_hardware: Optional[str] = None,
        **kwargs,
    ):
        self.required_hardware = required_hardware
        self.detected_hardware = detected_hardware

        if required_hardware and detected_hardware:
            message = (
                f"Hardware attestation unavailable. "
                f"Required: {required_hardware}, Detected: {detected_hardware}"
            )

        super().__init__(
            message=message,
            error_code="AETHEL-ATT-001",
            recovery_suggestion=(
                "Deploy to TEE-enabled hardware or use dev mode with "
                "AETHELRED_DEV_MODE=true for development/testing."
            ),
            **kwargs,
        )


class AttestationVerificationError(AttestationError):
    """
    Raised when attestation verification fails.

    This can occur due to:
    - Invalid attestation report format
    - Signature verification failure
    - Expired attestation
    - Untrusted measurement
    """

    def __init__(
        self,
        message: str = "Attestation verification failed",
        attestation_type: Optional[str] = None,
        failure_reason: Optional[str] = None,
        **kwargs,
    ):
        self.attestation_type = attestation_type
        self.failure_reason = failure_reason

        if failure_reason:
            message = f"Attestation verification failed: {failure_reason}"

        super().__init__(
            message=message,
            error_code="AETHEL-ATT-002",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion=(
                "Verify enclave measurement matches expected value. "
                "Check that attestation report has not expired."
            ),
            **kwargs,
        )


class AttestationExpiredError(AttestationError):
    """Raised when an attestation report has expired."""

    def __init__(
        self,
        message: str = "Attestation report has expired",
        expired_at: Optional[datetime] = None,
        max_age_seconds: Optional[int] = None,
        **kwargs,
    ):
        self.expired_at = expired_at
        self.max_age_seconds = max_age_seconds

        super().__init__(
            message=message,
            error_code="AETHEL-ATT-003",
            recovery_suggestion="Generate a fresh attestation report.",
            **kwargs,
        )

    def is_retryable(self) -> bool:
        return True


class EnclaveInitializationError(AttestationError):
    """Raised when TEE enclave fails to initialize."""

    def __init__(
        self,
        message: str = "Failed to initialize TEE enclave",
        enclave_type: Optional[str] = None,
        **kwargs,
    ):
        self.enclave_type = enclave_type

        super().__init__(
            message=message,
            error_code="AETHEL-ATT-004",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion=(
                "Check TEE driver installation and enclave configuration. "
                "Verify sufficient EPC memory is available."
            ),
            **kwargs,
        )


# =============================================================================
# Compliance Errors (200-299)
# =============================================================================

class ComplianceError(AethelredError):
    """Base exception for compliance-related errors."""

    ERROR_PREFIX = "AETHEL-CMP"
    CATEGORY = ErrorCategory.COMPLIANCE


class ComplianceViolationError(ComplianceError):
    """
    Raised when an operation violates regulatory compliance requirements.

    Example:
        >>> raise ComplianceViolationError(
        ...     regulation="GDPR",
        ...     violation_type="data_transfer",
        ...     details="Cross-border transfer to non-adequate jurisdiction",
        ... )
    """

    def __init__(
        self,
        message: str = "Compliance violation detected",
        regulation: Optional[str] = None,
        violation_type: Optional[str] = None,
        details: Optional[str] = None,
        legal_reference: Optional[str] = None,
        **kwargs,
    ):
        self.regulation = regulation
        self.violation_type = violation_type
        self.details = details
        self.legal_reference = legal_reference

        if regulation and details:
            message = f"[{regulation}] Compliance violation: {details}"

        super().__init__(
            message=message,
            error_code="AETHEL-CMP-001",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion=(
                f"Review {regulation} requirements and ensure data handling "
                "complies with applicable regulations."
            ),
            **kwargs,
        )


class DataTransferBlockedError(ComplianceError):
    """
    Raised when a cross-border data transfer is blocked.

    This occurs when data would be transferred to a jurisdiction
    that doesn't meet compliance requirements.
    """

    def __init__(
        self,
        message: str = "Cross-border data transfer blocked",
        source_jurisdiction: Optional[str] = None,
        target_jurisdiction: Optional[str] = None,
        blocking_regulation: Optional[str] = None,
        **kwargs,
    ):
        self.source_jurisdiction = source_jurisdiction
        self.target_jurisdiction = target_jurisdiction
        self.blocking_regulation = blocking_regulation

        if source_jurisdiction and target_jurisdiction:
            message = (
                f"Data transfer from {source_jurisdiction} to "
                f"{target_jurisdiction} blocked by {blocking_regulation}"
            )

        super().__init__(
            message=message,
            error_code="AETHEL-CMP-002",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion=(
                "Use data residency-compliant infrastructure or obtain "
                "appropriate legal transfer mechanisms (SCCs, BCRs, etc.)."
            ),
            **kwargs,
        )


class ConsentRequiredError(ComplianceError):
    """Raised when explicit consent is required for an operation."""

    def __init__(
        self,
        message: str = "Explicit consent required",
        consent_type: Optional[str] = None,
        data_categories: Optional[List[str]] = None,
        **kwargs,
    ):
        self.consent_type = consent_type
        self.data_categories = data_categories or []

        super().__init__(
            message=message,
            error_code="AETHEL-CMP-003",
            recovery_suggestion="Obtain explicit consent from data subject.",
            **kwargs,
        )


class RetentionPeriodExceededError(ComplianceError):
    """Raised when data retention period has been exceeded."""

    def __init__(
        self,
        message: str = "Data retention period exceeded",
        retention_policy: Optional[str] = None,
        max_retention_days: Optional[int] = None,
        **kwargs,
    ):
        self.retention_policy = retention_policy
        self.max_retention_days = max_retention_days

        super().__init__(
            message=message,
            error_code="AETHEL-CMP-004",
            recovery_suggestion=(
                "Delete or anonymize data that has exceeded its retention period."
            ),
            **kwargs,
        )


# =============================================================================
# Jurisdiction Errors (300-399)
# =============================================================================

class JurisdictionError(AethelredError):
    """Base exception for jurisdiction-related errors."""

    ERROR_PREFIX = "AETHEL-JUR"
    CATEGORY = ErrorCategory.JURISDICTION


class JurisdictionViolationError(JurisdictionError):
    """
    Raised when data is accessed from an unauthorized jurisdiction.

    This is a core sovereignty enforcement error that prevents
    data from being accessed outside its designated jurisdiction.
    """

    def __init__(
        self,
        message: str = "Jurisdiction violation",
        required_jurisdiction: Optional[str] = None,
        current_jurisdiction: Optional[str] = None,
        data_id: Optional[str] = None,
        **kwargs,
    ):
        self.required_jurisdiction = required_jurisdiction
        self.current_jurisdiction = current_jurisdiction
        self.data_id = data_id

        if required_jurisdiction and current_jurisdiction:
            message = (
                f"Data requires jurisdiction '{required_jurisdiction}' "
                f"but current environment is '{current_jurisdiction}'"
            )

        super().__init__(
            message=message,
            error_code="AETHEL-JUR-001",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion=(
                f"Access this data from a TEE located in {required_jurisdiction}. "
                "Use aethelred.with_jurisdiction() context manager."
            ),
            **kwargs,
        )


class DataLocalizationError(JurisdictionError):
    """Raised when data localization requirements are violated."""

    def __init__(
        self,
        message: str = "Data localization requirement violated",
        required_region: Optional[str] = None,
        actual_region: Optional[str] = None,
        regulation: Optional[str] = None,
        **kwargs,
    ):
        self.required_region = required_region
        self.actual_region = actual_region
        self.regulation = regulation

        super().__init__(
            message=message,
            error_code="AETHEL-JUR-002",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion=(
                f"Process this data in {required_region}-located infrastructure."
            ),
            **kwargs,
        )


class JurisdictionNotSupportedError(JurisdictionError):
    """Raised when a jurisdiction is not supported by the platform."""

    def __init__(
        self,
        message: str = "Jurisdiction not supported",
        jurisdiction: Optional[str] = None,
        supported_jurisdictions: Optional[List[str]] = None,
        **kwargs,
    ):
        self.jurisdiction = jurisdiction
        self.supported_jurisdictions = supported_jurisdictions or []

        super().__init__(
            message=message,
            error_code="AETHEL-JUR-003",
            recovery_suggestion=(
                "Contact support to request additional jurisdiction support."
            ),
            **kwargs,
        )


# =============================================================================
# Hardware Errors (400-499)
# =============================================================================

class HardwareError(AethelredError):
    """Base exception for hardware-related errors."""

    ERROR_PREFIX = "AETHEL-HW"
    CATEGORY = ErrorCategory.HARDWARE


class HardwareNotAvailableError(HardwareError):
    """
    Raised when required hardware is not available.
    """

    def __init__(
        self,
        message: str = "Required hardware not available",
        required_type: Optional[str] = None,
        available_types: Optional[List[str]] = None,
        **kwargs,
    ):
        self.required_type = required_type
        self.available_types = available_types or []

        if required_type:
            message = f"Required hardware '{required_type}' is not available"

        super().__init__(
            message=message,
            error_code="AETHEL-HW-001",
            recovery_suggestion=(
                "Deploy to infrastructure with required hardware capabilities."
            ),
            **kwargs,
        )


class HardwareCapabilityError(HardwareError):
    """Raised when hardware doesn't meet capability requirements."""

    def __init__(
        self,
        message: str = "Hardware capability requirements not met",
        required_capability: Optional[str] = None,
        security_level_required: Optional[int] = None,
        security_level_available: Optional[int] = None,
        **kwargs,
    ):
        self.required_capability = required_capability
        self.security_level_required = security_level_required
        self.security_level_available = security_level_available

        super().__init__(
            message=message,
            error_code="AETHEL-HW-002",
            recovery_suggestion=(
                "Upgrade to hardware with higher security level."
            ),
            **kwargs,
        )


class GPUNotAvailableError(HardwareError):
    """Raised when GPU is required but not available."""

    def __init__(
        self,
        message: str = "GPU not available",
        required_gpu: Optional[str] = None,
        **kwargs,
    ):
        self.required_gpu = required_gpu

        super().__init__(
            message=message,
            error_code="AETHEL-HW-003",
            recovery_suggestion=(
                "Deploy to GPU-enabled infrastructure."
            ),
            **kwargs,
        )


# =============================================================================
# Cryptography Errors (500-599)
# =============================================================================

class CryptographyError(AethelredError):
    """Base exception for cryptography-related errors."""

    ERROR_PREFIX = "AETHEL-CRY"
    CATEGORY = ErrorCategory.CRYPTOGRAPHY


class EncryptionError(CryptographyError):
    """Raised when encryption fails."""

    def __init__(
        self,
        message: str = "Encryption failed",
        algorithm: Optional[str] = None,
        **kwargs,
    ):
        self.algorithm = algorithm

        super().__init__(
            message=message,
            error_code="AETHEL-CRY-001",
            recovery_suggestion="Check encryption key and algorithm configuration.",
            **kwargs,
        )


class DecryptionError(CryptographyError):
    """Raised when decryption fails."""

    def __init__(
        self,
        message: str = "Decryption failed",
        reason: Optional[str] = None,
        **kwargs,
    ):
        self.reason = reason

        if reason:
            message = f"Decryption failed: {reason}"

        super().__init__(
            message=message,
            error_code="AETHEL-CRY-002",
            recovery_suggestion=(
                "Verify decryption key matches encryption key. "
                "Check for data corruption."
            ),
            **kwargs,
        )


class SignatureVerificationError(CryptographyError):
    """Raised when signature verification fails."""

    def __init__(
        self,
        message: str = "Signature verification failed",
        signer: Optional[str] = None,
        **kwargs,
    ):
        self.signer = signer

        super().__init__(
            message=message,
            error_code="AETHEL-CRY-003",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion=(
                "Verify the signature was created with the correct key. "
                "Check for data tampering."
            ),
            **kwargs,
        )


class KeyDerivationError(CryptographyError):
    """Raised when key derivation fails."""

    def __init__(
        self,
        message: str = "Key derivation failed",
        **kwargs,
    ):
        super().__init__(
            message=message,
            error_code="AETHEL-CRY-004",
            recovery_suggestion="Check key derivation parameters.",
            **kwargs,
        )


class ProofGenerationError(CryptographyError):
    """Raised when ZK proof generation fails."""

    def __init__(
        self,
        message: str = "Zero-knowledge proof generation failed",
        proof_type: Optional[str] = None,
        **kwargs,
    ):
        self.proof_type = proof_type

        super().__init__(
            message=message,
            error_code="AETHEL-CRY-005",
            recovery_suggestion=(
                "Check circuit constraints and input validity."
            ),
            **kwargs,
        )


class ProofVerificationError(CryptographyError):
    """Raised when ZK proof verification fails."""

    def __init__(
        self,
        message: str = "Zero-knowledge proof verification failed",
        **kwargs,
    ):
        super().__init__(
            message=message,
            error_code="AETHEL-CRY-006",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion=(
                "Verify proof was generated correctly. "
                "Check for proof tampering."
            ),
            **kwargs,
        )


# =============================================================================
# Network Errors (600-699)
# =============================================================================

class NetworkError(AethelredError):
    """Base exception for network-related errors."""

    ERROR_PREFIX = "AETHEL-NET"
    CATEGORY = ErrorCategory.NETWORK

    def is_retryable(self) -> bool:
        return True


class ConnectionError(NetworkError):
    """Raised when connection to Aethelred network fails."""

    def __init__(
        self,
        message: str = "Failed to connect to Aethelred network",
        endpoint: Optional[str] = None,
        **kwargs,
    ):
        self.endpoint = endpoint

        if endpoint:
            message = f"Failed to connect to {endpoint}"

        super().__init__(
            message=message,
            error_code="AETHEL-NET-001",
            recovery_suggestion=(
                "Check network connectivity and endpoint configuration."
            ),
            **kwargs,
        )


class TimeoutError(NetworkError):
    """Raised when a network operation times out."""

    def __init__(
        self,
        message: str = "Network operation timed out",
        operation: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        **kwargs,
    ):
        self.operation = operation
        self.timeout_seconds = timeout_seconds

        super().__init__(
            message=message,
            error_code="AETHEL-NET-002",
            recovery_suggestion=(
                "Increase timeout or check network latency."
            ),
            **kwargs,
        )


class RPCError(NetworkError):
    """Raised when an RPC call fails."""

    def __init__(
        self,
        message: str = "RPC call failed",
        method: Optional[str] = None,
        rpc_code: Optional[int] = None,
        **kwargs,
    ):
        self.method = method
        self.rpc_code = rpc_code

        if method:
            message = f"RPC call to '{method}' failed"

        super().__init__(
            message=message,
            error_code="AETHEL-NET-003",
            recovery_suggestion="Check RPC endpoint and parameters.",
            **kwargs,
        )


class TransactionError(NetworkError):
    """Raised when a transaction fails."""

    def __init__(
        self,
        message: str = "Transaction failed",
        tx_hash: Optional[str] = None,
        tx_error: Optional[str] = None,
        **kwargs,
    ):
        self.tx_hash = tx_hash
        self.tx_error = tx_error

        if tx_error:
            message = f"Transaction failed: {tx_error}"

        super().__init__(
            message=message,
            error_code="AETHEL-NET-004",
            recovery_suggestion=(
                "Check transaction parameters and account balance."
            ),
            **kwargs,
        )


# =============================================================================
# Authorization Errors (700-799)
# =============================================================================

class AuthorizationError(AethelredError):
    """Base exception for authorization-related errors."""

    ERROR_PREFIX = "AETHEL-AUTH"
    CATEGORY = ErrorCategory.AUTHORIZATION


class PermissionDeniedError(AuthorizationError):
    """Raised when permission is denied for an operation."""

    def __init__(
        self,
        message: str = "Permission denied",
        required_permission: Optional[str] = None,
        resource: Optional[str] = None,
        **kwargs,
    ):
        self.required_permission = required_permission
        self.resource = resource

        if resource:
            message = f"Permission denied for resource: {resource}"

        super().__init__(
            message=message,
            error_code="AETHEL-AUTH-001",
            recovery_suggestion=(
                "Request appropriate permissions from data owner."
            ),
            **kwargs,
        )


class AccessControlError(AuthorizationError):
    """Raised when access control policy blocks access."""

    def __init__(
        self,
        message: str = "Access blocked by policy",
        policy_name: Optional[str] = None,
        reason: Optional[str] = None,
        **kwargs,
    ):
        self.policy_name = policy_name
        self.reason = reason

        super().__init__(
            message=message,
            error_code="AETHEL-AUTH-002",
            recovery_suggestion="Review and update access control policies.",
            **kwargs,
        )


class InvalidCredentialsError(AuthorizationError):
    """Raised when credentials are invalid."""

    def __init__(
        self,
        message: str = "Invalid credentials",
        **kwargs,
    ):
        super().__init__(
            message=message,
            error_code="AETHEL-AUTH-003",
            recovery_suggestion="Check API key or authentication token.",
            **kwargs,
        )


# =============================================================================
# Validation Errors (800-899)
# =============================================================================

class ValidationError(AethelredError):
    """Base exception for validation-related errors."""

    ERROR_PREFIX = "AETHEL-VAL"
    CATEGORY = ErrorCategory.VALIDATION


class InvalidInputError(ValidationError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str = "Invalid input",
        field: Optional[str] = None,
        expected: Optional[str] = None,
        actual: Optional[str] = None,
        **kwargs,
    ):
        self.field = field
        self.expected = expected
        self.actual = actual

        if field:
            message = f"Invalid input for field '{field}'"

        super().__init__(
            message=message,
            error_code="AETHEL-VAL-001",
            recovery_suggestion="Check input format and constraints.",
            **kwargs,
        )


class SchemaValidationError(ValidationError):
    """Raised when schema validation fails."""

    def __init__(
        self,
        message: str = "Schema validation failed",
        schema_errors: Optional[List[str]] = None,
        **kwargs,
    ):
        self.schema_errors = schema_errors or []

        super().__init__(
            message=message,
            error_code="AETHEL-VAL-002",
            recovery_suggestion="Fix schema validation errors.",
            **kwargs,
        )


class ModelNotFoundError(ValidationError):
    """Raised when a referenced model is not found."""

    def __init__(
        self,
        message: str = "Model not found",
        model_id: Optional[str] = None,
        **kwargs,
    ):
        self.model_id = model_id

        if model_id:
            message = f"Model '{model_id}' not found"

        super().__init__(
            message=message,
            error_code="AETHEL-VAL-003",
            recovery_suggestion="Check model ID and registry.",
            **kwargs,
        )


class SealNotFoundError(ValidationError):
    """Raised when a digital seal is not found."""

    def __init__(
        self,
        message: str = "Digital seal not found",
        seal_id: Optional[str] = None,
        **kwargs,
    ):
        self.seal_id = seal_id

        if seal_id:
            message = f"Digital seal '{seal_id}' not found"

        super().__init__(
            message=message,
            error_code="AETHEL-VAL-004",
            recovery_suggestion="Check seal ID and block height.",
            **kwargs,
        )


# =============================================================================
# Resource Errors (900-999)
# =============================================================================

class ResourceError(AethelredError):
    """Base exception for resource-related errors."""

    ERROR_PREFIX = "AETHEL-RES"
    CATEGORY = ErrorCategory.RESOURCE


class ResourceExhaustedError(ResourceError):
    """Raised when a resource is exhausted."""

    def __init__(
        self,
        message: str = "Resource exhausted",
        resource_type: Optional[str] = None,
        limit: Optional[int] = None,
        **kwargs,
    ):
        self.resource_type = resource_type
        self.limit = limit

        super().__init__(
            message=message,
            error_code="AETHEL-RES-001",
            recovery_suggestion="Increase resource limits or reduce usage.",
            **kwargs,
        )

    def is_retryable(self) -> bool:
        return True


class QuotaExceededError(ResourceError):
    """Raised when a quota is exceeded."""

    def __init__(
        self,
        message: str = "Quota exceeded",
        quota_type: Optional[str] = None,
        quota_limit: Optional[int] = None,
        current_usage: Optional[int] = None,
        **kwargs,
    ):
        self.quota_type = quota_type
        self.quota_limit = quota_limit
        self.current_usage = current_usage

        super().__init__(
            message=message,
            error_code="AETHEL-RES-002",
            recovery_suggestion="Request quota increase or wait for reset.",
            **kwargs,
        )


class MemoryError(ResourceError):
    """Raised when memory allocation fails."""

    def __init__(
        self,
        message: str = "Memory allocation failed",
        required_bytes: Optional[int] = None,
        **kwargs,
    ):
        self.required_bytes = required_bytes

        super().__init__(
            message=message,
            error_code="AETHEL-RES-003",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion=(
                "Reduce memory usage or increase available memory."
            ),
            **kwargs,
        )


# =============================================================================
# Internal Errors (1000+)
# =============================================================================

class InternalError(AethelredError):
    """Base exception for internal errors."""

    ERROR_PREFIX = "AETHEL-INT"
    CATEGORY = ErrorCategory.INTERNAL


class ConfigurationError(InternalError):
    """Raised when configuration is invalid."""

    def __init__(
        self,
        message: str = "Invalid configuration",
        config_key: Optional[str] = None,
        **kwargs,
    ):
        self.config_key = config_key

        super().__init__(
            message=message,
            error_code="AETHEL-INT-001",
            recovery_suggestion="Check configuration file and environment.",
            **kwargs,
        )


class StateError(InternalError):
    """Raised when internal state is inconsistent."""

    def __init__(
        self,
        message: str = "Internal state error",
        **kwargs,
    ):
        super().__init__(
            message=message,
            error_code="AETHEL-INT-002",
            severity=ErrorSeverity.CRITICAL,
            recovery_suggestion="Restart the application. Report if persistent.",
            **kwargs,
        )


class NotImplementedError(InternalError):
    """Raised when a feature is not yet implemented."""

    def __init__(
        self,
        message: str = "Feature not implemented",
        feature: Optional[str] = None,
        **kwargs,
    ):
        self.feature = feature

        if feature:
            message = f"Feature '{feature}' is not yet implemented"

        super().__init__(
            message=message,
            error_code="AETHEL-INT-003",
            recovery_suggestion="Check roadmap for feature availability.",
            **kwargs,
        )


# =============================================================================
# Exception Registry
# =============================================================================

# Map of error codes to exception classes for deserialization
_EXCEPTION_REGISTRY: Dict[str, Type[AethelredError]] = {}

def register_exception(cls: Type[AethelredError]) -> Type[AethelredError]:
    """Register an exception class for deserialization."""
    _EXCEPTION_REGISTRY[cls.__name__] = cls
    return cls

def get_exception_class(name: str) -> Optional[Type[AethelredError]]:
    """Get exception class by name."""
    return _EXCEPTION_REGISTRY.get(name)

def from_dict(data: Dict[str, Any]) -> AethelredError:
    """
    Reconstruct an exception from a dictionary.

    Useful for deserializing exceptions from logs or network responses.
    """
    error_type = data.get("error_type", "AethelredError")
    cls = get_exception_class(error_type) or AethelredError

    return cls(
        message=data.get("message", "Unknown error"),
        error_code=data.get("error_code"),
        severity=ErrorSeverity[data.get("severity", "ERROR")],
        recovery_suggestion=data.get("recovery_suggestion"),
    )


# Register all exception classes
for _name, _obj in list(globals().items()):
    if isinstance(_obj, type) and issubclass(_obj, AethelredError):
        register_exception(_obj)


# =============================================================================
# Convenience functions
# =============================================================================

def raise_for_jurisdiction(
    required: str,
    current: str,
    data_id: Optional[str] = None,
) -> None:
    """
    Raise JurisdictionViolationError if jurisdictions don't match.

    Example:
        >>> raise_for_jurisdiction("UAE", "US")
        JurisdictionViolationError: Data requires jurisdiction 'UAE' but current environment is 'US'
    """
    if required != current:
        raise JurisdictionViolationError(
            required_jurisdiction=required,
            current_jurisdiction=current,
            data_id=data_id,
        )


def raise_for_attestation(available: bool, required_hardware: str = "TEE") -> None:
    """
    Raise AttestationNotAvailableError if attestation is not available.
    """
    if not available:
        raise AttestationNotAvailableError(required_hardware=required_hardware)


def raise_for_compliance(
    regulation: str,
    violation_type: str,
    details: str,
) -> None:
    """
    Raise ComplianceViolationError for a compliance issue.
    """
    raise ComplianceViolationError(
        regulation=regulation,
        violation_type=violation_type,
        details=details,
    )
