"""
Aethelred Python SDK - Sovereign AI Platform

The most critical piece of software in the Aethelred stack. It enables Data Scientists
to use Aethelred without understanding Blockchain, Rust, or TEEs. Simply write Python,
add a decorator, and your code becomes Sovereign.

Example:
    >>> from aethelred import sovereign, SovereignData
    >>> from aethelred.hardware import Hardware, Compliance
    >>>
    >>> @sovereign(hardware=Hardware.TEE_REQUIRED, compliance=Compliance.UAE_DATA_RESIDENCY)
    ... def analyze_patient(data: SovereignData):
    ...     return model.predict(data)
    >>>
    >>> # Data is automatically protected by hardware attestation
    >>> result = analyze_patient(patient_data)

Features:
    - @sovereign decorator for hardware-enforced data protection
    - SovereignData class for jurisdiction-bound data
    - Automatic TEE attestation and verification
    - Built-in compliance checking (GDPR, HIPAA, UAE-DPL, etc.)
    - Digital Seals for verifiable AI computation
    - Zero-trust security model

Architecture:
    The Python SDK is a thin ergonomic layer over verified Rust code:

    Python User Code (@sovereign decorator)
           ↓
    Python Decorator Layer (intercepts calls, validates attestation)
           ↓
    PyO3 Rust Bindings (SovereignData, Attestation, Compliance)
           ↓
    Aethelred Core (hardware-verified cryptographic operations)
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, Dict, Optional

__version__ = "2.0.0"
__author__ = "Aethelred Team"
__email__ = "dev@aethelred.io"

# Initialize logging
logger = logging.getLogger("aethelred")
logger.addHandler(logging.NullHandler())

# =============================================================================
# Core Rust Bindings Import
# =============================================================================

# Flag to track if Rust core is available
_CORE_AVAILABLE = False
_CORE_IMPORT_ERROR: Optional[Exception] = None

try:
    from aethelred._core import (
        # Types
        Jurisdiction,
        HardwareType,
        # Data
        SovereignData,
        # Attestation
        AttestationReport,
        AttestationProvider,
        # Compliance
        ComplianceEngine,
        # Seals
        DigitalSeal,
        # Context
        ExecutionContext,
        # Utility functions
        sha256_hash,
        version as _core_version,
        is_tee_environment,
        detect_hardware,
    )
    _CORE_AVAILABLE = True
except ImportError as e:
    _CORE_IMPORT_ERROR = e

    # Provide stub implementations for development/testing
    class Jurisdiction:  # type: ignore
        """Stub Jurisdiction for development mode."""
        UAE = "UAE"
        SAUDI_ARABIA = "SAUDI_ARABIA"
        EU = "EU"
        US = "US"
        CHINA = "CHINA"
        SINGAPORE = "SINGAPORE"
        UK = "UK"
        GLOBAL = "GLOBAL"

        def __init__(self, name: str = "GLOBAL"):
            self._name = name

        def __str__(self) -> str:
            return self._name

    class HardwareType:  # type: ignore
        """Stub HardwareType for development mode."""
        GENERIC = "Generic"
        TEE_REQUIRED = "TeeRequired"
        INTEL_SGX = "IntelSgx"
        AWS_NITRO = "AwsNitro"

        @classmethod
        def from_str(cls, s: str) -> "HardwareType":
            return cls()

        def is_tee(self) -> bool:
            return False

        def security_level(self) -> int:
            return 0

        def supports_attestation(self) -> bool:
            return False

        def name(self) -> str:
            return "Generic"

    class SovereignData:  # type: ignore
        """Stub SovereignData for development mode."""

        def __init__(
            self,
            data: bytes,
            jurisdiction: Optional[Any] = None,
            classification: str = "internal",
        ):
            self._data = data
            self._jurisdiction = jurisdiction
            self._classification = classification

        def access(self) -> bytes:
            return self._data

        def jurisdiction(self) -> Optional[Any]:
            return self._jurisdiction

        def classification(self) -> str:
            return self._classification

    class AttestationReport:  # type: ignore
        """Stub AttestationReport for development mode."""

        def __init__(self):
            self.valid = True
            self.hardware_type = "Generic"

        def is_valid(self) -> bool:
            return True

        def hardware_type(self) -> str:
            return "Generic"

    class AttestationProvider:  # type: ignore
        """Stub AttestationProvider for development mode."""

        @classmethod
        def new(cls, hardware_type: str = "Generic") -> "AttestationProvider":
            return cls()

        def get_attestation(self) -> AttestationReport:
            return AttestationReport()

    class ComplianceEngine:  # type: ignore
        """Stub ComplianceEngine for development mode."""

        @classmethod
        def new(cls, regulations: list = None) -> "ComplianceEngine":
            return cls()

        def check(self, operation: str, context: dict = None) -> bool:
            return True

        def validate_transfer(
            self,
            source: str,
            destination: str,
        ) -> bool:
            return True

    class DigitalSeal:  # type: ignore
        """Stub DigitalSeal for development mode."""

        def __init__(self):
            self.id = "stub-seal"

        def id(self) -> str:
            return "stub-seal"

        def verify(self) -> bool:
            return True

    class ExecutionContext:  # type: ignore
        """Stub ExecutionContext for development mode."""

        def __init__(
            self,
            jurisdiction: Optional[Any] = None,
            hardware: Optional[Any] = None,
        ):
            self._jurisdiction = jurisdiction
            self._hardware = hardware

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    def sha256_hash(data: bytes) -> str:
        """Stub sha256_hash for development mode."""
        import hashlib
        return hashlib.sha256(data).hexdigest()

    def _core_version() -> str:
        """Stub version for development mode."""
        return "2.0.0-stub"

    def is_tee_environment() -> bool:
        """Stub is_tee_environment for development mode."""
        return False

    def detect_hardware() -> HardwareType:
        """Stub detect_hardware for development mode."""
        return HardwareType()

    # Log warning about stub mode
    if os.environ.get("AETHELRED_DEBUG"):
        logger.warning(
            f"Rust core not available, using Python stubs: {_CORE_IMPORT_ERROR}"
        )

# =============================================================================
# Python Module Imports
# =============================================================================

# Import Python-side modules
from aethelred.decorators import (
    sovereign,
    require_tee,
    require_attestation,
    compliance_check,
    with_seal,
    SovereignContext,
    SovereignResult,
)

from aethelred.hardware import (
    Hardware,
    Compliance,
    SecurityLevel,
    DataClassification,
    Region,
)

from aethelred.client import (
    AethelredClient,
    SyncAethelredClient,
    Network,
    NetworkConfig,
    ClientConfig,
    RetryPolicy,
    ComputeJob,
    JobStatus,
    DigitalSealInfo,
    ModelInfo,
    BlockInfo,
    ValidatorInfo,
    AccountInfo,
)

from aethelred.tensor import (
    SovereignTensor,
    TensorMetadata,
    DType,
    zeros,
    ones,
    rand,
    randn,
    from_numpy,
    from_torch,
    from_tensorflow,
    concat,
    stack,
)

from aethelred.exceptions import (
    # Base
    AethelredError,
    ErrorSeverity,
    ErrorCategory,
    ErrorContext,
    # Attestation
    AttestationError,
    AttestationNotAvailableError,
    AttestationVerificationError,
    AttestationExpiredError,
    EnclaveInitializationError,
    # Compliance
    ComplianceError,
    ComplianceViolationError,
    DataTransferBlockedError,
    ConsentRequiredError,
    RetentionPeriodExceededError,
    # Jurisdiction
    JurisdictionError,
    JurisdictionViolationError,
    DataLocalizationError,
    JurisdictionNotSupportedError,
    # Hardware
    HardwareError,
    HardwareNotAvailableError,
    HardwareCapabilityError,
    GPUNotAvailableError,
    # Cryptography
    CryptographyError,
    EncryptionError,
    DecryptionError,
    SignatureVerificationError,
    KeyDerivationError,
    ProofGenerationError,
    ProofVerificationError,
    # Network
    NetworkError,
    ConnectionError,
    TimeoutError,
    RPCError,
    TransactionError,
    # Authorization
    AuthorizationError,
    PermissionDeniedError,
    AccessControlError,
    InvalidCredentialsError,
    # Validation
    ValidationError,
    InvalidInputError,
    SchemaValidationError,
    ModelNotFoundError,
    SealNotFoundError,
    # Resource
    ResourceError,
    ResourceExhaustedError,
    QuotaExceededError,
    MemoryError,
    # Internal
    InternalError,
    ConfigurationError,
    StateError,
    NotImplementedError,
    # Convenience
    raise_for_jurisdiction,
    raise_for_attestation,
    raise_for_compliance,
)

# =============================================================================
# Public API
# =============================================================================

__all__ = [
    # Version
    "__version__",

    # Core types
    "Jurisdiction",
    "HardwareType",
    "SovereignData",
    "AttestationReport",
    "AttestationProvider",
    "ComplianceEngine",
    "DigitalSeal",
    "ExecutionContext",

    # Decorators
    "sovereign",
    "require_tee",
    "require_attestation",
    "compliance_check",
    "with_seal",
    "SovereignContext",
    "SovereignResult",

    # Hardware
    "Hardware",
    "Compliance",
    "SecurityLevel",
    "DataClassification",
    "Region",

    # Client
    "AethelredClient",
    "SyncAethelredClient",
    "Network",
    "NetworkConfig",
    "ClientConfig",
    "RetryPolicy",
    "ComputeJob",
    "JobStatus",
    "DigitalSealInfo",
    "ModelInfo",
    "BlockInfo",
    "ValidatorInfo",
    "AccountInfo",

    # Tensor
    "SovereignTensor",
    "TensorMetadata",
    "DType",
    "zeros",
    "ones",
    "rand",
    "randn",
    "from_numpy",
    "from_torch",
    "from_tensorflow",
    "concat",
    "stack",

    # Exceptions - Base
    "AethelredError",
    "ErrorSeverity",
    "ErrorCategory",
    "ErrorContext",

    # Exceptions - Attestation
    "AttestationError",
    "AttestationNotAvailableError",
    "AttestationVerificationError",
    "AttestationExpiredError",
    "EnclaveInitializationError",

    # Exceptions - Compliance
    "ComplianceError",
    "ComplianceViolationError",
    "DataTransferBlockedError",
    "ConsentRequiredError",
    "RetentionPeriodExceededError",

    # Exceptions - Jurisdiction
    "JurisdictionError",
    "JurisdictionViolationError",
    "DataLocalizationError",
    "JurisdictionNotSupportedError",

    # Exceptions - Hardware
    "HardwareError",
    "HardwareNotAvailableError",
    "HardwareCapabilityError",
    "GPUNotAvailableError",

    # Exceptions - Cryptography
    "CryptographyError",
    "EncryptionError",
    "DecryptionError",
    "SignatureVerificationError",
    "KeyDerivationError",
    "ProofGenerationError",
    "ProofVerificationError",

    # Exceptions - Network
    "NetworkError",
    "ConnectionError",
    "TimeoutError",
    "RPCError",
    "TransactionError",

    # Exceptions - Authorization
    "AuthorizationError",
    "PermissionDeniedError",
    "AccessControlError",
    "InvalidCredentialsError",

    # Exceptions - Validation
    "ValidationError",
    "InvalidInputError",
    "SchemaValidationError",
    "ModelNotFoundError",
    "SealNotFoundError",

    # Exceptions - Resource
    "ResourceError",
    "ResourceExhaustedError",
    "QuotaExceededError",
    "MemoryError",

    # Exceptions - Internal
    "InternalError",
    "ConfigurationError",
    "StateError",
    "NotImplementedError",

    # Exception utilities
    "raise_for_jurisdiction",
    "raise_for_attestation",
    "raise_for_compliance",

    # Utility functions
    "sha256_hash",
    "is_tee_environment",
    "detect_hardware",
    "get_version",
    "get_core_version",
    "check_environment",
    "is_core_available",
]


# =============================================================================
# Utility Functions
# =============================================================================

def get_version() -> str:
    """Get the Aethelred SDK version."""
    return __version__


def get_core_version() -> str:
    """Get the Aethelred Rust core version."""
    return _core_version()


def is_core_available() -> bool:
    """Check if the Rust core is available."""
    return _CORE_AVAILABLE


def check_environment() -> Dict[str, Any]:
    """
    Check the current execution environment.

    Returns:
        dict: Environment information including:
            - version: SDK version
            - core_version: Rust core version
            - core_available: Whether Rust core is loaded
            - hardware: Detected hardware type
            - is_tee: Whether running in TEE
            - security_level: Hardware security level
            - supports_attestation: Whether attestation is available
            - tee_environment: Detailed TEE environment info
            - dev_mode: Whether running in development mode
    """
    hardware = detect_hardware()
    dev_mode = os.environ.get("AETHELRED_DEV_MODE", "").lower() == "true"

    result = {
        "version": __version__,
        "core_version": get_core_version(),
        "core_available": _CORE_AVAILABLE,
        "hardware": hardware.name() if hasattr(hardware, "name") else str(hardware),
        "is_tee": hardware.is_tee() if hasattr(hardware, "is_tee") else False,
        "security_level": (
            hardware.security_level()
            if hasattr(hardware, "security_level")
            else 0
        ),
        "supports_attestation": (
            hardware.supports_attestation()
            if hasattr(hardware, "supports_attestation")
            else False
        ),
        "tee_environment": is_tee_environment(),
        "dev_mode": dev_mode,
        "python_version": sys.version,
    }

    # Add core import error if applicable
    if not _CORE_AVAILABLE:
        result["core_import_error"] = str(_CORE_IMPORT_ERROR)

    return result


def enable_dev_mode() -> None:
    """
    Enable development mode.

    In development mode:
    - TEE attestation checks are bypassed
    - Jurisdiction checks are bypassed
    - All operations are logged with warnings

    WARNING: Never use in production!
    """
    os.environ["AETHELRED_DEV_MODE"] = "true"
    logger.warning(
        "Development mode enabled - sovereignty checks are bypassed. "
        "DO NOT use in production!"
    )


def disable_dev_mode() -> None:
    """Disable development mode."""
    os.environ.pop("AETHELRED_DEV_MODE", None)
    logger.info("Development mode disabled - full sovereignty checks active.")


# =============================================================================
# Module Initialization
# =============================================================================

# Print environment info on import in debug mode
if os.environ.get("AETHELRED_DEBUG"):
    env_info = check_environment()
    logger.info(f"Aethelred SDK v{__version__} initialized")
    logger.info(f"Core available: {env_info['core_available']}")
    logger.info(f"Hardware: {env_info['hardware']} (Level {env_info['security_level']})")
    logger.info(f"TEE Environment: {env_info['tee_environment']}")
    logger.info(f"Dev Mode: {env_info['dev_mode']}")

# Show warning if running in stub mode without explicit dev mode
if not _CORE_AVAILABLE and not os.environ.get("AETHELRED_DEV_MODE"):
    import warnings
    warnings.warn(
        "Aethelred Rust core not available. Running with Python stubs. "
        "Set AETHELRED_DEV_MODE=true to suppress this warning, or install "
        "the full package with: pip install aethelred[native]",
        RuntimeWarning,
        stacklevel=2,
    )
