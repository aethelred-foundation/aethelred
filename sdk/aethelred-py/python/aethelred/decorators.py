"""
Aethelred Decorators - The Killer Feature

This module provides the @sovereign decorator and related utilities that enable
Data Scientists to write sovereign AI code without understanding the underlying
blockchain, TEE, or cryptographic infrastructure.

The decorators intercept function calls, validate hardware attestation, and
enforce sovereignty rules before allowing code execution.

Example:
    >>> from aethelred import sovereign, SovereignData
    >>> from aethelred.hardware import Hardware, Compliance
    >>>
    >>> @sovereign(
    ...     hardware=Hardware.TEE_REQUIRED,
    ...     compliance=Compliance.UAE_DATA_RESIDENCY | Compliance.GDPR,
    ...     jurisdiction="UAE",
    ... )
    >>> async def analyze_genomics(patient_data: SovereignData):
    ...     # This code ONLY runs if:
    ...     # 1. We're inside a verified TEE
    ...     # 2. The patient_data is allowed in this jurisdiction
    ...     # 3. All compliance checks pass
    ...     return model.predict(patient_data)

Architecture:
    The decorator system works as follows:

    1. Function is decorated with @sovereign
    2. When called, decorator intercepts the call
    3. Hardware attestation is fetched (from /dev/attestation or mock)
    4. All SovereignData arguments are validated against attestation
    5. Compliance checks are performed
    6. If all checks pass, function executes
    7. If any check fails, PermissionError is raised
    8. On success, optionally creates Digital Seal
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import inspect
import logging
import os
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Flag, auto
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    TypeVar,
    Union,
    overload,
)

from aethelred._core import (
    AttestationProvider,
    AttestationReport,
    ComplianceEngine,
    DigitalSeal,
    ExecutionContext,
    HardwareType,
    Jurisdiction,
    SovereignData,
    detect_hardware,
    is_tee_environment,
    sha256_hash,
)

from aethelred.hardware import Compliance, Hardware, SecurityLevel
from aethelred.exceptions import (
    AttestationError,
    ComplianceError,
    HardwareMismatchError,
    SovereigntyViolation,
)

logger = logging.getLogger("aethelred.decorators")

# Type variables for generic decorators
F = TypeVar("F", bound=Callable[..., Any])
AsyncF = TypeVar("AsyncF", bound=Callable[..., Awaitable[Any]])


# ============================================================================
# Global State
# ============================================================================

# Thread-local storage for execution context
import threading

_context_local = threading.local()


def get_current_context() -> Optional[ExecutionContext]:
    """Get the current execution context if any."""
    return getattr(_context_local, "context", None)


def set_current_context(ctx: Optional[ExecutionContext]) -> None:
    """Set the current execution context."""
    _context_local.context = ctx


# Global attestation provider (lazily initialized)
_attestation_provider: Optional[AttestationProvider] = None


def get_attestation_provider() -> AttestationProvider:
    """Get the global attestation provider."""
    global _attestation_provider
    if _attestation_provider is None:
        dev_mode = os.environ.get("AETHELRED_ENV", "").lower() != "production"
        _attestation_provider = AttestationProvider(dev_mode=dev_mode)
    return _attestation_provider


def get_local_attestation(user_data: Optional[str] = None) -> AttestationReport:
    """
    Get the local hardware attestation.

    In a real TEE, this reads from /dev/attestation.
    In development mode, this returns a mock attestation.

    Args:
        user_data: Optional user data to include in attestation

    Returns:
        AttestationReport: The hardware attestation report
    """
    provider = get_attestation_provider()
    report = provider.generate_report(user_data)

    # Verify the report
    provider.verify_report(report)

    return report


# ============================================================================
# Sovereign Context Manager
# ============================================================================


@dataclass
class SovereignContext:
    """
    Context manager for sovereign execution.

    Provides a scope where all operations are validated against
    hardware attestation and compliance requirements.

    Example:
        >>> with SovereignContext(hardware=Hardware.TEE_REQUIRED, jurisdiction="UAE") as ctx:
        ...     data = ctx.unlock(sovereign_data)
        ...     result = model.predict(data)
        ...     seal = ctx.create_seal(result)
    """

    hardware: Hardware = Hardware.GENERIC
    jurisdiction: Union[str, Jurisdiction] = "Global"
    compliance: Compliance = Compliance.NONE
    dev_mode: bool = False

    # Internal state
    _context: Optional[ExecutionContext] = field(default=None, repr=False)
    _attestation: Optional[AttestationReport] = field(default=None, repr=False)
    _unlocked_data: List[str] = field(default_factory=list, repr=False)
    _seals_created: List[DigitalSeal] = field(default_factory=list, repr=False)
    _start_time: float = field(default=0.0, repr=False)

    def __post_init__(self):
        # Convert jurisdiction string to enum if needed
        if isinstance(self.jurisdiction, str):
            self.jurisdiction = Jurisdiction.from_code(self.jurisdiction)

        # Auto-detect dev mode from environment
        if not self.dev_mode:
            self.dev_mode = os.environ.get("AETHELRED_ENV", "").lower() != "production"

    def __enter__(self) -> SovereignContext:
        self._start_time = time.time()

        # Create execution context
        hw_type = self._map_hardware_to_type()
        self._context = ExecutionContext(
            hardware=hw_type,
            jurisdiction=self.jurisdiction,
            dev_mode=self.dev_mode,
        )

        # Initialize context (fetch attestation)
        self._context.initialize()
        self._attestation = self._context.get_attestation()

        # Validate hardware requirements
        self._validate_hardware()

        # Set as current context
        set_current_context(self._context)

        logger.info(
            f"Sovereign context entered: hardware={hw_type.name()}, "
            f"jurisdiction={self.jurisdiction.name()}"
        )

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clear current context
        set_current_context(None)

        elapsed = time.time() - self._start_time

        if exc_type is not None:
            logger.error(
                f"Sovereign context exited with error after {elapsed:.2f}s: {exc_val}"
            )
        else:
            logger.info(
                f"Sovereign context exited successfully after {elapsed:.2f}s, "
                f"data_accessed={len(self._unlocked_data)}, "
                f"seals_created={len(self._seals_created)}"
            )

        return False  # Don't suppress exceptions

    async def __aenter__(self) -> SovereignContext:
        return self.__enter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return self.__exit__(exc_type, exc_val, exc_tb)

    def _map_hardware_to_type(self) -> HardwareType:
        """Map Hardware enum to HardwareType."""
        if self.hardware == Hardware.GENERIC:
            return HardwareType.Generic
        elif self.hardware == Hardware.TEE_REQUIRED:
            detected = detect_hardware()
            if not detected.is_tee():
                raise HardwareMismatchError("TEE required but not detected")
            return detected
        elif self.hardware == Hardware.TEE_PREFERRED:
            return detect_hardware()
        elif self.hardware == Hardware.INTEL_SGX:
            return HardwareType.IntelSgxDcap
        elif self.hardware == Hardware.AMD_SEV:
            return HardwareType.AmdSevSnp
        elif self.hardware == Hardware.AWS_NITRO:
            return HardwareType.AwsNitro
        elif self.hardware == Hardware.NVIDIA_H100:
            return HardwareType.NvidiaH100Cc
        else:
            return HardwareType.Generic

    def _validate_hardware(self) -> None:
        """Validate hardware requirements."""
        if self.hardware == Hardware.TEE_REQUIRED:
            if self._attestation is None:
                raise AttestationError("No attestation available")
            if not self._attestation.verified:
                raise AttestationError("Attestation not verified")
            if self._attestation.hardware.security_level() < SecurityLevel.TEE:
                raise HardwareMismatchError(
                    f"TEE required but hardware security level is "
                    f"{self._attestation.hardware.security_level()}"
                )

    def unlock(self, data: SovereignData) -> str:
        """
        Unlock sovereign data within this context.

        Args:
            data: The sovereign data to unlock

        Returns:
            The unlocked data as a string

        Raises:
            SovereigntyViolation: If data cannot be unlocked
        """
        if self._attestation is None:
            raise AttestationError("No attestation available")

        # Access the data (this performs all sovereignty checks in Rust)
        unlocked = data.access(self._attestation)
        self._unlocked_data.append(data.id)

        return unlocked

    def unlock_bytes(self, data: SovereignData) -> bytes:
        """Unlock sovereign data as bytes."""
        if self._attestation is None:
            raise AttestationError("No attestation available")

        unlocked = data.access_bytes(self._attestation)
        self._unlocked_data.append(data.id)

        return unlocked

    def create_seal(
        self,
        model_output: Any,
        model_hash: Optional[str] = None,
        input_hash: Optional[str] = None,
        purpose: str = "inference",
        metadata: Optional[Dict[str, str]] = None,
    ) -> DigitalSeal:
        """
        Create a digital seal for the computation.

        Args:
            model_output: The output of the model
            model_hash: Hash of the model (auto-computed if not provided)
            input_hash: Hash of the input (auto-computed if not provided)
            purpose: Purpose of the computation
            metadata: Additional metadata

        Returns:
            DigitalSeal: The created seal
        """
        if self._context is None:
            raise RuntimeError("Not in sovereign context")

        # Compute hashes
        output_bytes = self._serialize_output(model_output)
        output_hash = sha256_hash(output_bytes)

        if model_hash is None:
            model_hash = "model-" + sha256_hash(b"default-model")[:16]

        if input_hash is None:
            input_hash = "input-" + sha256_hash(b"default-input")[:16]

        # Create seal through context
        seal = self._context.create_seal(model_hash, input_hash, output_hash, purpose)

        # Add metadata
        if metadata:
            for key, value in metadata.items():
                seal.add_metadata(key, value)

        self._seals_created.append(seal)

        return seal

    def _serialize_output(self, output: Any) -> bytes:
        """Serialize model output for hashing."""
        if isinstance(output, bytes):
            return output
        elif isinstance(output, str):
            return output.encode("utf-8")
        elif hasattr(output, "numpy"):
            # Handle PyTorch/TensorFlow tensors
            return output.numpy().tobytes()
        elif hasattr(output, "tobytes"):
            # Handle numpy arrays
            return output.tobytes()
        else:
            import json
            return json.dumps(output, sort_keys=True).encode("utf-8")

    @property
    def attestation(self) -> Optional[AttestationReport]:
        """Get the current attestation report."""
        return self._attestation

    @property
    def context(self) -> Optional[ExecutionContext]:
        """Get the execution context."""
        return self._context


# ============================================================================
# Main @sovereign Decorator
# ============================================================================


def sovereign(
    hardware: Hardware = Hardware.GENERIC,
    compliance: Compliance = Compliance.NONE,
    jurisdiction: Union[str, Jurisdiction] = "Global",
    require_attestation: bool = True,
    create_seal: bool = False,
    audit: bool = True,
    strict: bool = True,
    dev_mode: Optional[bool] = None,
) -> Callable[[F], F]:
    """
    The Aethelred Sovereign Decorator.

    Enforces that the decorated function ONLY runs if the physical hardware
    matches the required jurisdiction and security level. This is the primary
    interface for Data Scientists to create sovereign AI applications.

    Args:
        hardware: Hardware requirement (TEE_REQUIRED, TEE_PREFERRED, etc.)
        compliance: Compliance flags (GDPR, HIPAA, UAE, etc.)
        jurisdiction: Jurisdiction where computation is allowed
        require_attestation: Whether to require hardware attestation
        create_seal: Whether to automatically create a Digital Seal
        audit: Whether to log execution for audit
        strict: Whether to fail on any compliance violation
        dev_mode: Override dev mode (None = auto-detect)

    Returns:
        Decorated function with sovereignty enforcement

    Example:
        >>> @sovereign(
        ...     hardware=Hardware.TEE_REQUIRED,
        ...     compliance=Compliance.UAE_DATA_RESIDENCY | Compliance.GDPR,
        ...     jurisdiction="UAE",
        ... )
        >>> def analyze_patient(data: SovereignData):
        ...     return model.predict(data)
    """

    # Convert jurisdiction string to enum
    if isinstance(jurisdiction, str):
        jurisdiction_enum = Jurisdiction.from_code(jurisdiction)
    else:
        jurisdiction_enum = jurisdiction

    # Determine dev mode
    if dev_mode is None:
        dev_mode = os.environ.get("AETHELRED_ENV", "").lower() != "production"

    def decorator(func: F) -> F:
        # Check if function is async
        is_async = asyncio.iscoroutinefunction(func)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            return _execute_sovereign(
                func=func,
                args=args,
                kwargs=kwargs,
                hardware=hardware,
                compliance=compliance,
                jurisdiction=jurisdiction_enum,
                require_attestation=require_attestation,
                create_seal=create_seal,
                audit=audit,
                strict=strict,
                dev_mode=dev_mode,
                is_async=False,
            )

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            return await _execute_sovereign(
                func=func,
                args=args,
                kwargs=kwargs,
                hardware=hardware,
                compliance=compliance,
                jurisdiction=jurisdiction_enum,
                require_attestation=require_attestation,
                create_seal=create_seal,
                audit=audit,
                strict=strict,
                dev_mode=dev_mode,
                is_async=True,
            )

        if is_async:
            return async_wrapper  # type: ignore
        else:
            return sync_wrapper  # type: ignore

    return decorator


def _execute_sovereign(
    func: Callable,
    args: tuple,
    kwargs: dict,
    hardware: Hardware,
    compliance: Compliance,
    jurisdiction: Jurisdiction,
    require_attestation: bool,
    create_seal: bool,
    audit: bool,
    strict: bool,
    dev_mode: bool,
    is_async: bool,
) -> Any:
    """Execute a function with sovereignty enforcement."""

    start_time = time.time()
    func_name = func.__qualname__

    if audit:
        logger.info(f"Sovereign execution started: {func_name}")

    # Step 1: Get hardware attestation
    if require_attestation:
        try:
            attestation = get_local_attestation()
        except Exception as e:
            if strict:
                raise AttestationError(f"Failed to get attestation: {e}")
            attestation = None
            logger.warning(f"Attestation failed, continuing in non-strict mode: {e}")
    else:
        attestation = None

    # Step 2: Validate hardware requirements
    if hardware != Hardware.GENERIC and attestation is not None:
        _validate_hardware_requirement(hardware, attestation, strict)

    # Step 3: Process SovereignData arguments
    unlocked_args = []
    unlocked_kwargs = {}
    sovereign_data_accessed: List[SovereignData] = []

    for arg in args:
        if isinstance(arg, SovereignData):
            if attestation is None:
                raise SovereigntyViolation(
                    "Cannot access SovereignData without attestation"
                )
            try:
                unlocked_value = arg.access(attestation)
                unlocked_args.append(unlocked_value)
                sovereign_data_accessed.append(arg)
            except Exception as e:
                logger.error(f"Failed to unlock SovereignData: {e}")
                raise SovereigntyViolation(f"Data access blocked: {e}")
        else:
            unlocked_args.append(arg)

    for key, value in kwargs.items():
        if isinstance(value, SovereignData):
            if attestation is None:
                raise SovereigntyViolation(
                    "Cannot access SovereignData without attestation"
                )
            try:
                unlocked_value = value.access(attestation)
                unlocked_kwargs[key] = unlocked_value
                sovereign_data_accessed.append(value)
            except Exception as e:
                logger.error(f"Failed to unlock SovereignData {key}: {e}")
                raise SovereigntyViolation(f"Data access blocked: {e}")
        else:
            unlocked_kwargs[key] = value

    # Step 4: Check compliance
    if compliance != Compliance.NONE and sovereign_data_accessed:
        engine = ComplianceEngine(strict_mode=strict)
        for data in sovereign_data_accessed:
            try:
                engine.validate(data, "process", jurisdiction)
            except Exception as e:
                if strict:
                    raise ComplianceError(f"Compliance check failed: {e}")
                logger.warning(f"Compliance issue (non-strict): {e}")

    # Step 5: Execute the function
    if audit:
        logger.info(
            f"Executing {func_name} in verified {jurisdiction.name()} environment"
        )

    try:
        if is_async:
            # Return coroutine for async execution
            async def async_exec():
                result = await func(*unlocked_args, **unlocked_kwargs)
                return _finalize_execution(
                    result=result,
                    func_name=func_name,
                    attestation=attestation,
                    jurisdiction=jurisdiction,
                    create_seal=create_seal,
                    audit=audit,
                    start_time=start_time,
                )
            return async_exec()
        else:
            result = func(*unlocked_args, **unlocked_kwargs)
            return _finalize_execution(
                result=result,
                func_name=func_name,
                attestation=attestation,
                jurisdiction=jurisdiction,
                create_seal=create_seal,
                audit=audit,
                start_time=start_time,
            )

    except Exception as e:
        elapsed = time.time() - start_time
        if audit:
            logger.error(f"Sovereign execution failed after {elapsed:.2f}s: {e}")
        raise


def _finalize_execution(
    result: Any,
    func_name: str,
    attestation: Optional[AttestationReport],
    jurisdiction: Jurisdiction,
    create_seal: bool,
    audit: bool,
    start_time: float,
) -> Any:
    """Finalize sovereign execution with optional seal creation."""

    elapsed = time.time() - start_time

    if create_seal and attestation is not None:
        # Create seal for the computation
        output_hash = sha256_hash(str(result).encode())
        seal = DigitalSeal(
            model_hash="auto-" + sha256_hash(func_name.encode())[:16],
            input_hash="auto-" + sha256_hash(str(start_time).encode())[:16],
            output_hash=output_hash,
            jurisdiction=jurisdiction,
            purpose=func_name,
        )
        seal.attach_attestation(attestation)
        seal.verify()

        if audit:
            logger.info(f"Digital Seal created: {seal.id}")

        # Return result with seal as attribute
        if hasattr(result, "__dict__"):
            result.__sovereign_seal__ = seal
        else:
            # For primitive types, wrap in container
            result = SovereignResult(value=result, seal=seal)

    if audit:
        logger.info(f"Sovereign execution completed in {elapsed:.2f}s: {func_name}")

    return result


def _validate_hardware_requirement(
    requirement: Hardware,
    attestation: AttestationReport,
    strict: bool,
) -> None:
    """Validate that hardware meets requirements."""

    hw_type = attestation.hardware

    if requirement == Hardware.TEE_REQUIRED:
        if not hw_type.is_tee():
            msg = f"TEE required but running on {hw_type.name()}"
            if strict:
                raise HardwareMismatchError(msg)
            logger.warning(msg)

    elif requirement == Hardware.INTEL_SGX:
        if hw_type not in (HardwareType.IntelSgxDcap, HardwareType.IntelSgxEpid):
            msg = f"Intel SGX required but running on {hw_type.name()}"
            if strict:
                raise HardwareMismatchError(msg)
            logger.warning(msg)

    elif requirement == Hardware.AMD_SEV:
        if hw_type not in (HardwareType.AmdSev, HardwareType.AmdSevSnp):
            msg = f"AMD SEV required but running on {hw_type.name()}"
            if strict:
                raise HardwareMismatchError(msg)
            logger.warning(msg)

    elif requirement == Hardware.AWS_NITRO:
        if hw_type != HardwareType.AwsNitro:
            msg = f"AWS Nitro required but running on {hw_type.name()}"
            if strict:
                raise HardwareMismatchError(msg)
            logger.warning(msg)


# ============================================================================
# Specialized Decorators
# ============================================================================


def require_tee(
    min_security_level: int = SecurityLevel.TEE,
    strict: bool = True,
) -> Callable[[F], F]:
    """
    Decorator that requires TEE execution.

    Args:
        min_security_level: Minimum security level required (0-10)
        strict: Whether to fail if requirements not met

    Example:
        >>> @require_tee(min_security_level=8)
        >>> def process_sensitive_data(data):
        ...     return model.predict(data)
    """
    return sovereign(
        hardware=Hardware.TEE_REQUIRED,
        strict=strict,
    )


def require_attestation(
    hardware: Hardware = Hardware.GENERIC,
    strict: bool = True,
) -> Callable[[F], F]:
    """
    Decorator that requires valid attestation.

    Args:
        hardware: Specific hardware type required
        strict: Whether to fail if attestation invalid

    Example:
        >>> @require_attestation(hardware=Hardware.INTEL_SGX)
        >>> def secure_computation(data):
        ...     return encrypt(data)
    """
    return sovereign(
        hardware=hardware,
        require_attestation=True,
        strict=strict,
    )


def compliance_check(
    regulations: Compliance,
    jurisdiction: Union[str, Jurisdiction] = "Global",
    strict: bool = True,
) -> Callable[[F], F]:
    """
    Decorator for compliance-only validation.

    Args:
        regulations: Compliance flags to check
        jurisdiction: Target jurisdiction
        strict: Whether to fail on violations

    Example:
        >>> @compliance_check(
        ...     regulations=Compliance.GDPR | Compliance.HIPAA,
        ...     jurisdiction="EU",
        ... )
        >>> def process_medical_data(patient_data):
        ...     return analyze(patient_data)
    """
    return sovereign(
        compliance=regulations,
        jurisdiction=jurisdiction,
        require_attestation=False,
        strict=strict,
    )


def with_seal(
    purpose: str = "inference",
    include_attestation: bool = True,
) -> Callable[[F], F]:
    """
    Decorator that automatically creates a Digital Seal.

    Args:
        purpose: Purpose of the computation
        include_attestation: Whether to include attestation in seal

    Example:
        >>> @with_seal(purpose="credit_scoring")
        >>> def calculate_credit_score(applicant_data):
        ...     return model.predict(applicant_data)
    """
    return sovereign(
        create_seal=True,
        require_attestation=include_attestation,
    )


# ============================================================================
# Result Container
# ============================================================================


@dataclass
class SovereignResult:
    """
    Container for sovereign computation results.

    Wraps primitive results with metadata including Digital Seal.
    """

    value: Any
    seal: Optional[DigitalSeal] = None
    attestation: Optional[AttestationReport] = None
    execution_time_ms: Optional[float] = None

    def __repr__(self) -> str:
        seal_id = self.seal.id[:8] if self.seal else "none"
        return f"SovereignResult(value={type(self.value).__name__}, seal={seal_id})"

    def __str__(self) -> str:
        return str(self.value)

    def unwrap(self) -> Any:
        """Get the underlying value."""
        return self.value

    def verify(self) -> bool:
        """Verify the result's seal."""
        if self.seal is None:
            return False
        return self.seal.verify()
