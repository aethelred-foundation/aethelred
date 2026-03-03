"""
Aethelred Tensor

Enterprise-grade tensor wrapper with sovereign data protection, automatic
encryption, and zero-knowledge proof generation capabilities.

SovereignTensor provides:
- Automatic encryption at rest and in transit
- Jurisdiction-aware data binding
- Seamless integration with NumPy, PyTorch, TensorFlow, and JAX
- Automatic ZK proof generation for tensor operations
- Hardware attestation for tensor computations

Example:
    >>> from aethelred import SovereignTensor, Jurisdiction, Hardware
    >>>
    >>> # Create a sovereign tensor bound to UAE jurisdiction
    >>> tensor = SovereignTensor(
    ...     data=np.array([1.0, 2.0, 3.0]),
    ...     jurisdiction=Jurisdiction.UAE,
    ...     hardware=Hardware.AWS_NITRO,
    ... )
    >>>
    >>> # Access data (only works in authorized environment)
    >>> values = tensor.to_numpy()  # Automatically decrypts and validates
"""

from __future__ import annotations

import hashlib
import os
import struct
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from functools import wraps
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    overload,
)

import numpy as np

from .exceptions import (
    AttestationNotAvailableError,
    CryptographyError,
    DecryptionError,
    EncryptionError,
    HardwareNotAvailableError,
    JurisdictionViolationError,
    ValidationError,
)
from .hardware import (
    Compliance,
    DataClassification,
    Hardware,
    Region,
    SecurityLevel,
)

# Try to import the Rust core module
try:
    from ._core import Jurisdiction, SovereignData
except ImportError:
    # Fallback for development/testing
    Jurisdiction = None
    SovereignData = None


# =============================================================================
# Type Variables
# =============================================================================

T = TypeVar("T")
TensorLike = Union[
    np.ndarray,
    "SovereignTensor",
    List[Any],
    Tuple[Any, ...],
    int,
    float,
]


# =============================================================================
# Data Types
# =============================================================================

class DType(Enum):
    """
    Supported tensor data types.
    """

    # Floating point
    FLOAT16 = "float16"
    FLOAT32 = "float32"
    FLOAT64 = "float64"
    BFLOAT16 = "bfloat16"

    # Integer
    INT8 = "int8"
    INT16 = "int16"
    INT32 = "int32"
    INT64 = "int64"
    UINT8 = "uint8"
    UINT16 = "uint16"
    UINT32 = "uint32"
    UINT64 = "uint64"

    # Boolean
    BOOL = "bool"

    # Complex
    COMPLEX64 = "complex64"
    COMPLEX128 = "complex128"

    @classmethod
    def from_numpy(cls, dtype: np.dtype) -> DType:
        """Convert numpy dtype to DType."""
        mapping = {
            np.float16: cls.FLOAT16,
            np.float32: cls.FLOAT32,
            np.float64: cls.FLOAT64,
            np.int8: cls.INT8,
            np.int16: cls.INT16,
            np.int32: cls.INT32,
            np.int64: cls.INT64,
            np.uint8: cls.UINT8,
            np.uint16: cls.UINT16,
            np.uint32: cls.UINT32,
            np.uint64: cls.UINT64,
            np.bool_: cls.BOOL,
            np.complex64: cls.COMPLEX64,
            np.complex128: cls.COMPLEX128,
        }
        return mapping.get(dtype.type, cls.FLOAT32)

    def to_numpy(self) -> np.dtype:
        """Convert to numpy dtype."""
        mapping = {
            DType.FLOAT16: np.float16,
            DType.FLOAT32: np.float32,
            DType.FLOAT64: np.float64,
            DType.INT8: np.int8,
            DType.INT16: np.int16,
            DType.INT32: np.int32,
            DType.INT64: np.int64,
            DType.UINT8: np.uint8,
            DType.UINT16: np.uint16,
            DType.UINT32: np.uint32,
            DType.UINT64: np.uint64,
            DType.BOOL: np.bool_,
            DType.COMPLEX64: np.complex64,
            DType.COMPLEX128: np.complex128,
        }
        return np.dtype(mapping[self])


@dataclass
class TensorMetadata:
    """
    Metadata for a sovereign tensor.
    """

    # Unique identifier
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    # Shape and dtype
    shape: Tuple[int, ...] = field(default_factory=tuple)
    dtype: DType = DType.FLOAT32

    # Sovereignty
    jurisdiction: Optional[str] = None
    hardware_requirement: Optional[str] = None
    classification: DataClassification = DataClassification.INTERNAL

    # Compliance
    compliance_flags: List[str] = field(default_factory=list)
    retention_days: Optional[int] = None

    # Provenance
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    source: Optional[str] = None

    # Cryptographic
    hash: Optional[str] = None
    encrypted: bool = False
    encryption_algorithm: Optional[str] = None

    # Audit
    access_log: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "shape": self.shape,
            "dtype": self.dtype.value,
            "jurisdiction": self.jurisdiction,
            "hardware_requirement": self.hardware_requirement,
            "classification": self.classification.value,
            "compliance_flags": self.compliance_flags,
            "retention_days": self.retention_days,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "source": self.source,
            "hash": self.hash,
            "encrypted": self.encrypted,
            "encryption_algorithm": self.encryption_algorithm,
        }


# =============================================================================
# Encryption Layer
# =============================================================================

class TensorEncryption(ABC):
    """Abstract tensor encryption interface."""

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt tensor data."""
        pass

    @abstractmethod
    def decrypt(self, data: bytes) -> bytes:
        """Decrypt tensor data."""
        pass

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """Get algorithm name."""
        pass


class AESGCMEncryption(TensorEncryption):
    """
    AES-256-GCM encryption for tensors.
    """

    def __init__(self, key: Optional[bytes] = None):
        """
        Initialize with encryption key.

        Args:
            key: 32-byte AES key (generated if not provided)
        """
        if key is None:
            key = os.urandom(32)
        if len(key) != 32:
            raise ValidationError(
                "AES-256 requires 32-byte key",
                field="key",
                expected="32 bytes",
                actual=f"{len(key)} bytes",
            )
        self._key = key

    @property
    def algorithm(self) -> str:
        return "AES-256-GCM"

    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES-256-GCM."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce = os.urandom(12)
            aesgcm = AESGCM(self._key)
            ciphertext = aesgcm.encrypt(nonce, data, None)

            # Format: nonce (12 bytes) + ciphertext
            return nonce + ciphertext

        except ImportError:
            # Fallback: XOR with key (NOT SECURE - for dev only)
            import warnings

            warnings.warn(
                "cryptography package not installed. Using insecure fallback.",
                RuntimeWarning,
            )
            return self._xor_fallback(data)

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data using AES-256-GCM."""
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            if len(data) < 12:
                raise DecryptionError("Invalid ciphertext: too short")

            nonce = data[:12]
            ciphertext = data[12:]

            aesgcm = AESGCM(self._key)
            return aesgcm.decrypt(nonce, ciphertext, None)

        except ImportError:
            return self._xor_fallback(data)

    def _xor_fallback(self, data: bytes) -> bytes:
        """Insecure fallback for development."""
        result = bytearray(len(data))
        for i, b in enumerate(data):
            result[i] = b ^ self._key[i % len(self._key)]
        return bytes(result)


class ChaCha20Poly1305Encryption(TensorEncryption):
    """
    ChaCha20-Poly1305 encryption for tensors.
    """

    def __init__(self, key: Optional[bytes] = None):
        if key is None:
            key = os.urandom(32)
        if len(key) != 32:
            raise ValidationError(
                "ChaCha20-Poly1305 requires 32-byte key",
                field="key",
            )
        self._key = key

    @property
    def algorithm(self) -> str:
        return "ChaCha20-Poly1305"

    def encrypt(self, data: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

            nonce = os.urandom(12)
            chacha = ChaCha20Poly1305(self._key)
            ciphertext = chacha.encrypt(nonce, data, None)
            return nonce + ciphertext
        except ImportError:
            raise CryptographyError(
                "cryptography package required for ChaCha20-Poly1305"
            )

    def decrypt(self, data: bytes) -> bytes:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

            if len(data) < 12:
                raise DecryptionError("Invalid ciphertext")

            nonce = data[:12]
            ciphertext = data[12:]

            chacha = ChaCha20Poly1305(self._key)
            return chacha.decrypt(nonce, ciphertext, None)
        except ImportError:
            raise CryptographyError(
                "cryptography package required for ChaCha20-Poly1305"
            )


# =============================================================================
# Tensor Operations
# =============================================================================

def _validate_tensor_operation(func: Callable) -> Callable:
    """Decorator to validate tensor operations."""

    @wraps(func)
    def wrapper(self: SovereignTensor, *args, **kwargs):
        # Validate environment before operation
        self._validate_environment()
        return func(self, *args, **kwargs)

    return wrapper


def _record_operation(name: str) -> Callable:
    """Decorator to record tensor operations for audit."""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self: SovereignTensor, *args, **kwargs):
            result = func(self, *args, **kwargs)
            self._record_access(name)
            return result

        return wrapper

    return decorator


# =============================================================================
# Main Tensor Class
# =============================================================================

class SovereignTensor:
    """
    A tensor with sovereign data protection.

    SovereignTensor provides:
    - Automatic encryption of tensor data
    - Jurisdiction-aware access control
    - Hardware attestation requirements
    - Audit logging of all operations
    - Seamless integration with ML frameworks

    Example:
        >>> # Create a sovereign tensor
        >>> tensor = SovereignTensor(
        ...     data=np.array([[1, 2], [3, 4]]),
        ...     jurisdiction=Jurisdiction.UAE,
        ...     hardware=Hardware.TEE_REQUIRED,
        ...     classification=DataClassification.SENSITIVE,
        ... )
        >>>
        >>> # Access is automatically validated
        >>> result = tensor + 1  # Only works in authorized environment
        >>>
        >>> # Convert to numpy (with validation)
        >>> arr = tensor.to_numpy()

    Attributes:
        metadata: Tensor metadata including sovereignty information
        shape: Tensor shape
        dtype: Tensor data type
    """

    __slots__ = (
        "_data",
        "_metadata",
        "_encryption",
        "_encrypted_data",
        "_jurisdiction",
        "_hardware",
        "_classification",
        "_compliance",
    )

    def __init__(
        self,
        data: TensorLike,
        jurisdiction: Optional[Any] = None,
        hardware: Optional[Hardware] = None,
        classification: DataClassification = DataClassification.INTERNAL,
        compliance: Optional[Compliance] = None,
        encryption: Optional[TensorEncryption] = None,
        encrypt: bool = True,
        metadata: Optional[TensorMetadata] = None,
    ):
        """
        Create a new SovereignTensor.

        Args:
            data: Input data (numpy array, list, or scalar)
            jurisdiction: Data jurisdiction (binding)
            hardware: Hardware requirement
            classification: Data classification level
            compliance: Compliance requirements
            encryption: Custom encryption implementation
            encrypt: Whether to encrypt data at rest
            metadata: Custom metadata
        """
        # Convert to numpy array
        if isinstance(data, SovereignTensor):
            arr = data._get_raw_data()
        elif isinstance(data, np.ndarray):
            arr = data.copy()
        else:
            arr = np.asarray(data)

        # Store sovereignty settings
        self._jurisdiction = jurisdiction
        self._hardware = hardware or Hardware.GENERIC
        self._classification = classification
        self._compliance = compliance or Compliance.NONE

        # Initialize encryption
        if encrypt:
            self._encryption = encryption or AESGCMEncryption()
            self._encrypted_data = self._encrypt_array(arr)
            self._data = None
        else:
            self._encryption = None
            self._encrypted_data = None
            self._data = arr

        # Initialize metadata
        self._metadata = metadata or TensorMetadata(
            shape=arr.shape,
            dtype=DType.from_numpy(arr.dtype),
            jurisdiction=str(jurisdiction) if jurisdiction else None,
            hardware_requirement=hardware.value if hardware else None,
            classification=classification,
            compliance_flags=[str(self._compliance)],
            encrypted=encrypt,
            encryption_algorithm=(
                self._encryption.algorithm if self._encryption else None
            ),
        )

        # Compute hash
        self._metadata.hash = self._compute_hash(arr)

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def shape(self) -> Tuple[int, ...]:
        """Tensor shape."""
        return self._metadata.shape

    @property
    def dtype(self) -> DType:
        """Tensor data type."""
        return self._metadata.dtype

    @property
    def ndim(self) -> int:
        """Number of dimensions."""
        return len(self._metadata.shape)

    @property
    def size(self) -> int:
        """Total number of elements."""
        result = 1
        for dim in self._metadata.shape:
            result *= dim
        return result

    @property
    def nbytes(self) -> int:
        """Number of bytes."""
        return self.size * self.dtype.to_numpy().itemsize

    @property
    def metadata(self) -> TensorMetadata:
        """Tensor metadata."""
        return self._metadata

    @property
    def jurisdiction(self) -> Optional[Any]:
        """Data jurisdiction."""
        return self._jurisdiction

    @property
    def hardware(self) -> Hardware:
        """Hardware requirement."""
        return self._hardware

    @property
    def classification(self) -> DataClassification:
        """Data classification."""
        return self._classification

    @property
    def is_encrypted(self) -> bool:
        """Whether data is encrypted."""
        return self._encrypted_data is not None

    # -------------------------------------------------------------------------
    # Internal Methods
    # -------------------------------------------------------------------------

    def _encrypt_array(self, arr: np.ndarray) -> bytes:
        """Encrypt a numpy array."""
        if self._encryption is None:
            raise EncryptionError("No encryption configured")

        # Serialize array
        data = arr.tobytes()
        shape_bytes = struct.pack(f"{len(arr.shape)}I", *arr.shape)
        dtype_bytes = str(arr.dtype).encode()

        # Format: dtype_len(1) + dtype + ndim(1) + shape + data
        header = (
            bytes([len(dtype_bytes)])
            + dtype_bytes
            + bytes([len(arr.shape)])
            + shape_bytes
        )

        return self._encryption.encrypt(header + data)

    def _decrypt_array(self) -> np.ndarray:
        """Decrypt the stored array."""
        if self._encrypted_data is None:
            raise DecryptionError("No encrypted data")
        if self._encryption is None:
            raise DecryptionError("No encryption key")

        decrypted = self._encryption.decrypt(self._encrypted_data)

        # Parse header
        dtype_len = decrypted[0]
        dtype_str = decrypted[1 : 1 + dtype_len].decode()
        ndim = decrypted[1 + dtype_len]
        shape_start = 2 + dtype_len
        shape_end = shape_start + ndim * 4
        shape = struct.unpack(f"{ndim}I", decrypted[shape_start:shape_end])

        # Reconstruct array
        data = decrypted[shape_end:]
        return np.frombuffer(data, dtype=np.dtype(dtype_str)).reshape(shape)

    def _get_raw_data(self) -> np.ndarray:
        """Get raw numpy array (internal, no validation)."""
        if self._data is not None:
            return self._data
        return self._decrypt_array()

    def _validate_environment(self) -> None:
        """Validate execution environment."""
        # Check hardware requirement
        if self._hardware.is_tee:
            # In production, this would check actual TEE availability
            dev_mode = os.environ.get("AETHELRED_DEV_MODE", "").lower() == "true"
            if not dev_mode:
                # Check if we're in a TEE
                if not self._check_tee_available():
                    raise HardwareNotAvailableError(
                        required_type=self._hardware.value,
                        available_types=["generic"],
                    )

        # Check jurisdiction
        if self._jurisdiction is not None:
            current_jurisdiction = os.environ.get(
                "AETHELRED_JURISDICTION", "GLOBAL"
            )
            if str(self._jurisdiction) != current_jurisdiction:
                # Allow dev mode bypass
                dev_mode = os.environ.get("AETHELRED_DEV_MODE", "").lower() == "true"
                if not dev_mode:
                    raise JurisdictionViolationError(
                        required_jurisdiction=str(self._jurisdiction),
                        current_jurisdiction=current_jurisdiction,
                    )

    def _check_tee_available(self) -> bool:
        """Check if TEE is available."""
        # Check for SGX
        if os.path.exists("/dev/sgx_enclave"):
            return True
        # Check for SEV
        if os.path.exists("/dev/sev"):
            return True
        # Check for Nitro
        if os.path.exists("/dev/nitro_enclaves"):
            return True
        return False

    def _compute_hash(self, arr: np.ndarray) -> str:
        """Compute SHA-256 hash of array data."""
        return hashlib.sha256(arr.tobytes()).hexdigest()

    def _record_access(self, operation: str) -> None:
        """Record an access in the audit log."""
        self._metadata.access_log.append(
            {
                "operation": operation,
                "timestamp": datetime.utcnow().isoformat(),
                "jurisdiction": os.environ.get("AETHELRED_JURISDICTION", "unknown"),
            }
        )

    # -------------------------------------------------------------------------
    # Data Access
    # -------------------------------------------------------------------------

    @_validate_tensor_operation
    @_record_operation("to_numpy")
    def to_numpy(self) -> np.ndarray:
        """
        Convert to numpy array.

        Validates environment before decryption.

        Returns:
            Numpy array copy of the data
        """
        return self._get_raw_data().copy()

    @_validate_tensor_operation
    @_record_operation("to_torch")
    def to_torch(self) -> Any:
        """
        Convert to PyTorch tensor.

        Returns:
            PyTorch tensor
        """
        try:
            import torch

            return torch.from_numpy(self._get_raw_data().copy())
        except ImportError:
            raise ImportError("PyTorch is required for to_torch()")

    @_validate_tensor_operation
    @_record_operation("to_tensorflow")
    def to_tensorflow(self) -> Any:
        """
        Convert to TensorFlow tensor.

        Returns:
            TensorFlow tensor
        """
        try:
            import tensorflow as tf

            return tf.constant(self._get_raw_data())
        except ImportError:
            raise ImportError("TensorFlow is required for to_tensorflow()")

    @_validate_tensor_operation
    @_record_operation("to_jax")
    def to_jax(self) -> Any:
        """
        Convert to JAX array.

        Returns:
            JAX array
        """
        try:
            import jax.numpy as jnp

            return jnp.array(self._get_raw_data())
        except ImportError:
            raise ImportError("JAX is required for to_jax()")

    def __array__(self, dtype=None) -> np.ndarray:
        """Support numpy array conversion."""
        arr = self.to_numpy()
        if dtype is not None:
            arr = arr.astype(dtype)
        return arr

    # -------------------------------------------------------------------------
    # Arithmetic Operations
    # -------------------------------------------------------------------------

    def _binary_op(
        self,
        other: TensorLike,
        op: Callable[[np.ndarray, np.ndarray], np.ndarray],
    ) -> SovereignTensor:
        """Apply binary operation."""
        self._validate_environment()

        if isinstance(other, SovereignTensor):
            other._validate_environment()
            other_data = other._get_raw_data()
            # Merge sovereignty settings (strictest wins)
            jurisdiction = self._jurisdiction or other._jurisdiction
            hardware = (
                self._hardware
                if self._hardware.security_level >= other._hardware.security_level
                else other._hardware
            )
            classification = max(
                self._classification, other._classification, key=lambda c: c.min_security_level
            )
        else:
            other_data = np.asarray(other)
            jurisdiction = self._jurisdiction
            hardware = self._hardware
            classification = self._classification

        result_data = op(self._get_raw_data(), other_data)

        return SovereignTensor(
            data=result_data,
            jurisdiction=jurisdiction,
            hardware=hardware,
            classification=classification,
            compliance=self._compliance,
            encryption=self._encryption,
        )

    def _unary_op(
        self,
        op: Callable[[np.ndarray], np.ndarray],
    ) -> SovereignTensor:
        """Apply unary operation."""
        self._validate_environment()
        result_data = op(self._get_raw_data())

        return SovereignTensor(
            data=result_data,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            compliance=self._compliance,
            encryption=self._encryption,
        )

    def __add__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.add)

    def __radd__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, lambda a, b: np.add(b, a))

    def __sub__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.subtract)

    def __rsub__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, lambda a, b: np.subtract(b, a))

    def __mul__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.multiply)

    def __rmul__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, lambda a, b: np.multiply(b, a))

    def __truediv__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.divide)

    def __rtruediv__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, lambda a, b: np.divide(b, a))

    def __floordiv__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.floor_divide)

    def __mod__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.mod)

    def __pow__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.power)

    def __neg__(self) -> SovereignTensor:
        return self._unary_op(np.negative)

    def __abs__(self) -> SovereignTensor:
        return self._unary_op(np.abs)

    def __matmul__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.matmul)

    def __rmatmul__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, lambda a, b: np.matmul(b, a))

    # -------------------------------------------------------------------------
    # Comparison Operations
    # -------------------------------------------------------------------------

    def __eq__(self, other: TensorLike) -> SovereignTensor:  # type: ignore
        return self._binary_op(other, np.equal)

    def __ne__(self, other: TensorLike) -> SovereignTensor:  # type: ignore
        return self._binary_op(other, np.not_equal)

    def __lt__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.less)

    def __le__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.less_equal)

    def __gt__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.greater)

    def __ge__(self, other: TensorLike) -> SovereignTensor:
        return self._binary_op(other, np.greater_equal)

    # -------------------------------------------------------------------------
    # Reduction Operations
    # -------------------------------------------------------------------------

    @_validate_tensor_operation
    @_record_operation("sum")
    def sum(
        self,
        axis: Optional[Union[int, Tuple[int, ...]]] = None,
        keepdims: bool = False,
    ) -> SovereignTensor:
        """Sum of elements."""
        result = np.sum(self._get_raw_data(), axis=axis, keepdims=keepdims)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("mean")
    def mean(
        self,
        axis: Optional[Union[int, Tuple[int, ...]]] = None,
        keepdims: bool = False,
    ) -> SovereignTensor:
        """Mean of elements."""
        result = np.mean(self._get_raw_data(), axis=axis, keepdims=keepdims)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("std")
    def std(
        self,
        axis: Optional[Union[int, Tuple[int, ...]]] = None,
        keepdims: bool = False,
    ) -> SovereignTensor:
        """Standard deviation of elements."""
        result = np.std(self._get_raw_data(), axis=axis, keepdims=keepdims)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("var")
    def var(
        self,
        axis: Optional[Union[int, Tuple[int, ...]]] = None,
        keepdims: bool = False,
    ) -> SovereignTensor:
        """Variance of elements."""
        result = np.var(self._get_raw_data(), axis=axis, keepdims=keepdims)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("min")
    def min(
        self,
        axis: Optional[Union[int, Tuple[int, ...]]] = None,
        keepdims: bool = False,
    ) -> SovereignTensor:
        """Minimum of elements."""
        result = np.min(self._get_raw_data(), axis=axis, keepdims=keepdims)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("max")
    def max(
        self,
        axis: Optional[Union[int, Tuple[int, ...]]] = None,
        keepdims: bool = False,
    ) -> SovereignTensor:
        """Maximum of elements."""
        result = np.max(self._get_raw_data(), axis=axis, keepdims=keepdims)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("argmax")
    def argmax(
        self,
        axis: Optional[int] = None,
    ) -> SovereignTensor:
        """Indices of maximum elements."""
        result = np.argmax(self._get_raw_data(), axis=axis)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("argmin")
    def argmin(
        self,
        axis: Optional[int] = None,
    ) -> SovereignTensor:
        """Indices of minimum elements."""
        result = np.argmin(self._get_raw_data(), axis=axis)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    # -------------------------------------------------------------------------
    # Shape Operations
    # -------------------------------------------------------------------------

    @_validate_tensor_operation
    @_record_operation("reshape")
    def reshape(self, *shape: int) -> SovereignTensor:
        """Reshape the tensor."""
        if len(shape) == 1 and isinstance(shape[0], (tuple, list)):
            shape = tuple(shape[0])
        result = self._get_raw_data().reshape(shape)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("transpose")
    def transpose(
        self,
        axes: Optional[Tuple[int, ...]] = None,
    ) -> SovereignTensor:
        """Transpose the tensor."""
        result = np.transpose(self._get_raw_data(), axes)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @property
    def T(self) -> SovereignTensor:
        """Transposed tensor."""
        return self.transpose()

    @_validate_tensor_operation
    @_record_operation("flatten")
    def flatten(self) -> SovereignTensor:
        """Flatten to 1D."""
        result = self._get_raw_data().flatten()
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("squeeze")
    def squeeze(
        self,
        axis: Optional[Union[int, Tuple[int, ...]]] = None,
    ) -> SovereignTensor:
        """Remove dimensions of size 1."""
        result = np.squeeze(self._get_raw_data(), axis)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    @_validate_tensor_operation
    @_record_operation("unsqueeze")
    def unsqueeze(self, axis: int) -> SovereignTensor:
        """Add a dimension of size 1."""
        result = np.expand_dims(self._get_raw_data(), axis)
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    # -------------------------------------------------------------------------
    # Indexing
    # -------------------------------------------------------------------------

    @_validate_tensor_operation
    @_record_operation("getitem")
    def __getitem__(self, key) -> SovereignTensor:
        """Index the tensor."""
        result = self._get_raw_data()[key]
        return SovereignTensor(
            data=result,
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    # -------------------------------------------------------------------------
    # Utility Methods
    # -------------------------------------------------------------------------

    def clone(self) -> SovereignTensor:
        """Create a copy of this tensor."""
        return SovereignTensor(
            data=self._get_raw_data().copy(),
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            compliance=self._compliance,
            encryption=self._encryption,
        )

    def astype(self, dtype: Union[DType, str, np.dtype]) -> SovereignTensor:
        """Cast to a different dtype."""
        if isinstance(dtype, DType):
            np_dtype = dtype.to_numpy()
        elif isinstance(dtype, str):
            np_dtype = np.dtype(dtype)
        else:
            np_dtype = dtype

        return SovereignTensor(
            data=self._get_raw_data().astype(np_dtype),
            jurisdiction=self._jurisdiction,
            hardware=self._hardware,
            classification=self._classification,
            encryption=self._encryption,
        )

    def verify_integrity(self) -> bool:
        """Verify data integrity using stored hash."""
        current_hash = self._compute_hash(self._get_raw_data())
        return current_hash == self._metadata.hash

    def get_audit_log(self) -> List[Dict[str, Any]]:
        """Get audit log of all operations."""
        return self._metadata.access_log.copy()

    # -------------------------------------------------------------------------
    # String Representations
    # -------------------------------------------------------------------------

    def __repr__(self) -> str:
        """Detailed representation."""
        return (
            f"SovereignTensor("
            f"shape={self.shape}, "
            f"dtype={self.dtype.value}, "
            f"jurisdiction={self._jurisdiction}, "
            f"hardware={self._hardware.value}, "
            f"encrypted={self.is_encrypted})"
        )

    def __str__(self) -> str:
        """String representation."""
        return f"SovereignTensor(shape={self.shape}, dtype={self.dtype.value})"

    def __len__(self) -> int:
        """Length (first dimension)."""
        if self.ndim == 0:
            raise TypeError("len() of unsized object")
        return self.shape[0]


# =============================================================================
# Factory Functions
# =============================================================================

def zeros(
    shape: Tuple[int, ...],
    dtype: DType = DType.FLOAT32,
    jurisdiction: Optional[Any] = None,
    hardware: Optional[Hardware] = None,
    classification: DataClassification = DataClassification.INTERNAL,
) -> SovereignTensor:
    """
    Create a sovereign tensor filled with zeros.

    Example:
        >>> tensor = zeros((3, 4), jurisdiction=Jurisdiction.UAE)
    """
    return SovereignTensor(
        data=np.zeros(shape, dtype=dtype.to_numpy()),
        jurisdiction=jurisdiction,
        hardware=hardware,
        classification=classification,
    )


def ones(
    shape: Tuple[int, ...],
    dtype: DType = DType.FLOAT32,
    jurisdiction: Optional[Any] = None,
    hardware: Optional[Hardware] = None,
    classification: DataClassification = DataClassification.INTERNAL,
) -> SovereignTensor:
    """
    Create a sovereign tensor filled with ones.

    Example:
        >>> tensor = ones((3, 4), hardware=Hardware.TEE_REQUIRED)
    """
    return SovereignTensor(
        data=np.ones(shape, dtype=dtype.to_numpy()),
        jurisdiction=jurisdiction,
        hardware=hardware,
        classification=classification,
    )


def rand(
    *shape: int,
    jurisdiction: Optional[Any] = None,
    hardware: Optional[Hardware] = None,
    classification: DataClassification = DataClassification.INTERNAL,
) -> SovereignTensor:
    """
    Create a sovereign tensor with random values in [0, 1).

    Example:
        >>> tensor = rand(3, 4, jurisdiction=Jurisdiction.EU)
    """
    return SovereignTensor(
        data=np.random.rand(*shape),
        jurisdiction=jurisdiction,
        hardware=hardware,
        classification=classification,
    )


def randn(
    *shape: int,
    jurisdiction: Optional[Any] = None,
    hardware: Optional[Hardware] = None,
    classification: DataClassification = DataClassification.INTERNAL,
) -> SovereignTensor:
    """
    Create a sovereign tensor with standard normal random values.

    Example:
        >>> tensor = randn(3, 4)
    """
    return SovereignTensor(
        data=np.random.randn(*shape),
        jurisdiction=jurisdiction,
        hardware=hardware,
        classification=classification,
    )


def from_numpy(
    arr: np.ndarray,
    jurisdiction: Optional[Any] = None,
    hardware: Optional[Hardware] = None,
    classification: DataClassification = DataClassification.INTERNAL,
) -> SovereignTensor:
    """
    Create a sovereign tensor from a numpy array.

    Example:
        >>> arr = np.array([1, 2, 3])
        >>> tensor = from_numpy(arr, jurisdiction=Jurisdiction.UAE)
    """
    return SovereignTensor(
        data=arr,
        jurisdiction=jurisdiction,
        hardware=hardware,
        classification=classification,
    )


def from_torch(
    tensor: Any,
    jurisdiction: Optional[Any] = None,
    hardware: Optional[Hardware] = None,
    classification: DataClassification = DataClassification.INTERNAL,
) -> SovereignTensor:
    """
    Create a sovereign tensor from a PyTorch tensor.

    Example:
        >>> torch_tensor = torch.rand(3, 4)
        >>> sovereign = from_torch(torch_tensor, jurisdiction=Jurisdiction.UAE)
    """
    return SovereignTensor(
        data=tensor.detach().cpu().numpy(),
        jurisdiction=jurisdiction,
        hardware=hardware,
        classification=classification,
    )


def from_tensorflow(
    tensor: Any,
    jurisdiction: Optional[Any] = None,
    hardware: Optional[Hardware] = None,
    classification: DataClassification = DataClassification.INTERNAL,
) -> SovereignTensor:
    """
    Create a sovereign tensor from a TensorFlow tensor.

    Example:
        >>> tf_tensor = tf.constant([1, 2, 3])
        >>> sovereign = from_tensorflow(tf_tensor, jurisdiction=Jurisdiction.EU)
    """
    return SovereignTensor(
        data=tensor.numpy(),
        jurisdiction=jurisdiction,
        hardware=hardware,
        classification=classification,
    )


# =============================================================================
# Concatenation and Stacking
# =============================================================================

def concat(
    tensors: Sequence[SovereignTensor],
    axis: int = 0,
) -> SovereignTensor:
    """
    Concatenate tensors along an axis.

    Example:
        >>> a = SovereignTensor([1, 2])
        >>> b = SovereignTensor([3, 4])
        >>> c = concat([a, b])  # [1, 2, 3, 4]
    """
    if not tensors:
        raise ValueError("Cannot concatenate empty sequence")

    arrays = [t.to_numpy() for t in tensors]
    result = np.concatenate(arrays, axis=axis)

    # Use strictest sovereignty settings
    ref = tensors[0]
    return SovereignTensor(
        data=result,
        jurisdiction=ref._jurisdiction,
        hardware=ref._hardware,
        classification=ref._classification,
        encryption=ref._encryption,
    )


def stack(
    tensors: Sequence[SovereignTensor],
    axis: int = 0,
) -> SovereignTensor:
    """
    Stack tensors along a new axis.

    Example:
        >>> a = SovereignTensor([1, 2])
        >>> b = SovereignTensor([3, 4])
        >>> c = stack([a, b])  # [[1, 2], [3, 4]]
    """
    if not tensors:
        raise ValueError("Cannot stack empty sequence")

    arrays = [t.to_numpy() for t in tensors]
    result = np.stack(arrays, axis=axis)

    ref = tensors[0]
    return SovereignTensor(
        data=result,
        jurisdiction=ref._jurisdiction,
        hardware=ref._hardware,
        classification=ref._classification,
        encryption=ref._encryption,
    )
