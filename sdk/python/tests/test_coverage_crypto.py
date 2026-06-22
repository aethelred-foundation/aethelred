"""
Comprehensive tests for crypto fallback module:
- aethelred/crypto/fallback.py (BackendVariant, BackendInfo, detection, HybridSigner, HybridVerifier,
  _PurePythonHybridSigner, _PurePythonHybridVerifier, _NativeHybridSigner, _NativeHybridVerifier)
"""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock, patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, SECP256K1, derive_private_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest


def _fixed_ec_private_key():
    return derive_private_key(1, SECP256K1())


def _raw_ecdsa_signature(private_key, message: bytes) -> bytes:
    der_sig = private_key.sign(message, ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _ec_public_key_bytes(public_key) -> bytes:
    return public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]


# ---------------------------------------------------------------------------
# BackendVariant enum
# ---------------------------------------------------------------------------

class TestBackendVariant:
    def test_values(self):
        from aethelred.crypto.fallback import BackendVariant
        assert BackendVariant.NATIVE_LIBOQS.value == "native-liboqs"
        assert BackendVariant.PURE_PYTHON.value == "pure-python"

    def test_members(self):
        from aethelred.crypto.fallback import BackendVariant
        assert len(BackendVariant) == 2


# ---------------------------------------------------------------------------
# BackendInfo dataclass
# ---------------------------------------------------------------------------

class TestBackendInfo:
    def test_creation(self):
        from aethelred.crypto.fallback import BackendInfo, BackendVariant
        info = BackendInfo(
            name="test",
            variant=BackendVariant.PURE_PYTHON,
            version="1.0.0",
            fips_compliant=False,
            constant_time=False,
        )
        assert info.name == "test"
        assert info.variant == BackendVariant.PURE_PYTHON
        assert info.version == "1.0.0"
        assert info.fips_compliant is False
        assert info.constant_time is False

    def test_str_non_fips(self):
        from aethelred.crypto.fallback import BackendInfo, BackendVariant
        info = BackendInfo(
            name="pure-python",
            variant=BackendVariant.PURE_PYTHON,
            version="0.1.0",
            fips_compliant=False,
            constant_time=False,
        )
        s = str(info)
        assert "pure-python" in s
        assert "non-FIPS" in s

    def test_str_fips(self):
        from aethelred.crypto.fallback import BackendInfo, BackendVariant
        info = BackendInfo(
            name="liboqs",
            variant=BackendVariant.NATIVE_LIBOQS,
            version="0.9.0",
            fips_compliant=True,
            constant_time=True,
        )
        s = str(info)
        assert "liboqs" in s
        assert "FIPS" in s

    def test_frozen(self):
        from aethelred.crypto.fallback import BackendInfo, BackendVariant
        info = BackendInfo(
            name="test",
            variant=BackendVariant.PURE_PYTHON,
            version="1.0",
            fips_compliant=False,
            constant_time=False,
        )
        with pytest.raises(AttributeError):
            info.name = "changed"


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

class TestDetectBackend:
    def test_detect_native_liboqs(self):
        from aethelred.crypto.fallback import _detect_backend, BackendVariant
        mock_oqs = MagicMock()
        mock_oqs.__version__ = "0.9.0"
        with patch("importlib.import_module", return_value=mock_oqs):
            info = _detect_backend()
            assert info.variant == BackendVariant.NATIVE_LIBOQS
            assert info.name == "liboqs"
            assert info.version == "0.9.0"
            assert info.fips_compliant is True
            assert info.constant_time is True

    def test_detect_native_liboqs_no_version(self):
        from aethelred.crypto.fallback import _detect_backend, BackendVariant
        mock_oqs = MagicMock(spec=[])  # no __version__
        with patch("importlib.import_module", return_value=mock_oqs):
            info = _detect_backend()
            assert info.variant == BackendVariant.NATIVE_LIBOQS
            assert info.version == "unknown"

    def test_detect_pure_python_fallback(self):
        from aethelred.crypto.fallback import _detect_backend, BackendVariant
        with patch("importlib.import_module", side_effect=ImportError("no oqs")):
            import warnings
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                info = _detect_backend()
                assert info.variant == BackendVariant.PURE_PYTHON
                assert info.name == "aethelred-pure-python"
                assert info.fips_compliant is False
                assert info.constant_time is False
                # Should have issued a warning
                assert len(w) >= 1
                assert "liboqs-python" in str(w[0].message)


class TestGetBackend:
    def test_get_backend_cached(self):
        import aethelred.crypto.fallback as mod
        # Reset cache
        original = mod._backend_info
        try:
            mod._backend_info = None
            with patch.object(mod, "_detect_backend") as mock_detect:
                mock_info = MagicMock()
                mock_detect.return_value = mock_info
                result1 = mod.get_backend()
                result2 = mod.get_backend()
                assert result1 is mock_info
                assert result2 is mock_info
                mock_detect.assert_called_once()  # Only called once (cached)
        finally:
            mod._backend_info = original

    def test_get_backend_returns_backend_info(self):
        import aethelred.crypto.fallback as mod
        original = mod._backend_info
        try:
            mod._backend_info = None
            with patch("importlib.import_module", side_effect=ImportError("no oqs")):
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    info = mod.get_backend()
                    assert info is not None
                    assert hasattr(info, "variant")
        finally:
            mod._backend_info = original


class TestIsNative:
    def test_is_native_true(self):
        from aethelred.crypto.fallback import is_native, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod
        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="liboqs",
                variant=BackendVariant.NATIVE_LIBOQS,
                version="0.9.0",
                fips_compliant=True,
                constant_time=True,
            )
            assert is_native() is True
        finally:
            mod._backend_info = original

    def test_is_native_false(self):
        from aethelred.crypto.fallback import is_native, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod
        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="pure-python",
                variant=BackendVariant.PURE_PYTHON,
                version="0.1.0",
                fips_compliant=False,
                constant_time=False,
            )
            assert is_native() is False
        finally:
            mod._backend_info = original


# ---------------------------------------------------------------------------
# Protocol checks
# ---------------------------------------------------------------------------

class TestProtocols:
    def test_signer_protocol(self):
        from aethelred.crypto.fallback import SignerProtocol

        class GoodSigner:
            def sign(self, message: bytes) -> bytes:
                return b""
            def verify(self, message: bytes, signature: bytes) -> bool:
                return True
            def public_key_bytes(self) -> bytes:
                return b""

        assert isinstance(GoodSigner(), SignerProtocol)

    def test_kem_protocol(self):
        from aethelred.crypto.fallback import KEMProtocol

        class GoodKEM:
            def encapsulate(self, public_key: bytes):
                return (b"", b"")
            def decapsulate(self, ciphertext: bytes) -> bytes:
                return b""
            def public_key_bytes(self) -> bytes:
                return b""

        assert isinstance(GoodKEM(), KEMProtocol)


# ---------------------------------------------------------------------------
# _PurePythonHybridSigner
# ---------------------------------------------------------------------------

class TestPurePythonHybridSigner:
    def _make_signer(self, **kwargs):
        """Create a _PurePythonHybridSigner with mocked Dilithium only."""
        from aethelred.crypto.fallback import _PurePythonHybridSigner

        mock_dilithium_signer = MagicMock()
        mock_dilithium_signer.sign.return_value = MagicMock(to_bytes=MagicMock(return_value=b"\x01" * 32))
        mock_dilithium_signer.verify.return_value = True
        mock_dilithium_signer.public_key_bytes.return_value = b"\x02" * 64

        mock_dil_module = MagicMock()
        mock_dil_module.DilithiumSigner.return_value = mock_dilithium_signer
        mock_dil_module.DilithiumSecurityLevel.LEVEL3 = "LEVEL3"

        with patch.dict("sys.modules", {
            "aethelred.crypto.pqc.dilithium": mock_dil_module,
            "aethelred.crypto.pqc": MagicMock(),
        }):
            signer = _PurePythonHybridSigner(**kwargs)
            return signer, mock_dilithium_signer

    def test_init_generates_keys(self):
        signer, mock_dil = self._make_signer()
        assert signer._ecdsa_sk is not None
        assert signer._ecdsa_vk is not None
        assert signer._dilithium is mock_dil

    def test_init_with_existing_ecdsa_key(self):
        private_key_bytes = b"\x01" * 32
        signer, mock_dil = self._make_signer(ecdsa_private_key=private_key_bytes)
        expected_public_key = _ec_public_key_bytes(
            derive_private_key(int.from_bytes(private_key_bytes, "big"), SECP256K1()).public_key()
        )
        assert signer.public_key_bytes()[:64] == expected_public_key

    def test_sign(self):
        signer, mock_dil = self._make_signer()
        sig = signer.sign(b"hello")
        assert isinstance(sig, bytes)
        # Wire format: 4 bytes header + ECDSA sig + Dilithium sig
        header = sig[:4]
        ecdsa_len = int.from_bytes(header, "big")
        assert ecdsa_len == 64

    def test_verify_valid(self):
        signer, mock_dil = self._make_signer()
        combined = signer.sign(b"hello")
        result = signer.verify(b"hello", combined)
        assert result is True

    def test_verify_invalid_ecdsa_len(self):
        signer, mock_dil = self._make_signer()
        # Header says 9999 bytes but signature is short
        header = (9999).to_bytes(4, "big")
        combined = header + b"\x00" * 10
        result = signer.verify(b"hello", combined)
        assert result is False

    def test_verify_ecdsa_raises(self):
        signer, mock_dil = self._make_signer()
        combined = signer.sign(b"hello")
        signer._ecdsa_vk = MagicMock()
        signer._ecdsa_vk.verify.side_effect = InvalidSignature("bad sig")
        result = signer.verify(b"hello", combined)
        assert result is False

    def test_verify_value_error(self):
        signer, mock_dil = self._make_signer()
        combined = signer.sign(b"hello")
        signer._ecdsa_vk = MagicMock()
        signer._ecdsa_vk.verify.side_effect = ValueError("bad format")
        result = signer.verify(b"hello", combined)
        assert result is False

    def test_public_key_bytes(self):
        signer, mock_dil = self._make_signer()
        pk = signer.public_key_bytes()
        assert isinstance(pk, bytes)
        # Should be ECDSA pk + Dilithium pk
        assert len(pk) == 64 + 64  # mock sizes

    def test_header_size(self):
        from aethelred.crypto.fallback import _PurePythonHybridSigner
        assert _PurePythonHybridSigner.HEADER_SIZE == 4

    def test_cryptography_import_error(self):
        """Test that ImportError is raised when cryptography EC support is unavailable."""
        from aethelred.crypto.fallback import _PurePythonHybridSigner

        mock_dil_module = MagicMock()
        mock_dil_module.DilithiumSigner.return_value = MagicMock()
        mock_dil_module.DilithiumSecurityLevel.LEVEL3 = "LEVEL3"

        with patch.dict("sys.modules", {
            "cryptography.hazmat.primitives.asymmetric.ec": None,
            "aethelred.crypto.pqc.dilithium": mock_dil_module,
            "aethelred.crypto.pqc": MagicMock(),
        }):
            with pytest.raises(ImportError, match="cryptography"):
                _PurePythonHybridSigner()


# ---------------------------------------------------------------------------
# _PurePythonHybridVerifier
# ---------------------------------------------------------------------------

class TestPurePythonHybridVerifier:
    def _make_verifier(self, public_key=None):
        """Create a _PurePythonHybridVerifier with mocked Dilithium only."""
        from aethelred.crypto.fallback import _PurePythonHybridVerifier

        dil_pk_size = 1952  # Dilithium3 public key size
        ecdsa_sk = _fixed_ec_private_key()
        ecdsa_pk = _ec_public_key_bytes(ecdsa_sk.public_key())

        if public_key is None:
            public_key = ecdsa_pk + b"\x02" * dil_pk_size

        mock_dil_module = MagicMock()
        mock_dil_module.DilithiumSecurityLevel.LEVEL3 = "LEVEL3"
        mock_dil_module.DILITHIUM_SIZES = {"LEVEL3": {"public_key": dil_pk_size}}
        mock_dil_module.DilithiumSigner.verify_with_public_key.return_value = True

        with patch.dict("sys.modules", {
            "aethelred.crypto.pqc.dilithium": mock_dil_module,
            "aethelred.crypto.pqc": MagicMock(),
        }):
            verifier = _PurePythonHybridVerifier(public_key)
            return verifier, ecdsa_sk, mock_dil_module

    def test_init(self):
        verifier, ecdsa_sk, mock_dil = self._make_verifier()
        assert verifier._ecdsa_pk_bytes == _ec_public_key_bytes(ecdsa_sk.public_key())

    def test_init_short_key(self):
        """Public key shorter than or equal to Dilithium pk size should raise ValueError."""
        from aethelred.crypto.fallback import _PurePythonHybridVerifier

        dil_pk_size = 1952
        mock_dil_module = MagicMock()
        mock_dil_module.DilithiumSecurityLevel.LEVEL3 = "LEVEL3"
        mock_dil_module.DILITHIUM_SIZES = {"LEVEL3": {"public_key": dil_pk_size}}

        with patch.dict("sys.modules", {
            "aethelred.crypto.pqc.dilithium": mock_dil_module,
            "aethelred.crypto.pqc": MagicMock(),
        }):
            with pytest.raises(ValueError, match="too short"):
                _PurePythonHybridVerifier(b"\x00" * dil_pk_size)

    def test_init_cryptography_import_error(self):
        """Test ImportError when cryptography EC support is unavailable."""
        from aethelred.crypto.fallback import _PurePythonHybridVerifier

        dil_pk_size = 1952
        mock_dil_module = MagicMock()
        mock_dil_module.DilithiumSecurityLevel.LEVEL3 = "LEVEL3"
        mock_dil_module.DILITHIUM_SIZES = {"LEVEL3": {"public_key": dil_pk_size}}

        pk = _ec_public_key_bytes(_fixed_ec_private_key().public_key()) + b"\x02" * dil_pk_size

        with patch.dict("sys.modules", {
            "cryptography.hazmat.primitives.asymmetric.ec": None,
            "aethelred.crypto.pqc.dilithium": mock_dil_module,
            "aethelred.crypto.pqc": MagicMock(),
        }):
            with pytest.raises(ImportError, match="cryptography"):
                _PurePythonHybridVerifier(pk)

    def test_verify_valid(self):
        verifier, ecdsa_sk, mock_dil = self._make_verifier()
        ecdsa_sig = _raw_ecdsa_signature(ecdsa_sk, b"hello")
        dil_sig = b"\x01" * 32
        header = len(ecdsa_sig).to_bytes(4, "big")
        combined = header + ecdsa_sig + dil_sig
        # Keep mocked dilithium module active during verify() call,
        # since verify() does a runtime import of DilithiumSigner
        with patch.dict("sys.modules", {
            "aethelred.crypto.pqc.dilithium": mock_dil,
        }):
            result = verifier.verify(b"hello", combined)
        assert result is True

    def test_verify_invalid_ecdsa_len(self):
        verifier, ecdsa_sk, mock_dil = self._make_verifier()
        header = (9999).to_bytes(4, "big")
        combined = header + b"\x00" * 10
        result = verifier.verify(b"hello", combined)
        assert result is False

    def test_verify_ecdsa_exception(self):
        verifier, ecdsa_sk, mock_dil = self._make_verifier()
        verifier._ecdsa_vk = MagicMock()
        verifier._ecdsa_vk.verify.side_effect = InvalidSignature("bad signature")
        ecdsa_sig = _raw_ecdsa_signature(ecdsa_sk, b"hello")
        dil_sig = b"\x01" * 32
        header = len(ecdsa_sig).to_bytes(4, "big")
        combined = header + ecdsa_sig + dil_sig
        result = verifier.verify(b"hello", combined)
        assert result is False

    def test_verify_value_error(self):
        verifier, ecdsa_sk, mock_dil = self._make_verifier()
        verifier._ecdsa_vk = MagicMock()
        verifier._ecdsa_vk.verify.side_effect = ValueError("bad format")
        ecdsa_sig = _raw_ecdsa_signature(ecdsa_sk, b"hello")
        dil_sig = b"\x01" * 32
        header = len(ecdsa_sig).to_bytes(4, "big")
        combined = header + ecdsa_sig + dil_sig
        result = verifier.verify(b"hello", combined)
        assert result is False

    def test_header_size(self):
        from aethelred.crypto.fallback import _PurePythonHybridVerifier
        assert _PurePythonHybridVerifier.HEADER_SIZE == 4


# ---------------------------------------------------------------------------
# HybridSigner (unified)
# ---------------------------------------------------------------------------

class TestHybridSigner:
    def test_init_pure_python_backend(self):
        from aethelred.crypto.fallback import HybridSigner, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="pure-python",
                variant=BackendVariant.PURE_PYTHON,
                version="0.1.0",
                fips_compliant=False,
                constant_time=False,
            )
            mock_impl = MagicMock()
            with patch("aethelred.crypto.fallback._PurePythonHybridSigner", return_value=mock_impl):
                signer = HybridSigner()
                assert signer._impl is mock_impl
        finally:
            mod._backend_info = original

    def test_init_native_backend(self):
        from aethelred.crypto.fallback import HybridSigner, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="liboqs",
                variant=BackendVariant.NATIVE_LIBOQS,
                version="0.9.0",
                fips_compliant=True,
                constant_time=True,
            )
            mock_impl = MagicMock()
            with patch("aethelred.crypto.fallback._NativeHybridSigner", return_value=mock_impl):
                signer = HybridSigner()
                assert signer._impl is mock_impl
        finally:
            mod._backend_info = original

    def test_sign_delegates(self):
        from aethelred.crypto.fallback import HybridSigner, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="pure-python",
                variant=BackendVariant.PURE_PYTHON,
                version="0.1.0",
                fips_compliant=False,
                constant_time=False,
            )
            mock_impl = MagicMock()
            mock_impl.sign.return_value = b"signature"
            with patch("aethelred.crypto.fallback._PurePythonHybridSigner", return_value=mock_impl):
                signer = HybridSigner()
                result = signer.sign(b"message")
                assert result == b"signature"
                mock_impl.sign.assert_called_once_with(b"message")
        finally:
            mod._backend_info = original

    def test_verify_delegates(self):
        from aethelred.crypto.fallback import HybridSigner, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="pure-python",
                variant=BackendVariant.PURE_PYTHON,
                version="0.1.0",
                fips_compliant=False,
                constant_time=False,
            )
            mock_impl = MagicMock()
            mock_impl.verify.return_value = True
            with patch("aethelred.crypto.fallback._PurePythonHybridSigner", return_value=mock_impl):
                signer = HybridSigner()
                result = signer.verify(b"msg", b"sig")
                assert result is True
                mock_impl.verify.assert_called_once_with(b"msg", b"sig")
        finally:
            mod._backend_info = original

    def test_public_key_bytes_delegates(self):
        from aethelred.crypto.fallback import HybridSigner, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="pure-python",
                variant=BackendVariant.PURE_PYTHON,
                version="0.1.0",
                fips_compliant=False,
                constant_time=False,
            )
            mock_impl = MagicMock()
            mock_impl.public_key_bytes.return_value = b"\x01" * 128
            with patch("aethelred.crypto.fallback._PurePythonHybridSigner", return_value=mock_impl):
                signer = HybridSigner()
                pk = signer.public_key_bytes()
                assert pk == b"\x01" * 128
        finally:
            mod._backend_info = original

    def test_fingerprint(self):
        from aethelred.crypto.fallback import HybridSigner, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="pure-python",
                variant=BackendVariant.PURE_PYTHON,
                version="0.1.0",
                fips_compliant=False,
                constant_time=False,
            )
            pk_bytes = b"\x01" * 128
            expected_fp = hashlib.sha256(pk_bytes).hexdigest()[:16]

            mock_impl = MagicMock()
            mock_impl.public_key_bytes.return_value = pk_bytes
            with patch("aethelred.crypto.fallback._PurePythonHybridSigner", return_value=mock_impl):
                signer = HybridSigner()
                assert signer.fingerprint == expected_fp
                assert len(signer.fingerprint) == 16
        finally:
            mod._backend_info = original

    def test_init_with_keys(self):
        from aethelred.crypto.fallback import HybridSigner, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="pure-python",
                variant=BackendVariant.PURE_PYTHON,
                version="0.1.0",
                fips_compliant=False,
                constant_time=False,
            )
            mock_impl = MagicMock()
            with patch("aethelred.crypto.fallback._PurePythonHybridSigner", return_value=mock_impl) as mock_cls:
                signer = HybridSigner(
                    ecdsa_private_key=b"\xaa" * 32,
                    dilithium_secret_key=b"\xbb" * 64,
                    dilithium_public_key=b"\xcc" * 64,
                )
                mock_cls.assert_called_once_with(
                    ecdsa_private_key=b"\xaa" * 32,
                    dilithium_secret_key=b"\xbb" * 64,
                    dilithium_public_key=b"\xcc" * 64,
                )
        finally:
            mod._backend_info = original


# ---------------------------------------------------------------------------
# HybridVerifier (unified)
# ---------------------------------------------------------------------------

class TestHybridVerifier:
    def test_init_pure_python_backend(self):
        from aethelred.crypto.fallback import HybridVerifier, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="pure-python",
                variant=BackendVariant.PURE_PYTHON,
                version="0.1.0",
                fips_compliant=False,
                constant_time=False,
            )
            mock_impl = MagicMock()
            with patch("aethelred.crypto.fallback._PurePythonHybridVerifier", return_value=mock_impl):
                verifier = HybridVerifier(b"\x01" * 128)
                assert verifier._impl is mock_impl
        finally:
            mod._backend_info = original

    def test_init_native_backend(self):
        from aethelred.crypto.fallback import HybridVerifier, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="liboqs",
                variant=BackendVariant.NATIVE_LIBOQS,
                version="0.9.0",
                fips_compliant=True,
                constant_time=True,
            )
            mock_impl = MagicMock()
            with patch("aethelred.crypto.fallback._NativeHybridVerifier", return_value=mock_impl):
                verifier = HybridVerifier(b"\x01" * 128)
                assert verifier._impl is mock_impl
        finally:
            mod._backend_info = original

    def test_verify_delegates(self):
        from aethelred.crypto.fallback import HybridVerifier, BackendInfo, BackendVariant
        import aethelred.crypto.fallback as mod

        original = mod._backend_info
        try:
            mod._backend_info = BackendInfo(
                name="pure-python",
                variant=BackendVariant.PURE_PYTHON,
                version="0.1.0",
                fips_compliant=False,
                constant_time=False,
            )
            mock_impl = MagicMock()
            mock_impl.verify.return_value = True
            with patch("aethelred.crypto.fallback._PurePythonHybridVerifier", return_value=mock_impl):
                verifier = HybridVerifier(b"\x01" * 128)
                result = verifier.verify(b"msg", b"sig")
                assert result is True
                mock_impl.verify.assert_called_once_with(b"msg", b"sig")
        finally:
            mod._backend_info = original


# ---------------------------------------------------------------------------
# _NativeHybridSigner
# ---------------------------------------------------------------------------

class TestNativeHybridSigner:
    def _make_native_signer(self, **kwargs):
        """Create a _NativeHybridSigner with mocked OQS only."""
        from aethelred.crypto.fallback import _NativeHybridSigner

        mock_sig = MagicMock()
        mock_sig.sign.return_value = b"\xdd" * 48
        mock_sig.verify.return_value = True
        mock_sig.generate_keypair.return_value = b"\xee" * 1952

        mock_oqs = MagicMock()
        mock_oqs.Signature.return_value = mock_sig

        with patch.dict("sys.modules", {
            "oqs": mock_oqs,
        }):
            signer = _NativeHybridSigner(**kwargs)
            return signer, mock_sig

    def test_init_generates_keys(self):
        signer, mock_sig = self._make_native_signer()
        assert signer._sig is mock_sig
        mock_sig.generate_keypair.assert_called_once()
        assert signer._public_key == b"\xee" * 1952

    def test_init_with_existing_keys(self):
        signer, mock_sig = self._make_native_signer(
            ecdsa_private_key=b"\x01" * 32,
            dilithium_secret_key=b"\x02" * 64,
            dilithium_public_key=b"\x03" * 1952,
        )
        assert signer._public_key == b"\x03" * 1952
        mock_sig.generate_keypair.assert_not_called()

    def test_sign(self):
        signer, mock_sig = self._make_native_signer()
        result = signer.sign(b"hello")
        assert isinstance(result, bytes)
        # Wire format: 4-byte header + ECDSA sig + Dilithium sig
        header = result[:4]
        ecdsa_len = int.from_bytes(header, "big")
        assert ecdsa_len == 64
        assert signer.verify(b"hello", result) is True
        assert result[4+64:] == b"\xdd" * 48

    def test_verify_valid(self):
        signer, mock_sig = self._make_native_signer()
        combined = signer.sign(b"hello")
        result = signer.verify(b"hello", combined)
        assert result is True

    def test_verify_exception(self):
        signer, mock_sig = self._make_native_signer()
        combined = signer.sign(b"hello")
        signer._ecdsa_vk = MagicMock()
        signer._ecdsa_vk.verify.side_effect = InvalidSignature("bad sig")
        result = signer.verify(b"hello", combined)
        assert result is False

    def test_public_key_bytes(self):
        signer, mock_sig = self._make_native_signer()
        pk = signer.public_key_bytes()
        assert len(pk) == 64 + 1952
        assert pk[:64] == _ec_public_key_bytes(signer._ecdsa_vk)
        assert pk[64:] == b"\xee" * 1952

    def test_header_size(self):
        from aethelred.crypto.fallback import _NativeHybridSigner
        assert _NativeHybridSigner.HEADER_SIZE == 4


# ---------------------------------------------------------------------------
# _NativeHybridVerifier
# ---------------------------------------------------------------------------

class TestNativeHybridVerifier:
    def _make_native_verifier(self, public_key=None):
        """Create a _NativeHybridVerifier with mocked OQS only."""
        from aethelred.crypto.fallback import _NativeHybridVerifier

        mock_sig = MagicMock()
        mock_sig.length_public_key = 1952
        mock_sig.verify.return_value = True

        mock_oqs = MagicMock()
        mock_oqs.Signature.return_value = mock_sig

        ecdsa_sk = _fixed_ec_private_key()

        if public_key is None:
            public_key = _ec_public_key_bytes(ecdsa_sk.public_key()) + b"\x02" * 1952

        with patch.dict("sys.modules", {
            "oqs": mock_oqs,
        }):
            verifier = _NativeHybridVerifier(public_key)
            return verifier, mock_sig, ecdsa_sk

    def test_init(self):
        verifier, mock_sig, ecdsa_sk = self._make_native_verifier()
        assert verifier._sig is mock_sig
        assert verifier._dil_pk == b"\x02" * 1952

    def test_verify_valid(self):
        verifier, mock_sig, ecdsa_sk = self._make_native_verifier()
        ecdsa_sig = _raw_ecdsa_signature(ecdsa_sk, b"hello")
        dil_sig = b"\xdd" * 48
        header = len(ecdsa_sig).to_bytes(4, "big")
        combined = header + ecdsa_sig + dil_sig
        result = verifier.verify(b"hello", combined)
        assert result is True

    def test_verify_exception(self):
        verifier, mock_sig, ecdsa_sk = self._make_native_verifier()
        verifier._ecdsa_vk = MagicMock()
        verifier._ecdsa_vk.verify.side_effect = InvalidSignature("bad signature")
        ecdsa_sig = _raw_ecdsa_signature(ecdsa_sk, b"hello")
        dil_sig = b"\xdd" * 48
        header = len(ecdsa_sig).to_bytes(4, "big")
        combined = header + ecdsa_sig + dil_sig
        result = verifier.verify(b"hello", combined)
        assert result is False

    def test_header_size(self):
        from aethelred.crypto.fallback import _NativeHybridVerifier
        assert _NativeHybridVerifier.HEADER_SIZE == 4


# ---------------------------------------------------------------------------
# __all__ exports
# ---------------------------------------------------------------------------

class TestModuleExports:
    def test_all_defined(self):
        from aethelred.crypto import fallback
        assert hasattr(fallback, "__all__")
        assert "BackendInfo" in fallback.__all__
        assert "BackendVariant" in fallback.__all__
        assert "HybridSigner" in fallback.__all__
        assert "HybridVerifier" in fallback.__all__
        assert "get_backend" in fallback.__all__
        assert "is_native" in fallback.__all__
