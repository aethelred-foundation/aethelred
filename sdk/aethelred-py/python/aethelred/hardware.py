"""
Aethelred Hardware Definitions

Provides enums and constants for hardware types, compliance requirements,
and security levels. These make the API readable and prevent typos in
configuration.

Example:
    >>> from aethelred.hardware import Hardware, Compliance
    >>>
    >>> @sovereign(
    ...     hardware=Hardware.TEE_REQUIRED,
    ...     compliance=Compliance.UAE_DATA_RESIDENCY | Compliance.GDPR,
    ... )
    >>> def process_sensitive_data(data):
    ...     pass
"""

from __future__ import annotations

from enum import Enum, Flag, IntEnum, auto
from typing import List, Set


class Hardware(Enum):
    """
    Hardware requirement levels for sovereign execution.

    These specify what type of hardware environment is required
    for a sovereign function to execute.
    """

    # No specific hardware requirements
    GENERIC = "Generic"

    # TEE is required - function will not run without it
    TEE_REQUIRED = "TeeRequired"

    # TEE is preferred but not required
    TEE_PREFERRED = "TeePreferred"

    # Specific hardware platforms
    INTEL_SGX = "IntelSgxDcap"
    INTEL_SGX_EPID = "IntelSgxEpid"
    INTEL_TDX = "IntelTdx"
    AMD_SEV = "AmdSev"
    AMD_SEV_SNP = "AmdSevSnp"
    ARM_TRUSTZONE = "ArmTrustZone"
    ARM_CCA = "ArmCca"
    AWS_NITRO = "AwsNitro"
    AZURE_CONFIDENTIAL = "AzureConfidential"
    GCP_CONFIDENTIAL = "GcpConfidential"
    NVIDIA_H100 = "NvidiaH100Cc"
    NVIDIA_A100 = "NvidiaA100"

    def __str__(self) -> str:
        return self.value

    @property
    def is_tee(self) -> bool:
        """Check if this hardware type is a TEE."""
        return self in {
            Hardware.TEE_REQUIRED,
            Hardware.TEE_PREFERRED,
            Hardware.INTEL_SGX,
            Hardware.INTEL_SGX_EPID,
            Hardware.INTEL_TDX,
            Hardware.AMD_SEV,
            Hardware.AMD_SEV_SNP,
            Hardware.ARM_TRUSTZONE,
            Hardware.ARM_CCA,
            Hardware.AWS_NITRO,
            Hardware.AZURE_CONFIDENTIAL,
            Hardware.GCP_CONFIDENTIAL,
            Hardware.NVIDIA_H100,
        }

    @property
    def supports_attestation(self) -> bool:
        """Check if this hardware supports remote attestation."""
        return self in {
            Hardware.INTEL_SGX,
            Hardware.INTEL_SGX_EPID,
            Hardware.INTEL_TDX,
            Hardware.AMD_SEV_SNP,
            Hardware.ARM_CCA,
            Hardware.AWS_NITRO,
            Hardware.AZURE_CONFIDENTIAL,
            Hardware.GCP_CONFIDENTIAL,
            Hardware.NVIDIA_H100,
        }

    @property
    def security_level(self) -> int:
        """Get the security level (0-10) for this hardware."""
        levels = {
            Hardware.GENERIC: 0,
            Hardware.NVIDIA_A100: 2,
            Hardware.TEE_PREFERRED: 3,
            Hardware.ARM_TRUSTZONE: 5,
            Hardware.INTEL_SGX_EPID: 5,
            Hardware.AMD_SEV: 6,
            Hardware.TEE_REQUIRED: 7,
            Hardware.AWS_NITRO: 8,
            Hardware.AZURE_CONFIDENTIAL: 8,
            Hardware.GCP_CONFIDENTIAL: 8,
            Hardware.INTEL_SGX: 8,
            Hardware.AMD_SEV_SNP: 8,
            Hardware.INTEL_TDX: 9,
            Hardware.ARM_CCA: 9,
            Hardware.NVIDIA_H100: 9,
        }
        return levels.get(self, 0)


class Compliance(Flag):
    """
    Compliance flags for regulatory requirements.

    These can be combined using the | operator to specify
    multiple compliance requirements.

    Example:
        >>> compliance = Compliance.GDPR | Compliance.HIPAA
    """

    # No compliance requirements
    NONE = 0

    # General Data Protection Regulation (EU)
    GDPR = auto()

    # Health Insurance Portability and Accountability Act (US)
    HIPAA = auto()

    # California Consumer Privacy Act (US-CA)
    CCPA = auto()

    # UAE Data Protection Law
    UAE_DATA_PROTECTION = auto()
    UAE_DATA_RESIDENCY = auto()

    # China Personal Information Protection Law
    PIPL = auto()
    CHINA_DATA_LOCALIZATION = auto()

    # Singapore Personal Data Protection Act
    PDPA_SG = auto()

    # UK GDPR
    UK_GDPR = auto()

    # Saudi Arabia PDPL
    PDPL_SA = auto()

    # Japan APPI
    APPI = auto()

    # South Korea PIPA
    PIPA = auto()

    # Brazil LGPD
    LGPD = auto()

    # India DPDP
    DPDP = auto()

    # Canada PIPEDA
    PIPEDA = auto()

    # Australia Privacy Act
    PRIVACY_ACT_AU = auto()

    # Financial regulations
    PCI_DSS = auto()
    SOX = auto()
    GLBA = auto()

    # Healthcare specific
    HITECH = auto()

    # AI specific regulations
    EU_AI_ACT = auto()

    # ESG/Sustainability
    EU_CSRD = auto()
    SEC_ESG = auto()

    # Combined presets
    @classmethod
    def healthcare_us(cls) -> Compliance:
        """US Healthcare compliance (HIPAA + HITECH)."""
        return cls.HIPAA | cls.HITECH

    @classmethod
    def financial_us(cls) -> Compliance:
        """US Financial compliance."""
        return cls.SOX | cls.GLBA | cls.PCI_DSS

    @classmethod
    def uae_strict(cls) -> Compliance:
        """Strict UAE compliance with data residency."""
        return cls.UAE_DATA_PROTECTION | cls.UAE_DATA_RESIDENCY

    @classmethod
    def china_strict(cls) -> Compliance:
        """Strict China compliance with data localization."""
        return cls.PIPL | cls.CHINA_DATA_LOCALIZATION

    @classmethod
    def eu_comprehensive(cls) -> Compliance:
        """Comprehensive EU compliance."""
        return cls.GDPR | cls.EU_AI_ACT | cls.EU_CSRD

    def __str__(self) -> str:
        if self == Compliance.NONE:
            return "None"
        flags = [f.name for f in Compliance if f in self and f != Compliance.NONE]
        return " | ".join(flags)

    @property
    def requires_tee(self) -> bool:
        """Check if these compliance flags require TEE."""
        tee_required = {
            Compliance.UAE_DATA_RESIDENCY,
            Compliance.CHINA_DATA_LOCALIZATION,
            Compliance.PDPL_SA,
        }
        return bool(self & (Compliance.UAE_DATA_RESIDENCY | Compliance.CHINA_DATA_LOCALIZATION | Compliance.PDPL_SA))

    @property
    def requires_data_localization(self) -> bool:
        """Check if these flags require data localization."""
        return bool(self & (
            Compliance.UAE_DATA_RESIDENCY |
            Compliance.CHINA_DATA_LOCALIZATION
        ))

    def get_regulations(self) -> List[str]:
        """Get the list of regulation codes."""
        mapping = {
            Compliance.GDPR: "GDPR",
            Compliance.HIPAA: "HIPAA",
            Compliance.CCPA: "CCPA",
            Compliance.UAE_DATA_PROTECTION: "UAE-DPL",
            Compliance.UAE_DATA_RESIDENCY: "UAE-DPL",
            Compliance.PIPL: "PIPL",
            Compliance.CHINA_DATA_LOCALIZATION: "PIPL",
            Compliance.PDPA_SG: "PDPA",
            Compliance.UK_GDPR: "UK-GDPR",
            Compliance.PDPL_SA: "PDPL",
            Compliance.APPI: "APPI",
            Compliance.PIPA: "PIPA",
            Compliance.LGPD: "LGPD",
            Compliance.DPDP: "DPDP",
            Compliance.PIPEDA: "PIPEDA",
            Compliance.PRIVACY_ACT_AU: "Privacy-Act",
            Compliance.PCI_DSS: "PCI-DSS",
            Compliance.SOX: "SOX",
            Compliance.GLBA: "GLBA",
            Compliance.HITECH: "HITECH",
            Compliance.EU_AI_ACT: "EU-AI-Act",
            Compliance.EU_CSRD: "EU-CSRD",
            Compliance.SEC_ESG: "SEC-ESG",
        }
        return list(set(
            mapping[f] for f in Compliance
            if f in self and f in mapping
        ))


class SecurityLevel(IntEnum):
    """
    Security levels for hardware environments.

    These correspond to the security_level() method on HardwareType.
    """

    # No security guarantees
    NONE = 0

    # Basic OS-level isolation
    PROCESS = 1

    # Container-level isolation
    CONTAINER = 2

    # VM-level isolation
    VM = 3

    # Hardware security module
    HSM = 4

    # Legacy TEE (e.g., SGX EPID, basic TrustZone)
    TEE_LEGACY = 5

    # Memory encryption (e.g., AMD SEV without SNP)
    MEMORY_ENCRYPTED = 6

    # TEE with remote attestation
    TEE = 7

    # Full attestation with secure nested paging
    TEE_ATTESTED = 8

    # Latest generation confidential computing
    CONFIDENTIAL = 9

    # Maximum security (theoretical)
    MAXIMUM = 10

    @classmethod
    def minimum_for_regulation(cls, regulation: str) -> SecurityLevel:
        """Get minimum security level for a regulation."""
        requirements = {
            "HIPAA": cls.TEE,
            "UAE-DPL": cls.TEE_ATTESTED,
            "PIPL": cls.TEE_ATTESTED,
            "PDPL": cls.TEE,
            "PCI-DSS": cls.TEE,
            "GDPR": cls.CONTAINER,
        }
        return requirements.get(regulation, cls.NONE)


class DataClassification(Enum):
    """
    Data classification levels.

    These define how sensitive data is and what protections are required.
    """

    # Public data - no restrictions
    PUBLIC = "public"

    # Internal use only
    INTERNAL = "internal"

    # Confidential - requires authentication
    CONFIDENTIAL = "confidential"

    # Sensitive - requires encryption
    SENSITIVE = "sensitive"

    # Restricted - requires TEE
    RESTRICTED = "restricted"

    # Top Secret - requires highest security
    TOP_SECRET = "top_secret"

    @property
    def min_security_level(self) -> SecurityLevel:
        """Get minimum security level for this classification."""
        levels = {
            DataClassification.PUBLIC: SecurityLevel.NONE,
            DataClassification.INTERNAL: SecurityLevel.PROCESS,
            DataClassification.CONFIDENTIAL: SecurityLevel.CONTAINER,
            DataClassification.SENSITIVE: SecurityLevel.TEE_LEGACY,
            DataClassification.RESTRICTED: SecurityLevel.TEE,
            DataClassification.TOP_SECRET: SecurityLevel.CONFIDENTIAL,
        }
        return levels[self]

    @property
    def requires_encryption(self) -> bool:
        """Check if this classification requires encryption."""
        return self in {
            DataClassification.SENSITIVE,
            DataClassification.RESTRICTED,
            DataClassification.TOP_SECRET,
        }

    @property
    def requires_tee(self) -> bool:
        """Check if this classification requires TEE."""
        return self in {
            DataClassification.RESTRICTED,
            DataClassification.TOP_SECRET,
        }


class Region(Enum):
    """
    Geographic regions for data residency.

    These map to specific cloud regions and data centers.
    """

    # Middle East
    UAE_ABUDHABI = "ae-abudhabi-1"
    UAE_DUBAI = "ae-dubai-1"
    SAUDI_RIYADH = "sa-riyadh-1"
    QATAR_DOHA = "qa-doha-1"
    BAHRAIN_MANAMA = "bh-manama-1"

    # Europe
    EU_FRANKFURT = "eu-frankfurt-1"
    EU_AMSTERDAM = "eu-amsterdam-1"
    EU_LONDON = "eu-london-1"
    EU_PARIS = "eu-paris-1"
    EU_ZURICH = "eu-zurich-1"

    # Americas
    US_EAST = "us-east-1"
    US_WEST = "us-west-2"
    US_CENTRAL = "us-central-1"
    CANADA_CENTRAL = "ca-central-1"
    BRAZIL_SAO_PAULO = "br-sao-paulo-1"

    # Asia Pacific
    SINGAPORE = "ap-singapore-1"
    JAPAN_TOKYO = "ap-tokyo-1"
    AUSTRALIA_SYDNEY = "ap-sydney-1"
    KOREA_SEOUL = "ap-seoul-1"
    INDIA_MUMBAI = "ap-mumbai-1"
    CHINA_BEIJING = "cn-beijing-1"
    CHINA_SHANGHAI = "cn-shanghai-1"

    @property
    def jurisdiction(self) -> str:
        """Get the jurisdiction code for this region."""
        mapping = {
            Region.UAE_ABUDHABI: "UAE",
            Region.UAE_DUBAI: "UAE",
            Region.SAUDI_RIYADH: "SA",
            Region.QATAR_DOHA: "QA",
            Region.BAHRAIN_MANAMA: "BH",
            Region.EU_FRANKFURT: "EU",
            Region.EU_AMSTERDAM: "EU",
            Region.EU_LONDON: "UK",
            Region.EU_PARIS: "EU",
            Region.EU_ZURICH: "CH",
            Region.US_EAST: "US",
            Region.US_WEST: "US",
            Region.US_CENTRAL: "US",
            Region.CANADA_CENTRAL: "CA",
            Region.BRAZIL_SAO_PAULO: "BR",
            Region.SINGAPORE: "SG",
            Region.JAPAN_TOKYO: "JP",
            Region.AUSTRALIA_SYDNEY: "AU",
            Region.KOREA_SEOUL: "KR",
            Region.INDIA_MUMBAI: "IN",
            Region.CHINA_BEIJING: "CN",
            Region.CHINA_SHANGHAI: "CN",
        }
        return mapping.get(self, "GLOBAL")

    @property
    def is_eu_adequate(self) -> bool:
        """Check if this region has EU adequacy decision."""
        return self.jurisdiction in {"UK", "CH", "JP", "KR", "CA", "NZ", "IL"}

    @property
    def requires_localization(self) -> bool:
        """Check if this region requires data localization."""
        return self.jurisdiction in {"UAE", "SA", "CN"}


# Convenience aliases
TEE_REQUIRED = Hardware.TEE_REQUIRED
TEE_PREFERRED = Hardware.TEE_PREFERRED
INTEL_SGX = Hardware.INTEL_SGX
AMD_SEV = Hardware.AMD_SEV_SNP
AWS_NITRO = Hardware.AWS_NITRO
NVIDIA_H100 = Hardware.NVIDIA_H100

GDPR = Compliance.GDPR
HIPAA = Compliance.HIPAA
UAE = Compliance.uae_strict()
CHINA = Compliance.china_strict()
