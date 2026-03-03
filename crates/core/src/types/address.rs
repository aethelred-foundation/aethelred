//! Aethelred Address Types
//!
//! Bech32-encoded addresses derived from hybrid public keys.

use crate::crypto::hash::sha256;
use crate::crypto::hybrid::HybridPublicKey;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// Address errors
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    #[error("Invalid address length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Invalid address prefix: expected {expected}, got {actual}")]
    InvalidPrefix { expected: String, actual: String },

    #[error("Invalid checksum")]
    InvalidChecksum,

    #[error("Invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("Invalid address type byte: {0}")]
    InvalidType(u8),
}

/// Address type identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddressType {
    /// Standard user address (from hybrid keypair)
    User = 0x00,
    /// Smart contract address
    Contract = 0x01,
    /// Validator address
    Validator = 0x02,
    /// System address (governance, rewards, etc.)
    System = 0x03,
    /// Oracle address
    Oracle = 0x04,
}

impl AddressType {
    /// Parse from byte
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(Self::User),
            0x01 => Some(Self::Contract),
            0x02 => Some(Self::Validator),
            0x03 => Some(Self::System),
            0x04 => Some(Self::Oracle),
            _ => None,
        }
    }

    /// Convert to byte
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    /// Get bech32 prefix
    pub fn prefix(&self) -> &'static str {
        match self {
            Self::User => "aethel",
            Self::Contract => "aethelc",
            Self::Validator => "aethelv",
            Self::System => "aethels",
            Self::Oracle => "aethelo",
        }
    }
}

impl Default for AddressType {
    fn default() -> Self {
        Self::User
    }
}

/// 20-byte address (derived from public key hash)
const ADDRESS_SIZE: usize = 20;

/// Aethelred address
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    /// Address type
    address_type: AddressType,
    /// 20-byte address hash
    bytes: [u8; ADDRESS_SIZE],
}

impl Address {
    /// Zero address
    pub const ZERO: Self = Self {
        address_type: AddressType::User,
        bytes: [0u8; ADDRESS_SIZE],
    };

    /// System treasury address
    pub const TREASURY: Self = Self {
        address_type: AddressType::System,
        bytes: [0x01; ADDRESS_SIZE],
    };

    /// Reward pool address
    pub const REWARDS: Self = Self {
        address_type: AddressType::System,
        bytes: [0x02; ADDRESS_SIZE],
    };

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; ADDRESS_SIZE], address_type: AddressType) -> Self {
        Self {
            address_type,
            bytes,
        }
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8], address_type: AddressType) -> Result<Self, AddressError> {
        if slice.len() != ADDRESS_SIZE {
            return Err(AddressError::InvalidLength {
                expected: ADDRESS_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self {
            address_type,
            bytes,
        })
    }

    /// Create from hybrid public key
    pub fn from_public_key(public_key: &HybridPublicKey) -> Self {
        let hash = sha256(&public_key.to_bytes());
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(&hash.as_bytes()[..ADDRESS_SIZE]);
        Self {
            address_type: AddressType::User,
            bytes,
        }
    }

    /// Create contract address from deployer and nonce
    pub fn create_contract(deployer: &Address, nonce: u64) -> Self {
        let mut data = Vec::with_capacity(ADDRESS_SIZE + 8);
        data.extend_from_slice(&deployer.bytes);
        data.extend_from_slice(&nonce.to_le_bytes());
        let hash = sha256(&data);
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(&hash.as_bytes()[..ADDRESS_SIZE]);
        Self {
            address_type: AddressType::Contract,
            bytes,
        }
    }

    /// Create validator address from validator public key
    pub fn from_validator_key(validator_pk: &HybridPublicKey) -> Self {
        let hash = sha256(&validator_pk.to_bytes());
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(&hash.as_bytes()[..ADDRESS_SIZE]);
        Self {
            address_type: AddressType::Validator,
            bytes,
        }
    }

    /// Get address type
    pub fn address_type(&self) -> AddressType {
        self.address_type
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8; ADDRESS_SIZE] {
        &self.bytes
    }

    /// Check if zero address
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Check if system address
    pub fn is_system(&self) -> bool {
        self.address_type == AddressType::System
    }

    /// Convert to bech32 string
    pub fn to_bech32(&self) -> String {
        // Simple hex encoding with prefix for MVP
        // In production, use proper bech32 encoding
        let prefix = self.address_type.prefix();
        format!("{}1{}", prefix, hex::encode(self.bytes))
    }

    /// Parse from bech32 string
    pub fn from_bech32(s: &str) -> Result<Self, AddressError> {
        // Find prefix
        let sep_idx = s
            .find('1')
            .ok_or_else(|| AddressError::InvalidEncoding("Missing separator".into()))?;

        let prefix = &s[..sep_idx];
        let data = &s[sep_idx + 1..];

        // Determine address type from prefix
        let address_type = match prefix {
            "aethel" => AddressType::User,
            "aethelc" => AddressType::Contract,
            "aethelv" => AddressType::Validator,
            "aethels" => AddressType::System,
            "aethelo" => AddressType::Oracle,
            _ => {
                return Err(AddressError::InvalidPrefix {
                    expected: "aethel/aethelc/aethelv/aethels/aethelo".into(),
                    actual: prefix.into(),
                })
            }
        };

        // Decode hex data
        let bytes = hex::decode(data).map_err(|e| AddressError::InvalidEncoding(e.to_string()))?;

        Self::from_slice(&bytes, address_type)
    }

    /// Get checksum (last 4 bytes of hash)
    pub fn checksum(&self) -> [u8; 4] {
        let hash = sha256(&self.bytes);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(&hash.as_bytes()[..4]);
        checksum
    }
}

impl Default for Address {
    fn default() -> Self {
        Self::ZERO
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_bech32())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_bech32())
    }
}

impl FromStr for Address {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_bech32(s)
    }
}

/// Serialize address for storage
impl Address {
    /// Serialize to bytes (type + address)
    pub fn serialize(&self) -> [u8; ADDRESS_SIZE + 1] {
        let mut result = [0u8; ADDRESS_SIZE + 1];
        result[0] = self.address_type.to_byte();
        result[1..].copy_from_slice(&self.bytes);
        result
    }

    /// Deserialize from bytes
    pub fn deserialize(bytes: &[u8]) -> Result<Self, AddressError> {
        if bytes.len() != ADDRESS_SIZE + 1 {
            return Err(AddressError::InvalidLength {
                expected: ADDRESS_SIZE + 1,
                actual: bytes.len(),
            });
        }

        let address_type =
            AddressType::from_byte(bytes[0]).ok_or(AddressError::InvalidType(bytes[0]))?;

        let mut addr_bytes = [0u8; ADDRESS_SIZE];
        addr_bytes.copy_from_slice(&bytes[1..]);

        Ok(Self {
            address_type,
            bytes: addr_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_creation() {
        let bytes = [1u8; ADDRESS_SIZE];
        let addr = Address::from_bytes(bytes, AddressType::User);
        assert_eq!(addr.address_type(), AddressType::User);
        assert_eq!(addr.as_bytes(), &bytes);
    }

    #[test]
    fn test_bech32_roundtrip() {
        let bytes = [0x42u8; ADDRESS_SIZE];
        let addr = Address::from_bytes(bytes, AddressType::User);
        let bech32 = addr.to_bech32();
        assert!(bech32.starts_with("aethel1"));

        let recovered = Address::from_bech32(&bech32).unwrap();
        assert_eq!(addr, recovered);
    }

    #[test]
    fn test_contract_address() {
        let deployer = Address::from_bytes([1u8; ADDRESS_SIZE], AddressType::User);
        let contract = Address::create_contract(&deployer, 0);
        assert_eq!(contract.address_type(), AddressType::Contract);

        // Same deployer + nonce should produce same address
        let contract2 = Address::create_contract(&deployer, 0);
        assert_eq!(contract, contract2);

        // Different nonce should produce different address
        let contract3 = Address::create_contract(&deployer, 1);
        assert_ne!(contract, contract3);
    }

    #[test]
    fn test_address_types() {
        assert_eq!(AddressType::User.prefix(), "aethel");
        assert_eq!(AddressType::Contract.prefix(), "aethelc");
        assert_eq!(AddressType::Validator.prefix(), "aethelv");
    }

    #[test]
    fn test_serialize_deserialize() {
        let addr = Address::from_bytes([0xAB; ADDRESS_SIZE], AddressType::Validator);
        let serialized = addr.serialize();
        let deserialized = Address::deserialize(&serialized).unwrap();
        assert_eq!(addr, deserialized);
    }

    #[test]
    fn test_zero_address() {
        assert!(Address::ZERO.is_zero());
        assert!(!Address::TREASURY.is_zero());
    }
}
