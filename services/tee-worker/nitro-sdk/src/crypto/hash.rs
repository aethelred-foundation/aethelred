//! # Cryptographic Hashing
//!
//! Multi-algorithm hash functions for various use cases.

use super::*;

// ============================================================================
// Hash Functions
// ============================================================================

/// Hash a message with SHA-256
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a message with SHA-384
pub fn sha384(data: &[u8]) -> [u8; 48] {
    use sha2::{Digest, Sha384};
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a message with SHA-512
pub fn sha512(data: &[u8]) -> [u8; 64] {
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a message with SHA3-256
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash a message with BLAKE3
pub fn blake3(data: &[u8]) -> [u8; 32] {
    blake3::hash(data).into()
}

/// Hash with specified algorithm
pub fn hash(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => sha256(data).to_vec(),
        HashAlgorithm::Sha384 => sha384(data).to_vec(),
        HashAlgorithm::Sha512 => sha512(data).to_vec(),
        HashAlgorithm::Sha3_256 => sha3_256(data).to_vec(),
        HashAlgorithm::Blake3 => blake3(data).to_vec(),
    }
}

// ============================================================================
// Merkle Tree
// ============================================================================

/// Simple Merkle tree for data integrity
pub struct MerkleTree {
    /// Leaf hashes
    leaves: Vec<[u8; 32]>,
    /// All nodes (bottom-up, left-to-right)
    nodes: Vec<[u8; 32]>,
    /// Root hash
    root: [u8; 32],
}

impl MerkleTree {
    /// Build a Merkle tree from data items
    pub fn from_data(items: &[&[u8]]) -> Self {
        let leaves: Vec<[u8; 32]> = items.iter().map(|item| sha256(item)).collect();
        Self::from_leaves(leaves)
    }

    /// Build from pre-computed leaf hashes
    pub fn from_leaves(leaves: Vec<[u8; 32]>) -> Self {
        if leaves.is_empty() {
            return MerkleTree {
                leaves: vec![],
                nodes: vec![],
                root: [0u8; 32],
            };
        }

        let mut nodes = leaves.clone();
        let mut level = leaves.clone();

        while level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in level.chunks(2) {
                let hash = if chunk.len() == 2 {
                    Self::hash_pair(&chunk[0], &chunk[1])
                } else {
                    Self::hash_pair(&chunk[0], &chunk[0])
                };
                next_level.push(hash);
            }

            nodes.extend_from_slice(&next_level);
            level = next_level;
        }

        let root = level[0];

        MerkleTree {
            leaves,
            nodes,
            root,
        }
    }

    /// Get the root hash
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Get proof for a leaf at index
    pub fn proof(&self, index: usize) -> Option<MerkleProof> {
        if index >= self.leaves.len() {
            return None;
        }

        let mut proof = Vec::new();
        let mut current_index = index;
        let mut level_start = 0;
        let mut level_size = self.leaves.len();

        while level_size > 1 {
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level_size {
                let sibling_hash = if level_start + sibling_index < self.nodes.len() {
                    self.nodes[level_start + sibling_index]
                } else {
                    self.nodes[level_start + current_index] // Duplicate for odd leaf count
                };

                proof.push(ProofElement {
                    hash: sibling_hash,
                    is_left: current_index % 2 == 1,
                });
            }

            level_start += level_size;
            level_size = (level_size + 1) / 2;
            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_index: index,
            leaf_hash: self.leaves[index],
            proof,
            root: self.root,
        })
    }

    /// Verify a proof
    pub fn verify_proof(proof: &MerkleProof) -> bool {
        let mut current_hash = proof.leaf_hash;

        for element in &proof.proof {
            current_hash = if element.is_left {
                Self::hash_pair(&element.hash, &current_hash)
            } else {
                Self::hash_pair(&current_hash, &element.hash)
            };
        }

        current_hash == proof.root
    }

    fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        let mut data = [0u8; 64];
        data[..32].copy_from_slice(left);
        data[32..].copy_from_slice(right);
        sha256(&data)
    }
}

/// Merkle proof
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Leaf index
    pub leaf_index: usize,
    /// Leaf hash
    pub leaf_hash: [u8; 32],
    /// Proof elements
    pub proof: Vec<ProofElement>,
    /// Expected root
    pub root: [u8; 32],
}

/// Element in a Merkle proof
#[derive(Debug, Clone)]
pub struct ProofElement {
    /// Sibling hash
    pub hash: [u8; 32],
    /// Is this the left sibling?
    pub is_left: bool,
}

// ============================================================================
// Commitment Schemes
// ============================================================================

/// Pedersen-style commitment (simplified)
pub struct Commitment {
    /// Commitment value
    pub value: [u8; 32],
    /// Blinding factor (keep secret!)
    pub blinding: [u8; 32],
}

impl Commitment {
    /// Create a commitment to data
    pub fn commit(data: &[u8]) -> Self {
        let mut blinding = [0u8; 32];
        SecureRandom::fill_bytes(&mut blinding).unwrap();

        let mut combined = Vec::with_capacity(data.len() + 32);
        combined.extend_from_slice(data);
        combined.extend_from_slice(&blinding);

        let value = sha256(&combined);

        Commitment { value, blinding }
    }

    /// Open the commitment and verify
    pub fn verify(commitment: &[u8; 32], data: &[u8], blinding: &[u8; 32]) -> bool {
        let mut combined = Vec::with_capacity(data.len() + 32);
        combined.extend_from_slice(data);
        combined.extend_from_slice(blinding);

        let computed = sha256(&combined);
        computed == *commitment
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_merkle_tree() {
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let tree = MerkleTree::from_data(&items);

        assert!(tree.root() != [0u8; 32]);
    }

    #[test]
    fn test_merkle_proof() {
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let tree = MerkleTree::from_data(&items);

        let proof = tree.proof(2).unwrap();
        assert!(MerkleTree::verify_proof(&proof));
    }

    #[test]
    fn test_commitment() {
        let data = b"secret data";
        let commitment = Commitment::commit(data);

        assert!(Commitment::verify(
            &commitment.value,
            data,
            &commitment.blinding
        ));

        assert!(!Commitment::verify(
            &commitment.value,
            b"wrong data",
            &commitment.blinding
        ));
    }
}
