use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

/// A 32-byte hash value.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub fn zero() -> Self {
        Hash256([0u8; 32])
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash256(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        let mut arr = [0u8; 32];
        let len = slice.len().min(32);
        arr[..len].copy_from_slice(&slice[..len]);
        Hash256(arr)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        let mut arr = [0u8; 32];
        let len = bytes.len().min(32);
        arr[..len].copy_from_slice(&bytes[..len]);
        Ok(Hash256(arr))
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Hash({}..{})",
            hex::encode(&self.0[..4]),
            hex::encode(&self.0[28..32]),
        )
    }
}

impl Serialize for Hash256 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.to_hex().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Hash256 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        Hash256::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Hashing functions
// ---------------------------------------------------------------------------

/// Hash arbitrary bytes with SHA-256.
pub fn hash_bytes(data: &[u8]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Hash256::from_slice(&hasher.finalize())
}

/// Serialize a value for hashing and fail closed if serialization invariants break.
pub fn serialize_for_hash<T: Serialize>(value: &T, context: &'static str) -> Vec<u8> {
    bincode::serialize(value).unwrap_or_else(|err| panic!("{context} serialization failed: {err}"))
}

/// Hash a serializable transaction (or any serde-serializable struct).
pub fn hash_transaction<T: Serialize>(tx: &T) -> Hash256 {
    let encoded = serialize_for_hash(tx, "hash_transaction");
    hash_bytes(&encoded)
}

/// Double SHA-256 hash (used for block headers, matching Bitcoin convention).
pub fn double_hash(data: &[u8]) -> Hash256 {
    let first = hash_bytes(data);
    hash_bytes(first.as_bytes())
}

/// Fast hash using Blake3 (used for non-consensus-critical paths).
pub fn blake3_hash(data: &[u8]) -> Hash256 {
    let h = blake3::hash(data);
    Hash256::from_slice(h.as_bytes())
}

/// Combine two hashes (for merkle tree construction).
pub fn combine_hashes(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut combined = Vec::with_capacity(64);
    combined.extend_from_slice(left.as_bytes());
    combined.extend_from_slice(right.as_bytes());
    hash_bytes(&combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::ser::Error as _;
    use serde::Serializer;

    struct FailingSerialize;

    impl Serialize for FailingSerialize {
        fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(S::Error::custom("intentional failure"))
        }
    }

    #[test]
    fn test_hash_deterministic() {
        let h1 = hash_bytes(b"zincha chain");
        let h2 = hash_bytes(b"zincha chain");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_different_inputs() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hex_roundtrip() {
        let h = hash_bytes(b"test");
        let hex_str = h.to_hex();
        let h2 = Hash256::from_hex(&hex_str).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    #[should_panic(expected = "failing_consensus_hash serialization failed")]
    fn test_serialize_for_hash_fails_closed_on_serialization_error() {
        let _ = serialize_for_hash(&FailingSerialize, "failing_consensus_hash");
    }
}
