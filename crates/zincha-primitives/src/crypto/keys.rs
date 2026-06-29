use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use pkcs8::LineEnding;
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::error::{Result, ZinchaError};

pub const ADDRESS_PREFIX: &str = "zn1";

// ---------------------------------------------------------------------------
// Address
// ---------------------------------------------------------------------------

/// A 20-byte Zincha address derived from a public key.
/// Format: zn1<bech32-like hex>
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Address(#[serde(with = "hex_serde")] pub [u8; 20]);

impl Address {
    /// Derive address from a public key: SHA-256 of pubkey, take last 20 bytes.
    pub fn from_public_key(pubkey: &PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey.as_bytes());
        let hash = hasher.finalize();
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);
        Address(addr)
    }

    fn decode_raw_hex_body(s: &str) -> Result<Self> {
        let bytes = hex::decode(s).map_err(|e| ZinchaError::InvalidPublicKey(e.to_string()))?;
        if bytes.len() != 20 {
            return Err(ZinchaError::InvalidPublicKey(format!(
                "Address must be 20 bytes, got {}",
                bytes.len()
            )));
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        Ok(Address(addr))
    }

    /// Create address from the canonical public `zn1...` string form.
    pub fn from_hex(s: &str) -> Result<Self> {
        let Some(raw_hex) = s.strip_prefix(ADDRESS_PREFIX) else {
            return Err(ZinchaError::InvalidPublicKey(format!(
                "Address must start with {}",
                ADDRESS_PREFIX
            )));
        };
        Self::decode_raw_hex_body(raw_hex)
    }

    /// Create address from internal raw 40-character hex without a `zn1` prefix.
    pub fn from_raw_hex(s: &str) -> Result<Self> {
        if s.starts_with(ADDRESS_PREFIX) {
            return Err(ZinchaError::InvalidPublicKey(format!(
                "Raw hex address must not include {} prefix",
                ADDRESS_PREFIX
            )));
        }
        Self::decode_raw_hex_body(s)
    }

    /// The treasury address (validator reward emissions pool).
    /// Deterministic: 0x00...01
    pub fn treasury() -> Self {
        let mut addr = [0u8; 20];
        addr[19] = 0x01;
        Address(addr)
    }

    /// Ecosystem fund address (grants, partnerships, dev incentives).
    /// Deterministic: 0x00...02
    pub fn ecosystem_fund() -> Self {
        let mut addr = [0u8; 20];
        addr[19] = 0x02;
        Address(addr)
    }

    /// Distribution fund address (public distribution programs and launch allocations).
    /// Deterministic: 0x00...03
    pub fn distribution_fund() -> Self {
        let mut addr = [0u8; 20];
        addr[19] = 0x03;
        Address(addr)
    }

    /// Foundation address (operations, research — subject to vesting).
    /// Deterministic: 0x00...04
    pub fn foundation() -> Self {
        let mut addr = [0u8; 20];
        addr[19] = 0x04;
        Address(addr)
    }

    /// The null/zero address.
    pub fn zero() -> Self {
        Address([0u8; 20])
    }

    pub fn to_raw_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn to_hex(&self) -> String {
        format!("{}{}", ADDRESS_PREFIX, self.to_raw_hex())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", ADDRESS_PREFIX, self.to_raw_hex())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self)
    }
}

// ---------------------------------------------------------------------------
// PublicKey wrapper
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PublicKey(VerifyingKey);

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for PublicKey {}

impl PublicKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let vk = VerifyingKey::from_bytes(bytes)
            .map_err(|e| ZinchaError::InvalidPublicKey(e.to_string()))?;
        Ok(PublicKey(vk))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.0
            .verify(message, &signature.0)
            .map_err(|e| ZinchaError::InvalidSignature(e.to_string()))
    }

    pub fn to_address(&self) -> Address {
        Address::from_public_key(self)
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        hex::encode(self.as_bytes()).serialize(s)
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 32];
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Public key must be 32 bytes"));
        }
        arr.copy_from_slice(&bytes);
        PublicKey::from_bytes(&arr).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", hex::encode(&self.as_bytes()[..8]))
    }
}

// ---------------------------------------------------------------------------
// Signature wrapper
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Signature(DalekSignature);

impl Signature {
    pub fn from_bytes(bytes: &[u8; 64]) -> Result<Self> {
        let sig = DalekSignature::from_bytes(bytes);
        Ok(Signature(sig))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0.to_bytes()
    }
}

impl Serialize for Signature {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        hex::encode(self.to_bytes()).serialize(s)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Signature must be 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Signature::from_bytes(&arr).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig({}..)", hex::encode(&self.to_bytes()[..8]))
    }
}

// ---------------------------------------------------------------------------
// Keypair
// ---------------------------------------------------------------------------

pub struct Keypair {
    signing_key: SigningKey,
}

impl Keypair {
    /// Generate a new random keypair using OS entropy.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Keypair { signing_key }
    }

    /// Restore keypair from secret key bytes.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        Keypair { signing_key }
    }

    /// Restore keypair from a PKCS#8 PEM-encoded private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_pem(pem).map_err(|error| {
            ZinchaError::InvalidPublicKey(format!("invalid PKCS#8 PEM: {}", error))
        })?;
        Ok(Keypair { signing_key })
    }

    /// Get the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.signing_key.verifying_key())
    }

    /// Get the derived Zincha address.
    pub fn address(&self) -> Address {
        self.public_key().to_address()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature(self.signing_key.sign(message))
    }

    /// Get secret key bytes (handle with care!).
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Export this private key as a PKCS#8 PEM document.
    pub fn to_pkcs8_pem(&self) -> Result<String> {
        self.signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|document| document.to_string())
            .map_err(|error| ZinchaError::KeyDerivation(format!("encode PKCS#8 PEM: {}", error)))
    }
}

// ---------------------------------------------------------------------------
// Helper module for hex serde on fixed-size arrays
// ---------------------------------------------------------------------------
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 20], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 20], D::Error> {
        let hex_str = String::deserialize(d)?;
        let bytes = hex::decode(&hex_str).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 20];
        if bytes.len() != 20 {
            return Err(serde::de::Error::custom("Expected 20 bytes"));
        }
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_sign_verify() {
        let kp = Keypair::generate();
        let msg = b"hello zincha";
        let sig = kp.sign(msg);
        assert!(kp.public_key().verify(msg, &sig).is_ok());
    }

    #[test]
    fn test_keypair_sign_verify_wrong_message() {
        let kp = Keypair::generate();
        let sig = kp.sign(b"hello zincha");
        assert!(kp.public_key().verify(b"wrong message", &sig).is_err());
    }

    #[test]
    fn test_address_derivation_deterministic() {
        let kp = Keypair::from_secret_bytes(&[42u8; 32]);
        let addr1 = kp.address();
        let addr2 = kp.address();
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn test_address_display() {
        let addr = Address::treasury();
        let s = addr.to_string();
        assert!(s.starts_with(ADDRESS_PREFIX));
    }

    #[test]
    fn test_address_from_hex_rejects_legacy_prefix() {
        let addr = Address::treasury();
        let legacy = format!("ax1{}", addr.to_raw_hex());
        assert!(Address::from_hex(&legacy).is_err());
    }

    #[test]
    fn test_address_from_hex_rejects_bare_hex() {
        let addr = Address::treasury();
        assert!(Address::from_hex(&addr.to_raw_hex()).is_err());
    }

    #[test]
    fn test_address_from_raw_hex_accepts_bare_hex_and_rejects_prefixed() {
        let addr = Address::treasury();
        assert_eq!(Address::from_raw_hex(&addr.to_raw_hex()).unwrap(), addr);
        assert!(Address::from_raw_hex(&addr.to_string()).is_err());
    }

    #[test]
    fn test_keypair_restore() {
        let kp1 = Keypair::generate();
        let secret = kp1.secret_bytes();
        let kp2 = Keypair::from_secret_bytes(&secret);
        assert_eq!(kp1.address(), kp2.address());
    }

    #[test]
    fn test_keypair_pkcs8_pem_round_trip() {
        let kp1 = Keypair::generate();
        let pem = kp1.to_pkcs8_pem().expect("encode pkcs8");
        let kp2 = Keypair::from_pkcs8_pem(&pem).expect("decode pkcs8");
        assert_eq!(kp1.address(), kp2.address());
        assert_eq!(kp1.secret_bytes(), kp2.secret_bytes());
    }
}
