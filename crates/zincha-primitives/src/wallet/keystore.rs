use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

use crate::crypto::{Address, Keypair};
use crate::error::{Result, ZinchaError};

/// Which key derivation function protects this keystore entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KdfType {
    Argon2id,
}

/// Which cipher protects this entry's encrypted key material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CipherType {
    #[serde(rename = "xchacha20poly1305")]
    XChaCha20Poly1305,
}

/// How this keystore entry's key material originally entered the public wallet surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeystoreEntryOrigin {
    /// Random keypair generated directly by Zincha.
    Generated,
    /// Imported from a raw 32-byte secret key file.
    RawSecretFile,
    /// Imported from a standard PKCS#8 PEM private key.
    Pkcs8Pem,
    /// Derived from a BIP39 mnemonic phrase.
    Mnemonic,
}

/// An encrypted keystore entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeystoreEntry {
    /// The address derived from this key.
    pub address: Address,
    /// Encrypted secret key bytes.
    pub encrypted_key: Vec<u8>,
    /// Salt for key derivation.
    pub salt: [u8; 32],
    /// Nonce used by the authenticated cipher for current-format entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<Vec<u8>>,
    /// Creation timestamp.
    pub created_at: u64,
    /// Human-readable label.
    pub label: String,
    /// Which KDF protects the entry.
    pub kdf: KdfType,
    /// Which cipher protects the entry.
    pub cipher: CipherType,
    /// How this key originally entered the public wallet surface.
    pub origin: KeystoreEntryOrigin,
    /// Optional derivation path metadata for mnemonic-derived entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derivation_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPasswordChangeOutcome {
    pub kdf_before: KdfType,
    pub kdf_after: KdfType,
    pub cipher_before: CipherType,
    pub cipher_after: CipherType,
    pub password_changed: bool,
}

/// A keystore for managing multiple keypairs with password encryption.
#[derive(Debug)]
pub struct Keystore {
    entries: Vec<KeystoreEntry>,
    #[allow(dead_code)]
    path: Option<String>,
}

impl Keystore {
    /// Create a new empty keystore.
    pub fn new() -> Self {
        Keystore {
            entries: Vec::new(),
            path: None,
        }
    }

    /// Load a keystore from a file.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let data = std::fs::read_to_string(&path_str)
            .map_err(|e| ZinchaError::Storage(format!("Cannot read keystore: {}", e)))?;
        let mut keystore = Self::from_json_str(&data)?;
        keystore.path = Some(path_str);
        Ok(keystore)
    }

    /// Save the keystore to disk.
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = self.to_json_pretty()?;
        std::fs::write(path, json)
            .map_err(|e| ZinchaError::Storage(format!("Cannot write keystore: {}", e)))?;
        Ok(())
    }

    /// Parse a keystore from its JSON representation.
    pub fn from_json_str(data: &str) -> Result<Self> {
        let raw: serde_json::Value = serde_json::from_str(data)?;
        validate_keystore_json_shape(&raw)?;
        let entries: Vec<KeystoreEntry> = serde_json::from_value(raw)?;
        for entry in &entries {
            entry.validate_current_format()?;
        }
        Ok(Keystore {
            entries,
            path: None,
        })
    }

    /// Serialize the keystore to pretty JSON.
    pub fn to_json_pretty(&self) -> Result<String> {
        serde_json::to_string_pretty(&self.entries).map_err(Into::into)
    }

    /// Generate a new keypair and add it to the keystore.
    pub fn create_key(&mut self, password: &str, label: &str) -> Result<Address> {
        let keypair = Keypair::generate();
        let address = keypair.address();
        self.import_key_with_origin(
            &keypair,
            password,
            label,
            KeystoreEntryOrigin::Generated,
            None,
        )?;
        info!("Key created: {} ({})", address, label);
        Ok(address)
    }

    /// Import an existing keypair into the keystore.
    /// New keys are always encrypted with Argon2id.
    pub fn import_key(&mut self, keypair: &Keypair, password: &str, label: &str) -> Result<()> {
        self.import_key_with_origin(
            keypair,
            password,
            label,
            KeystoreEntryOrigin::RawSecretFile,
            None,
        )
    }

    pub fn import_key_with_origin(
        &mut self,
        keypair: &Keypair,
        password: &str,
        label: &str,
        origin: KeystoreEntryOrigin,
        derivation_path: Option<String>,
    ) -> Result<()> {
        if self.entry(&keypair.address()).is_some() {
            return Err(ZinchaError::InvalidPublicKey(format!(
                "Address {} already exists in keystore",
                keypair.address()
            )));
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let entry =
            Self::build_current_entry(keypair, password, label, now, origin, derivation_path)?;
        self.entries.push(entry);
        Ok(())
    }

    fn build_current_entry(
        keypair: &Keypair,
        password: &str,
        label: &str,
        created_at: u64,
        origin: KeystoreEntryOrigin,
        derivation_path: Option<String>,
    ) -> Result<KeystoreEntry> {
        let salt = generate_salt();
        let derived_key = derive_key_argon2id(password, &salt)?;
        let secret_bytes = keypair.secret_bytes();
        let nonce = generate_nonce();
        let cipher = XChaCha20Poly1305::new_from_slice(&derived_key).map_err(|error| {
            ZinchaError::KeyDerivation(format!("build keystore cipher: {}", error))
        })?;
        let aad = keystore_aad(&keypair.address());
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &secret_bytes,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|error| {
                ZinchaError::KeyDerivation(format!("encrypt keystore entry: {}", error))
            })?;

        Ok(KeystoreEntry {
            address: keypair.address(),
            encrypted_key: encrypted,
            salt,
            nonce: Some(nonce.to_vec()),
            created_at,
            label: label.to_string(),
            kdf: KdfType::Argon2id,
            cipher: CipherType::XChaCha20Poly1305,
            origin,
            derivation_path,
        })
    }

    /// Unlock a keypair with the given password.
    pub fn unlock(&self, address: &Address, password: &str) -> Result<Keypair> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.address == *address)
            .ok_or_else(|| {
                ZinchaError::InvalidPublicKey(format!("Address {} not found in keystore", address))
            })?;

        entry.validate_current_format()?;

        let derived_key = derive_key_argon2id(password, &entry.salt)?;
        let nonce = entry.nonce.as_ref().ok_or_else(|| {
            ZinchaError::KeyDerivation(format!(
                "Keystore entry {} is missing its cipher nonce",
                address
            ))
        })?;
        if nonce.len() != 24 {
            return Err(ZinchaError::KeyDerivation(format!(
                "Keystore entry {} has invalid nonce length {}",
                address,
                nonce.len()
            )));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(&derived_key).map_err(|error| {
            ZinchaError::KeyDerivation(format!("build keystore cipher: {}", error))
        })?;
        let aad = keystore_aad(address);
        let decrypted = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: &entry.encrypted_key,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| {
                ZinchaError::KeyDerivation(
                    "Invalid password or corrupted keystore entry".to_string(),
                )
            })?;
        if decrypted.len() != 32 {
            return Err(ZinchaError::KeyDerivation(format!(
                "Keystore entry {} decrypted to invalid secret length {}",
                address,
                decrypted.len()
            )));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&decrypted);

        let keypair = Keypair::from_secret_bytes(&secret);

        // Verify the derived address matches
        if keypair.address() != *address {
            return Err(ZinchaError::KeyDerivation(
                "Decrypted key does not match stored address".to_string(),
            ));
        }

        Ok(keypair)
    }

    pub fn relabel(&mut self, address: &Address, label: &str) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.address == *address)
            .ok_or_else(|| {
                ZinchaError::InvalidPublicKey(format!("Address {} not found in keystore", address))
            })?;
        entry.label = label.to_string();
        Ok(())
    }

    pub fn change_entry_password(
        &mut self,
        address: &Address,
        current_password: &str,
        new_password: &str,
    ) -> Result<EntryPasswordChangeOutcome> {
        let keypair = self.unlock(address, current_password)?;
        let index = self
            .entries
            .iter()
            .position(|entry| entry.address == *address)
            .ok_or_else(|| {
                ZinchaError::InvalidPublicKey(format!("Address {} not found in keystore", address))
            })?;
        let original = self.entries[index].clone();
        self.entries[index] = Self::build_current_entry(
            &keypair,
            new_password,
            &original.label,
            original.created_at,
            original.origin,
            original.derivation_path.clone(),
        )?;

        Ok(EntryPasswordChangeOutcome {
            kdf_before: original.kdf,
            kdf_after: KdfType::Argon2id,
            cipher_before: original.cipher,
            cipher_after: CipherType::XChaCha20Poly1305,
            password_changed: current_password != new_password,
        })
    }

    /// List all addresses in the keystore.
    pub fn list_addresses(&self) -> Vec<(Address, String)> {
        self.entries
            .iter()
            .map(|e| (e.address.clone(), e.label.clone()))
            .collect()
    }

    /// Borrow the keystore entries for read-only CLI and API rendering.
    pub fn entries(&self) -> &[KeystoreEntry] {
        &self.entries
    }

    /// Look up one keystore entry by address.
    pub fn entry(&self, address: &Address) -> Option<&KeystoreEntry> {
        self.entries.iter().find(|entry| entry.address == *address)
    }

    /// Remove a key from the keystore.
    pub fn remove(&mut self, address: &Address) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.address != *address);
        self.entries.len() < before
    }

    /// Number of keys in the keystore.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl KeystoreEntry {
    pub fn validate_current_format(&self) -> Result<()> {
        let nonce = self.nonce.as_ref().ok_or_else(|| {
            ZinchaError::Serialization(format!(
                "Keystore entry {} is missing required xchacha20poly1305 nonce metadata",
                self.address
            ))
        })?;
        if nonce.len() != 24 {
            return Err(ZinchaError::Serialization(format!(
                "Keystore entry {} has invalid nonce length {}",
                self.address,
                nonce.len()
            )));
        }
        Ok(())
    }
}

/// Derive a 32-byte key using Argon2id (memory-hard, GPU-resistant).
///
/// Parameters chosen for a reasonable security/speed tradeoff:
///   - Memory: 64 MiB (makes GPU attacks expensive)
///   - Iterations: 3 (standard recommendation for interactive use)
///   - Parallelism: 1 (single-threaded derivation)
///
/// These match the OWASP minimum recommendation for Argon2id.
fn derive_key_argon2id(password: &str, salt: &[u8; 32]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(
        64 * 1024, // 64 MiB memory
        3,         // 3 iterations
        1,         // 1 lane (parallelism)
        Some(32),  // 32-byte output
    )
    .map_err(|e| ZinchaError::KeyDerivation(format!("Argon2 params error: {}", e)))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| ZinchaError::KeyDerivation(format!("Argon2id derivation failed: {}", e)))?;

    Ok(key)
}

/// Generate a random 32-byte salt.
fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate a random 24-byte nonce for XChaCha20-Poly1305.
fn generate_nonce() -> [u8; 24] {
    let mut nonce = [0u8; 24];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

fn keystore_aad(address: &Address) -> String {
    format!("zincha-keystore:v2:{}", address)
}

fn validate_keystore_json_shape(raw: &serde_json::Value) -> Result<()> {
    let entries = raw.as_array().ok_or_else(|| {
        ZinchaError::Serialization("keystore JSON must be an array of entries".to_string())
    })?;

    for (index, entry) in entries.iter().enumerate() {
        let position = index + 1;
        let object = entry.as_object().ok_or_else(|| {
            ZinchaError::Serialization(format!("keystore entry {} must be a JSON object", position))
        })?;

        if object.contains_key("check_hash") {
            return Err(ZinchaError::Serialization(format!(
                "keystore entry {} contains removed legacy \"check_hash\" metadata; canonical keystore entries no longer support legacy password verifiers",
                position
            )));
        }

        let origin = object
            .get("origin")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                ZinchaError::Serialization(format!(
                    "keystore entry {} is missing required \"origin\" metadata; canonical keystore entries must declare how key material entered the wallet surface",
                    position
                ))
            })?;
        if !matches!(
            origin,
            "generated" | "raw_secret_file" | "pkcs8_pem" | "mnemonic"
        ) {
            return Err(ZinchaError::Serialization(format!(
                "keystore entry {} uses unsupported origin {:?}; expected one of \"generated\", \"raw_secret_file\", \"pkcs8_pem\", or \"mnemonic\"",
                position, origin
            )));
        }

        let kdf = object
            .get("kdf")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                ZinchaError::Serialization(format!(
                    "keystore entry {} is missing required \"kdf\" metadata; legacy keystore crypto is no longer supported",
                    position
                ))
            })?;
        if kdf != "argon2id" {
            return Err(ZinchaError::Serialization(format!(
                "keystore entry {} uses unsupported legacy kdf {:?}; only \"argon2id\" is supported",
                position, kdf
            )));
        }

        let cipher = object
            .get("cipher")
            .and_then(|value| value.as_str())
            .ok_or_else(|| {
                ZinchaError::Serialization(format!(
                    "keystore entry {} is missing required \"cipher\" metadata; legacy keystore crypto is no longer supported",
                    position
                ))
            })?;
        if cipher != "xchacha20poly1305" {
            return Err(ZinchaError::Serialization(format!(
                "keystore entry {} uses unsupported legacy cipher {:?}; only \"xchacha20poly1305\" is supported",
                position, cipher
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_unlock_argon2id() {
        let mut ks = Keystore::new();
        let addr = ks.create_key("mypassword", "test key").unwrap();

        // New keys should use the current secure Argon2id + AEAD format.
        let entry = ks.entries.iter().find(|e| e.address == addr).unwrap();
        assert_eq!(entry.kdf, KdfType::Argon2id);
        assert_eq!(entry.cipher, CipherType::XChaCha20Poly1305);
        assert_eq!(entry.origin, KeystoreEntryOrigin::Generated);
        assert!(entry.derivation_path.is_none());
        assert_eq!(entry.nonce.as_ref().map(Vec::len), Some(24));

        let kp = ks.unlock(&addr, "mypassword").unwrap();
        assert_eq!(kp.address(), addr);
    }

    #[test]
    fn test_wrong_password_fails() {
        let mut ks = Keystore::new();
        let addr = ks.create_key("correct", "test").unwrap();

        let result = ks.unlock(&addr, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn test_import_and_recover() {
        let original_kp = Keypair::generate();
        let addr = original_kp.address();

        let mut ks = Keystore::new();
        ks.import_key(&original_kp, "secret", "imported").unwrap();

        let recovered = ks.unlock(&addr, "secret").unwrap();
        assert_eq!(recovered.address(), addr);
    }

    #[test]
    fn test_tampered_current_ciphertext_fails_closed() {
        let mut ks = Keystore::new();
        let addr = ks.create_key("secret", "tamper").unwrap();
        let entry = ks
            .entries
            .iter_mut()
            .find(|entry| entry.address == addr)
            .expect("entry");
        entry.encrypted_key[0] ^= 0x80;

        let err = match ks.unlock(&addr, "secret") {
            Ok(_) => panic!("tampered ciphertext must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("Invalid password or corrupted keystore entry"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_tampered_current_nonce_fails_closed() {
        let mut ks = Keystore::new();
        let addr = ks.create_key("secret", "tamper").unwrap();
        let entry = ks
            .entries
            .iter_mut()
            .find(|entry| entry.address == addr)
            .expect("entry");
        let nonce = entry.nonce.as_mut().expect("nonce");
        nonce[0] ^= 0x55;

        let err = match ks.unlock(&addr, "secret") {
            Ok(_) => panic!("tampered nonce must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("Invalid password or corrupted keystore entry"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_legacy_json_without_cipher_metadata_is_rejected() {
        let keypair = Keypair::from_secret_bytes(&[51u8; 32]);
        let json = serde_json::json!([
            {
                "address": keypair.address().to_raw_hex(),
                "encrypted_key": vec![0u8; 32],
                "salt": vec![7u8; 32],
                "created_at": 11,
                "label": "legacy-json",
                "origin": "generated",
                "kdf": "argon2id"
            }
        ])
        .to_string();

        let err = Keystore::from_json_str(&json).expect_err("legacy json must be rejected");
        assert!(
            err.to_string()
                .contains("missing required \"cipher\" metadata"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_legacy_json_with_unsupported_cipher_is_rejected() {
        let keypair = Keypair::from_secret_bytes(&[52u8; 32]);
        let json = serde_json::json!([
            {
                "address": keypair.address().to_raw_hex(),
                "encrypted_key": vec![0u8; 32],
                "salt": vec![8u8; 32],
                "created_at": 12,
                "label": "legacy-json",
                "origin": "generated",
                "kdf": "argon2id",
                "cipher": "xor"
            }
        ])
        .to_string();

        let err = Keystore::from_json_str(&json).expect_err("legacy xor json must be rejected");
        assert!(
            err.to_string().contains("unsupported legacy cipher"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_current_json_missing_nonce_is_rejected() {
        let keypair = Keypair::from_secret_bytes(&[53u8; 32]);
        let json = serde_json::json!([
            {
                "address": keypair.address().to_raw_hex(),
                "encrypted_key": vec![0u8; 48],
                "salt": vec![9u8; 32],
                "created_at": 13,
                "label": "broken-current",
                "origin": "generated",
                "kdf": "argon2id",
                "cipher": "xchacha20poly1305"
            }
        ])
        .to_string();

        let err = Keystore::from_json_str(&json).expect_err("missing nonce must be rejected");
        assert!(
            err.to_string()
                .contains("missing required xchacha20poly1305 nonce"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_legacy_json_missing_origin_metadata_is_rejected() {
        let keypair = Keypair::from_secret_bytes(&[54u8; 32]);
        let json = serde_json::json!([
            {
                "address": keypair.address().to_raw_hex(),
                "encrypted_key": vec![0u8; 48],
                "salt": vec![10u8; 32],
                "nonce": vec![0u8; 24],
                "created_at": 14,
                "label": "missing-origin",
                "kdf": "argon2id",
                "cipher": "xchacha20poly1305"
            }
        ])
        .to_string();

        let err = Keystore::from_json_str(&json).expect_err("missing origin must be rejected");
        assert!(
            err.to_string()
                .contains("missing required \"origin\" metadata"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_legacy_json_with_removed_check_hash_metadata_is_rejected() {
        let keypair = Keypair::from_secret_bytes(&[55u8; 32]);
        let json = serde_json::json!([
            {
                "address": keypair.address().to_raw_hex(),
                "encrypted_key": vec![0u8; 48],
                "salt": vec![11u8; 32],
                "nonce": vec![0u8; 24],
                "check_hash": "removed-legacy-password-verifier",
                "created_at": 15,
                "label": "removed-check-hash",
                "origin": "generated",
                "kdf": "argon2id",
                "cipher": "xchacha20poly1305"
            }
        ])
        .to_string();

        let err = Keystore::from_json_str(&json).expect_err("removed check_hash must be rejected");
        assert!(
            err.to_string()
                .contains("contains removed legacy \"check_hash\" metadata"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_relabel_and_change_password_preserve_entry_metadata() {
        let keypair = Keypair::generate();
        let address = keypair.address();
        let mut ks = Keystore::new();
        ks.import_key(&keypair, "oldpw", "initial").unwrap();
        let created_at = ks.entry(&address).unwrap().created_at;

        ks.relabel(&address, "renamed").unwrap();
        let outcome = ks
            .change_entry_password(&address, "oldpw", "newpw")
            .unwrap();
        assert_eq!(
            outcome,
            EntryPasswordChangeOutcome {
                kdf_before: KdfType::Argon2id,
                kdf_after: KdfType::Argon2id,
                cipher_before: CipherType::XChaCha20Poly1305,
                cipher_after: CipherType::XChaCha20Poly1305,
                password_changed: true,
            }
        );

        let entry = ks.entry(&address).expect("entry preserved");
        assert_eq!(entry.label, "renamed");
        assert_eq!(entry.created_at, created_at);
        assert_eq!(entry.kdf, KdfType::Argon2id);
        assert_eq!(entry.cipher, CipherType::XChaCha20Poly1305);
        assert_eq!(entry.origin, KeystoreEntryOrigin::RawSecretFile);
        assert!(entry.derivation_path.is_none());

        assert!(ks.unlock(&address, "oldpw").is_err());
        let recovered = ks.unlock(&address, "newpw").unwrap();
        assert_eq!(recovered.address(), address);
    }

    #[test]
    fn test_import_key_rejects_duplicate_address() {
        let keypair = Keypair::generate();
        let mut ks = Keystore::new();
        ks.import_key(&keypair, "pw", "first").unwrap();
        let err = ks.import_key(&keypair, "pw", "duplicate").unwrap_err();
        assert!(
            err.to_string().contains("already exists in keystore"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_list_and_remove() {
        let mut ks = Keystore::new();
        let addr1 = ks.create_key("pw1", "key1").unwrap();
        let addr2 = ks.create_key("pw2", "key2").unwrap();

        assert_eq!(ks.len(), 2);
        assert_eq!(ks.list_addresses().len(), 2);

        assert!(ks.remove(&addr1));
        assert_eq!(ks.len(), 1);
        assert_eq!(ks.list_addresses()[0].0, addr2);
    }

    #[test]
    fn test_import_key_with_origin_preserves_derivation_metadata() {
        let keypair = Keypair::from_secret_bytes(&[19u8; 32]);
        let mut ks = Keystore::new();
        ks.import_key_with_origin(
            &keypair,
            "pw",
            "mnemonic",
            KeystoreEntryOrigin::Mnemonic,
            Some("m/44'/0'/0'".to_string()),
        )
        .expect("import");

        let entry = ks.entry(&keypair.address()).expect("entry");
        assert_eq!(entry.origin, KeystoreEntryOrigin::Mnemonic);
        assert_eq!(entry.derivation_path.as_deref(), Some("m/44'/0'/0'"));
    }
}
