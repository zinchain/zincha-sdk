use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::crypto::Keypair;
use crate::error::{Result, ZinchaError};

type HmacSha512 = Hmac<Sha512>;

pub const DEFAULT_MNEMONIC_WORD_COUNT: usize = 24;
pub const DEFAULT_DERIVATION_PATH: &str = "m";

pub struct DerivedMnemonicKey {
    pub keypair: Keypair,
    pub derivation_path: String,
}

pub struct GeneratedMnemonicKey {
    pub mnemonic: String,
    pub keypair: Keypair,
    pub derivation_path: String,
    pub word_count: usize,
}

pub fn generate_mnemonic_key(
    word_count: usize,
    passphrase: &str,
    derivation_path: Option<&str>,
) -> Result<GeneratedMnemonicKey> {
    validate_word_count(word_count)?;
    let mnemonic = Mnemonic::generate_in(Language::English, word_count).map_err(|error| {
        ZinchaError::KeyDerivation(format!("generate BIP39 mnemonic: {}", error))
    })?;
    let phrase = mnemonic.to_string();
    let derived = derive_keypair_from_mnemonic_phrase(&phrase, passphrase, derivation_path)?;
    Ok(GeneratedMnemonicKey {
        mnemonic: phrase,
        keypair: derived.keypair,
        derivation_path: derived.derivation_path,
        word_count,
    })
}

pub fn derive_keypair_from_mnemonic_phrase(
    phrase: &str,
    passphrase: &str,
    derivation_path: Option<&str>,
) -> Result<DerivedMnemonicKey> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase.trim())
        .map_err(|error| ZinchaError::KeyDerivation(format!("parse BIP39 mnemonic: {}", error)))?;
    let normalized_path = normalize_derivation_path(derivation_path)?;
    let seed = mnemonic.to_seed(passphrase);
    let secret = derive_slip10_ed25519_secret(&seed, &normalized_path)?;
    Ok(DerivedMnemonicKey {
        keypair: Keypair::from_secret_bytes(&secret),
        derivation_path: normalized_path,
    })
}

pub fn normalize_derivation_path(path: Option<&str>) -> Result<String> {
    let path = path
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_DERIVATION_PATH);
    let _ = parse_derivation_path(path)?;
    Ok(if path == DEFAULT_DERIVATION_PATH {
        DEFAULT_DERIVATION_PATH.to_string()
    } else {
        path_segments_to_string(&parse_derivation_path(path)?)
    })
}

fn validate_word_count(word_count: usize) -> Result<()> {
    match word_count {
        12 | 15 | 18 | 21 | 24 => Ok(()),
        _ => Err(ZinchaError::Config(format!(
            "unsupported mnemonic word count {}; use 12, 15, 18, 21, or 24",
            word_count
        ))),
    }
}

fn derive_slip10_ed25519_secret(seed: &[u8], path: &str) -> Result<[u8; 32]> {
    let indices = parse_derivation_path(path)?;
    let (mut secret, mut chain_code) = slip10_master(seed)?;
    for index in indices {
        let derived = slip10_child(&secret, &chain_code, index)?;
        secret = derived.0;
        chain_code = derived.1;
    }
    Ok(secret)
}

fn parse_derivation_path(path: &str) -> Result<Vec<u32>> {
    let mut segments = path.split('/');
    match segments.next() {
        Some("m") => {}
        _ => {
            return Err(ZinchaError::Config(format!(
                "invalid derivation path {}; paths must start with m",
                path
            )))
        }
    }

    let mut indices = Vec::new();
    for segment in segments {
        if segment.is_empty() {
            return Err(ZinchaError::Config(format!(
                "invalid derivation path {}; empty path segment",
                path
            )));
        }

        let hardened = segment.ends_with('\'') || segment.ends_with('h') || segment.ends_with('H');
        if !hardened {
            return Err(ZinchaError::Config(format!(
                "invalid derivation path {}; ed25519 paths must use hardened segments",
                path
            )));
        }

        let value = &segment[..segment.len() - 1];
        let index = value.parse::<u32>().map_err(|error| {
            ZinchaError::Config(format!(
                "invalid derivation path {}; segment {} is not a valid index: {}",
                path, segment, error
            ))
        })?;
        if index >= 0x8000_0000 {
            return Err(ZinchaError::Config(format!(
                "invalid derivation path {}; segment {} exceeds the maximum unhardened index",
                path, segment
            )));
        }
        indices.push(index);
    }

    Ok(indices)
}

fn path_segments_to_string(indices: &[u32]) -> String {
    if indices.is_empty() {
        return DEFAULT_DERIVATION_PATH.to_string();
    }

    let mut normalized = String::from("m");
    for index in indices {
        normalized.push('/');
        normalized.push_str(&index.to_string());
        normalized.push('\'');
    }
    normalized
}

fn slip10_master(seed: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").map_err(|error| {
        ZinchaError::KeyDerivation(format!("initialize SLIP-0010 master derivation: {}", error))
    })?;
    mac.update(seed);
    let digest = mac.finalize().into_bytes();
    let mut secret = [0u8; 32];
    let mut chain_code = [0u8; 32];
    secret.copy_from_slice(&digest[..32]);
    chain_code.copy_from_slice(&digest[32..]);
    Ok((secret, chain_code))
}

fn slip10_child(
    parent_secret: &[u8; 32],
    parent_chain_code: &[u8; 32],
    index: u32,
) -> Result<([u8; 32], [u8; 32])> {
    let mut mac = HmacSha512::new_from_slice(parent_chain_code).map_err(|error| {
        ZinchaError::KeyDerivation(format!("initialize SLIP-0010 child derivation: {}", error))
    })?;
    let hardened_index = index | 0x8000_0000;
    let mut data = [0u8; 1 + 32 + 4];
    data[0] = 0;
    data[1..33].copy_from_slice(parent_secret);
    data[33..].copy_from_slice(&hardened_index.to_be_bytes());
    mac.update(&data);
    let digest = mac.finalize().into_bytes();
    let mut secret = [0u8; 32];
    let mut chain_code = [0u8; 32];
    secret.copy_from_slice(&digest[..32]);
    chain_code.copy_from_slice(&digest[32..]);
    Ok((secret, chain_code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mnemonic_key_uses_requested_word_count() {
        let generated = generate_mnemonic_key(24, "", Some("m/44'/0'/0'")).expect("generate");
        assert_eq!(generated.word_count, 24);
        assert_eq!(generated.mnemonic.split_whitespace().count(), 24);
        assert_eq!(generated.derivation_path, "m/44'/0'/0'");
    }

    #[test]
    fn test_mnemonic_derivation_is_deterministic() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let first = derive_keypair_from_mnemonic_phrase(phrase, "", Some("m/44'/0'/0'"))
            .expect("derive first");
        let second = derive_keypair_from_mnemonic_phrase(phrase, "", Some("m/44'/0'/0'"))
            .expect("derive second");
        assert_eq!(first.keypair.address(), second.keypair.address());
        assert_eq!(first.derivation_path, second.derivation_path);
    }

    #[test]
    fn test_mnemonic_derivation_changes_with_path() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let first = derive_keypair_from_mnemonic_phrase(phrase, "", Some("m/44'/0'/0'"))
            .expect("derive first");
        let second = derive_keypair_from_mnemonic_phrase(phrase, "", Some("m/44'/0'/1'"))
            .expect("derive second");
        assert_ne!(first.keypair.address(), second.keypair.address());
    }

    #[test]
    fn test_normalize_derivation_path_accepts_root() {
        assert_eq!(normalize_derivation_path(None).expect("normalize"), "m");
        assert_eq!(
            normalize_derivation_path(Some("m")).expect("normalize"),
            "m"
        );
    }

    #[test]
    fn test_normalize_derivation_path_rejects_non_hardened_segments() {
        let error = normalize_derivation_path(Some("m/44/0'")).expect_err("reject path");
        assert!(error
            .to_string()
            .contains("ed25519 paths must use hardened segments"));
    }
}
