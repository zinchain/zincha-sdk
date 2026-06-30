use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use zincha_primitives::crypto::{Address, Hash256, PublicKey};

pub fn parse_address(raw: &str) -> Result<Address> {
    Address::from_hex(raw).with_context(|| format!("parse address {raw}"))
}

pub fn parse_hash(raw: &str) -> Result<Hash256> {
    Hash256::from_hex(raw).with_context(|| format!("parse hash {raw}"))
}

pub fn parse_public_key(raw: &str) -> Result<PublicKey> {
    let bytes = hex::decode(raw).with_context(|| format!("decode public key hex {raw}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    PublicKey::from_bytes(&bytes).with_context(|| format!("parse public key {raw}"))
}

pub fn parse_hex_bytes(raw: Option<&str>) -> Result<Vec<u8>> {
    match raw {
        Some(value) if !value.is_empty() => {
            hex::decode(value).with_context(|| format!("decode hex bytes {value}"))
        }
        _ => Ok(Vec::new()),
    }
}

pub fn parse_capabilities(
    values: Vec<String>,
) -> Result<Vec<zincha_primitives::primitives::Capability>> {
    Ok(values
        .into_iter()
        .map(|value| zincha_primitives::primitives::Capability::new(&value))
        .collect())
}

pub fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse JSON {}", path.display()))
}

pub fn read_public_text_file(path: &Path) -> Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

pub fn read_text_file(path: &Path) -> Result<String> {
    check_owner_only(path)?;
    std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

pub fn read_hex_or_file(
    value: &Option<String>,
    path: &Option<std::path::PathBuf>,
) -> Result<String> {
    match (value, path) {
        (Some(_), Some(_)) => bail!("provide either hex value or file, not both"),
        (Some(value), None) => Ok(value.trim().to_string()),
        (None, Some(path)) => Ok(read_public_text_file(path)?.trim().to_string()),
        (None, None) => bail!("missing hex value or file"),
    }
}

pub fn now_millis() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before Unix epoch")?
        .as_millis() as u64)
}

pub fn check_owner_only(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "{} must not be readable, writable, or executable by group/other",
                path.display()
            );
        }
    }
    Ok(())
}

pub fn write_private_file(path: &Path, contents: &str, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!("refusing to overwrite existing file {}", path.display());
    }
    std::fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    set_private_permissions(path)
}

pub fn save_private(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("write {}", path.display()))?;
    set_private_permissions(path)
}

pub fn set_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set private permissions on {}", path.display()))?;
    }
    Ok(())
}
