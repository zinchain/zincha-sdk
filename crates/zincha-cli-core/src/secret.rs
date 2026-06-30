use crate::support::{check_owner_only, parse_address, read_text_file};
use anyhow::{bail, Context, Result};
use clap::Args;
use std::env;
use std::io::IsTerminal;
use std::path::PathBuf;
use zincha_primitives::crypto::{Address, Keypair};
use zincha_primitives::wallet::Keystore;

#[derive(Args, Clone, Debug, Default)]
pub struct PasswordSourceArgs {
    #[arg(long)]
    pub password_file: Option<PathBuf>,
    #[arg(long)]
    pub password_env: Option<String>,
}

#[derive(Args, Clone, Debug, Default)]
pub struct KeySourceArgs {
    #[arg(long, conflicts_with_all = ["key_file", "keystore"])]
    pub secret_key: Option<String>,
    #[arg(long, conflicts_with_all = ["secret_key", "keystore"])]
    pub key_file: Option<PathBuf>,
    #[arg(long, conflicts_with_all = ["secret_key", "key_file"])]
    pub keystore: Option<PathBuf>,
    #[arg(long, requires = "keystore")]
    pub keystore_address: Option<String>,
    #[command(flatten)]
    pub password: PasswordSourceArgs,
}

pub fn load_keypair(args: &KeySourceArgs) -> Result<Keypair> {
    match (&args.secret_key, &args.key_file, &args.keystore) {
        (Some(raw), None, None) => load_secret_key(raw),
        (None, Some(path), None) => {
            let secret = read_text_file(path)?;
            secret_to_keypair(secret.trim())
        }
        (None, None, Some(path)) => {
            check_owner_only(path)?;
            let address = parse_keystore_address(args.keystore_address.as_deref())?;
            let password = load_password(&args.password, "Keystore password")?;
            let keystore =
                Keystore::load(path).with_context(|| format!("load {}", path.display()))?;
            keystore
                .unlock(&address, &password)
                .with_context(|| format!("unlock keystore entry {address}"))
        }
        _ => bail!("provide one key source: --secret-key, --key-file, or --keystore"),
    }
}

pub fn load_secret_key(raw: &str) -> Result<Keypair> {
    if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return secret_to_keypair(raw);
    }
    let path = PathBuf::from(raw);
    let secret = read_text_file(&path)?;
    secret_to_keypair(secret.trim())
}

pub fn secret_to_keypair(secret: &str) -> Result<Keypair> {
    let bytes = hex::decode(secret).context("decode secret key hex")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("secret key must be 32 bytes"))?;
    Ok(Keypair::from_secret_bytes(&bytes))
}

pub fn parse_keystore_address(raw: Option<&str>) -> Result<Address> {
    let raw =
        raw.ok_or_else(|| anyhow::anyhow!("--keystore-address is required with --keystore"))?;
    parse_address(raw)
}

pub fn load_password(args: &PasswordSourceArgs, prompt: &str) -> Result<String> {
    match (&args.password_file, &args.password_env) {
        (Some(_), Some(_)) => bail!("provide either --password-file or --password-env, not both"),
        (Some(path), None) => Ok(read_text_file(path)?
            .trim_end_matches(['\r', '\n'])
            .to_string()),
        (None, Some(name)) => env::var(name).with_context(|| format!("read password env {name}")),
        (None, None) => {
            if std::io::stdin().is_terminal() {
                rpassword::prompt_password(format!("{prompt}: ")).context("read password")
            } else {
                bail!("password source required in non-TTY mode; use --password-file or --password-env")
            }
        }
    }
}
