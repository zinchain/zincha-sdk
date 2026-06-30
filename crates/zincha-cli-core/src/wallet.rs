use crate::output::emit;
use crate::secret::{
    load_password, load_secret_key, secret_to_keypair, KeySourceArgs, PasswordSourceArgs,
};
use crate::support::{
    parse_address, read_text_file, save_private, set_private_permissions, write_private_file,
};
use crate::CliContext;
use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::{Path, PathBuf};
use zincha_client::ZinchaClient;
use zincha_primitives::crypto::Keypair;
use zincha_primitives::wallet::keystore::KeystoreEntryOrigin;
use zincha_primitives::wallet::mnemonic::derive_keypair_from_mnemonic_phrase;
use zincha_primitives::wallet::Keystore;

#[derive(Debug, Parser)]
pub struct KeygenCommand {
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub force: bool,
    #[arg(long, conflicts_with = "out")]
    pub unsafe_print_secret: bool,
}

#[derive(Debug, Parser)]
pub struct FaucetCommand {
    #[arg(long)]
    pub address: String,
    #[arg(long)]
    pub amount_micro_zin: Option<u64>,
    #[arg(long)]
    pub amount_zin: Option<u64>,
}

#[derive(Debug, Parser)]
pub struct WalletCommand {
    #[command(subcommand)]
    pub command: WalletCommands,
}

#[derive(Debug, Subcommand)]
pub enum WalletCommands {
    Address {
        #[arg(long)]
        secret_key: String,
    },
    Inspect {
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long)]
        address: Option<String>,
    },
    Create {
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long, default_value = "default")]
        label: String,
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        password: PasswordSourceArgs,
    },
    Import {
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long, default_value = "imported")]
        label: String,
        #[arg(long, conflicts_with_all = ["key_file", "mnemonic", "mnemonic_file"])]
        secret_key: Option<String>,
        #[arg(long, conflicts_with_all = ["secret_key", "mnemonic", "mnemonic_file"])]
        key_file: Option<PathBuf>,
        #[arg(long, conflicts_with_all = ["secret_key", "key_file", "mnemonic_file"])]
        mnemonic: Option<String>,
        #[arg(long, conflicts_with_all = ["secret_key", "key_file", "mnemonic"])]
        mnemonic_file: Option<PathBuf>,
        #[arg(long, default_value = "")]
        mnemonic_passphrase: String,
        #[arg(long)]
        derivation_path: Option<String>,
        #[command(flatten)]
        password: PasswordSourceArgs,
    },
    List {
        #[arg(long)]
        keystore: PathBuf,
    },
    Relabel {
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long)]
        address: String,
        #[arg(long)]
        label: String,
    },
    Export {
        #[command(flatten)]
        key_source: KeySourceArgs,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        unsafe_print_secret: bool,
        #[arg(long)]
        force: bool,
    },
    Remove {
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long)]
        address: String,
    },
    ChangePassword {
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long)]
        address: String,
        #[arg(long)]
        new_password_file: Option<PathBuf>,
        #[arg(long)]
        new_password_env: Option<String>,
        #[command(flatten)]
        password: PasswordSourceArgs,
    },
}

pub fn run_keygen(command: KeygenCommand, context: &CliContext) -> Result<()> {
    let keypair = Keypair::generate();
    if let Some(path) = command.out.as_ref() {
        write_private_file(path, &hex::encode(keypair.secret_bytes()), command.force)?;
    }
    emit(
        "keygen",
        json!({
            "address": keypair.address().to_string(),
            "public_key": hex::encode(keypair.public_key().as_bytes()),
            "secret_file": command.out.as_ref().map(|path| path.display().to_string()),
            "secret_key": command.unsafe_print_secret.then(|| hex::encode(keypair.secret_bytes())),
        }),
        context.json,
    )
}

pub fn run_wallet(command: WalletCommand, context: &CliContext) -> Result<()> {
    match command.command {
        WalletCommands::Address { secret_key } => {
            let keypair = load_secret_key(&secret_key)?;
            emit_keypair("wallet-address", &keypair, context)
        }
        WalletCommands::Inspect { keystore, address } => {
            let keystore = load_keystore(&keystore)?;
            let entries = match address {
                Some(address) => {
                    let address = parse_address(&address)?;
                    let entry = keystore.entry(&address).ok_or_else(|| {
                        anyhow::anyhow!("address {address} not found in keystore")
                    })?;
                    vec![entry_to_json(entry)]
                }
                None => keystore.entries().iter().map(entry_to_json).collect(),
            };
            emit(
                "wallet-inspect",
                json!({ "entries": entries }),
                context.json,
            )
        }
        WalletCommands::Create {
            keystore,
            label,
            force,
            password,
        } => {
            if keystore.exists() && !force {
                bail!(
                    "refusing to overwrite existing keystore {}",
                    keystore.display()
                );
            }
            let mut store = Keystore::new();
            let password = load_password(&password, "New keystore password")?;
            let address = store.create_key(&password, &label)?;
            save_keystore(&store, &keystore)?;
            emit(
                "wallet-create",
                json!({ "keystore": keystore.display().to_string(), "address": address.to_string(), "label": label }),
                context.json,
            )
        }
        WalletCommands::Import {
            keystore,
            label,
            secret_key,
            key_file,
            mnemonic,
            mnemonic_file,
            mnemonic_passphrase,
            derivation_path,
            password,
        } => {
            let mut store = load_or_new_keystore(&keystore)?;
            let password = load_password(&password, "Keystore password")?;
            let (keypair, origin, path_meta) = resolve_import_keypair(
                secret_key,
                key_file,
                mnemonic,
                mnemonic_file,
                &mnemonic_passphrase,
                derivation_path,
            )?;
            let address = keypair.address();
            store.import_key_with_origin(&keypair, &password, &label, origin, path_meta)?;
            save_keystore(&store, &keystore)?;
            emit(
                "wallet-import",
                json!({ "keystore": keystore.display().to_string(), "address": address.to_string(), "label": label }),
                context.json,
            )
        }
        WalletCommands::List { keystore } => {
            let store = load_keystore(&keystore)?;
            let entries: Vec<_> = store
                .list_addresses()
                .into_iter()
                .map(|(address, label)| json!({ "address": address.to_string(), "label": label }))
                .collect();
            emit(
                "wallet-list",
                json!({ "keystore": keystore.display().to_string(), "entries": entries }),
                context.json,
            )
        }
        WalletCommands::Relabel {
            keystore,
            address,
            label,
        } => {
            let mut store = load_keystore(&keystore)?;
            let address = parse_address(&address)?;
            store.relabel(&address, &label)?;
            save_keystore(&store, &keystore)?;
            emit(
                "wallet-relabel",
                json!({ "address": address.to_string(), "label": label }),
                context.json,
            )
        }
        WalletCommands::Export {
            key_source,
            out,
            unsafe_print_secret,
            force,
        } => {
            let keypair = crate::secret::load_keypair(&key_source)?;
            let secret = hex::encode(keypair.secret_bytes());
            if let Some(path) = out.as_ref() {
                write_private_file(path, &secret, force)?;
            }
            emit(
                "wallet-export",
                json!({
                    "address": keypair.address().to_string(),
                    "public_key": hex::encode(keypair.public_key().as_bytes()),
                    "secret_file": out.as_ref().map(|path| path.display().to_string()),
                    "secret_key": unsafe_print_secret.then_some(secret),
                }),
                context.json,
            )
        }
        WalletCommands::Remove { keystore, address } => {
            let mut store = load_keystore(&keystore)?;
            let address = parse_address(&address)?;
            if !store.remove(&address) {
                bail!("address {address} not found in keystore");
            }
            save_keystore(&store, &keystore)?;
            emit(
                "wallet-remove",
                json!({ "address": address.to_string(), "removed": true }),
                context.json,
            )
        }
        WalletCommands::ChangePassword {
            keystore,
            address,
            new_password_file,
            new_password_env,
            password,
        } => {
            let mut store = load_keystore(&keystore)?;
            let address = parse_address(&address)?;
            let current = load_password(&password, "Current keystore password")?;
            let new_password = load_password(
                &PasswordSourceArgs {
                    password_file: new_password_file,
                    password_env: new_password_env,
                },
                "New keystore password",
            )?;
            let outcome = store.change_entry_password(&address, &current, &new_password)?;
            save_keystore(&store, &keystore)?;
            emit(
                "wallet-change-password",
                json!({
                    "address": address.to_string(),
                    "password_changed": outcome.password_changed,
                    "kdf_after": format!("{:?}", outcome.kdf_after),
                    "cipher_after": format!("{:?}", outcome.cipher_after),
                }),
                context.json,
            )
        }
    }
}

pub async fn run_faucet(
    command: FaucetCommand,
    client: ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    emit(
        "faucet",
        client
            .request_faucet(
                &command.address,
                command.amount_micro_zin,
                command.amount_zin,
            )
            .await?,
        context.json,
    )
}

fn emit_keypair(command: &'static str, keypair: &Keypair, context: &CliContext) -> Result<()> {
    emit(
        command,
        json!({
            "address": keypair.address().to_string(),
            "public_key": hex::encode(keypair.public_key().as_bytes()),
        }),
        context.json,
    )
}

fn load_keystore(path: &Path) -> Result<Keystore> {
    crate::support::check_owner_only(path)?;
    Keystore::load(path).with_context(|| format!("load {}", path.display()))
}

fn load_or_new_keystore(path: &Path) -> Result<Keystore> {
    if path.exists() {
        load_keystore(path)
    } else {
        Ok(Keystore::new())
    }
}

fn save_keystore(store: &Keystore, path: &Path) -> Result<()> {
    let json = store.to_json_pretty()?;
    save_private(path, &json)?;
    set_private_permissions(path)
}

fn resolve_import_keypair(
    secret_key: Option<String>,
    key_file: Option<PathBuf>,
    mnemonic: Option<String>,
    mnemonic_file: Option<PathBuf>,
    mnemonic_passphrase: &str,
    derivation_path: Option<String>,
) -> Result<(Keypair, KeystoreEntryOrigin, Option<String>)> {
    match (secret_key, key_file, mnemonic, mnemonic_file) {
        (Some(secret), None, None, None) => Ok((
            secret_to_keypair(&secret)?,
            KeystoreEntryOrigin::RawSecretFile,
            None,
        )),
        (None, Some(path), None, None) => Ok((
            secret_to_keypair(read_text_file(&path)?.trim())?,
            KeystoreEntryOrigin::RawSecretFile,
            None,
        )),
        (None, None, Some(phrase), None) => {
            let derived = derive_keypair_from_mnemonic_phrase(
                &phrase,
                mnemonic_passphrase,
                derivation_path.as_deref(),
            )?;
            Ok((
                derived.keypair,
                KeystoreEntryOrigin::Mnemonic,
                Some(derived.derivation_path),
            ))
        }
        (None, None, None, Some(path)) => {
            let phrase = read_text_file(&path)?;
            let derived = derive_keypair_from_mnemonic_phrase(
                &phrase,
                mnemonic_passphrase,
                derivation_path.as_deref(),
            )?;
            Ok((
                derived.keypair,
                KeystoreEntryOrigin::Mnemonic,
                Some(derived.derivation_path),
            ))
        }
        _ => bail!("provide exactly one import key source"),
    }
}

fn entry_to_json(entry: &zincha_primitives::wallet::keystore::KeystoreEntry) -> serde_json::Value {
    json!({
        "address": entry.address.to_string(),
        "label": entry.label,
        "created_at": entry.created_at,
        "origin": format!("{:?}", entry.origin),
        "derivation_path": entry.derivation_path,
        "kdf": format!("{:?}", entry.kdf),
        "cipher": format!("{:?}", entry.cipher),
    })
}
