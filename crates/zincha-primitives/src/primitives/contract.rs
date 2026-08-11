use std::collections::{BTreeMap, HashMap, HashSet};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{hash_bytes, Address, Hash256};

pub const CONTRACT_UPGRADE_UNSUPPORTED_MSG: &str =
    "ContractUpgrade is not supported; deploy a new contract address and retarget callers/tools";

pub const CONTRACT_SOURCE_VERIFICATION_UNSUPPORTED_MSG: &str =
    "Reproducible contract source verification currently supports WAT, authenticated Rust source bundles, and authenticated AssemblyScript source bundles with canonical build recipes and authenticated WAT bytecode witnesses";
pub const CONTRACT_ROUTE_SCHEME: &str = "contractref://";
pub const CONTRACT_PLATFORM_PROFILE_VERSION: u32 = 1;
pub const CONTRACT_VM_PROFILE_ID: &str = "zincha-wasm-int-v1";
pub const CONTRACT_VM_PROFILE_VERSION: u32 = 1;
pub const CONTRACT_FIXED_POINT_SCALE: i64 = 1_000_000;

pub const CONTRACT_WASM_FEATURES: &[&str] = &[
    "mvp",
    "mutable-global",
    "sign-extension",
    "multi-value",
    "bulk-memory",
    "integer-only",
    "no-floats",
    "no-simd",
    "no-threads",
    "no-reference-types",
    "no-memory64",
    "no-component-model",
];

/// Maximum exported callable functions committed for a contract.
pub const MAX_CONTRACT_CALLABLE_EXPORTS: usize = 256;

/// Maximum UTF-8 byte length of a callable export name.
pub const MAX_CONTRACT_EXPORT_NAME_BYTES: usize = 128;

pub const CONTRACT_HOST_FUNCTIONS: &[&str] = &[
    "host_block_height",
    "host_block_timestamp",
    "host_call_value",
    "host_tool_nominal_price",
    "host_tool_subscription_covered_amount",
    "host_gas_remaining",
    "host_caller",
    "host_origin",
    "host_self_address",
    "host_get_balance",
    "host_get_nonce",
    "host_transfer",
    "host_storage_set",
    "host_storage_get",
    "host_storage_delete",
    "host_sha256",
    "host_blake3",
    "host_verify_signature",
    "host_chain_id",
    "host_address_from_pubkey",
    "host_emit_event",
    "host_caller_is_agent",
    "host_caller_reputation_micros",
    "host_get_reputation_score_micros",
    "host_get_effective_reputation_micros",
    "host_get_reputation_details_fixed",
    "host_agent_has_capability",
    "host_get_requester_reputation_details_fixed",
    "host_get_agent",
    "host_get_agent_capabilities",
    "host_get_task",
    "host_get_agreement",
    "host_get_tool",
    "host_search_tools",
    "host_get_task_status",
    "host_is_task_fulfilled",
    "host_get_agreement_status",
    "host_get_tool_reputation_fixed",
    "host_get_arbitrator_fixed",
    "host_call_contract",
    "host_tool_invoke",
    "host_token_balance",
    "host_token_allowance",
    "host_token_total_supply",
    "host_token_metadata",
    "host_token_transfer",
    "host_token_transfer_from",
    "host_token_mint",
    "host_token_burn",
    "host_token_approve",
];

/// Maximum supported route alias length.
pub const MAX_CONTRACT_ROUTE_NAME_BYTES: usize = 64;

/// Maximum supported canonical/source payload for a verified contract source.
pub const MAX_CONTRACT_SOURCE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum supported canonical ABI payload for an authenticated contract ABI.
pub const MAX_CONTRACT_ABI_BYTES: usize = 256 * 1024;

/// Source language accepted by the reproducible verification pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractSourceLanguage {
    Wat,
    Rust,
    #[serde(rename = "assemblyscript")]
    AssemblyScript,
}

/// Machine-readable summary of a supported provenance backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVerificationBackendCapability {
    /// Accepted source language / backend key.
    pub language: ContractSourceLanguage,
    /// Whether the published source itself directly reproduces the deployed
    /// bytecode, without a separate bytecode witness.
    pub direct_bytecode_reproduction: bool,
    /// Whether verification requires an authenticated bytecode witness.
    pub requires_bytecode_witness: bool,
    /// Whether verification requires an authenticated higher-level build recipe.
    pub requires_build_recipe: bool,
}

/// Machine-readable summary of the supported upgrade lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractUpgradePolicy {
    /// Same-address bytecode mutation is intentionally unsupported.
    pub same_address_upgrades_supported: bool,
    /// Supported rollout path: deploy a new immutable address.
    pub immutable_replacement_supported: bool,
    /// Stable route aliases can be retargeted to a new immutable address.
    pub stable_route_aliases_supported: bool,
    /// Stable route alias scheme for direct callers and tools.
    pub route_scheme: String,
}

/// Machine-readable contract platform scope for clients and tooling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractPlatformCapabilities {
    /// Monotonic version of the supported contract platform profile.
    pub profile_version: u32,
    /// Deterministic fingerprint of the advertised contract platform profile.
    pub profile_id: String,
    /// Consensus Wasm VM profile selected by this chain binary.
    pub contract_vm_profile_id: String,
    /// Monotonic version of the consensus Wasm VM profile.
    pub contract_vm_profile_version: u32,
    /// Consensus contract execution accepts integer-only Wasm modules.
    pub integer_only: bool,
    /// Fixed-point scale used by host APIs that expose scores, rates, and thresholds.
    pub fixed_point_scale: i64,
    /// Explicit Wasm feature profile advertised to contract toolchains.
    pub wasm_features: Vec<String>,
    /// Host imports available to consensus contracts.
    pub host_functions: Vec<String>,
    pub max_contract_bytes: usize,
    pub max_storage_value_bytes: usize,
    pub max_storage_per_contract_bytes: usize,
    pub max_call_depth: u32,
    pub upgrade_policy: ContractUpgradePolicy,
    pub supported_verification_backends: Vec<ContractVerificationBackendCapability>,
}

fn contract_platform_scope_components() -> (
    Vec<String>,
    Vec<String>,
    ContractUpgradePolicy,
    Vec<ContractVerificationBackendCapability>,
) {
    (
        CONTRACT_WASM_FEATURES
            .iter()
            .map(|feature| (*feature).to_string())
            .collect(),
        CONTRACT_HOST_FUNCTIONS
            .iter()
            .map(|function| (*function).to_string())
            .collect(),
        ContractUpgradePolicy {
            same_address_upgrades_supported: false,
            immutable_replacement_supported: true,
            stable_route_aliases_supported: true,
            route_scheme: CONTRACT_ROUTE_SCHEME.to_string(),
        },
        supported_contract_verification_backends(),
    )
}

fn compute_contract_platform_profile_id(
    wasm_features: &[String],
    host_functions: &[String],
    upgrade_policy: &ContractUpgradePolicy,
    supported_verification_backends: &[ContractVerificationBackendCapability],
) -> String {
    #[derive(Serialize)]
    struct ContractPlatformProfileFingerprint<'a> {
        profile_version: u32,
        contract_vm_profile_id: &'static str,
        contract_vm_profile_version: u32,
        integer_only: bool,
        fixed_point_scale: i64,
        wasm_features: &'a [String],
        host_functions: &'a [String],
        max_contract_bytes: usize,
        max_storage_value_bytes: usize,
        max_storage_per_contract_bytes: usize,
        max_call_depth: u32,
        upgrade_policy: &'a ContractUpgradePolicy,
        supported_verification_backends: &'a [ContractVerificationBackendCapability],
    }

    let encoded = bincode::serialize(&ContractPlatformProfileFingerprint {
        profile_version: CONTRACT_PLATFORM_PROFILE_VERSION,
        contract_vm_profile_id: CONTRACT_VM_PROFILE_ID,
        contract_vm_profile_version: CONTRACT_VM_PROFILE_VERSION,
        integer_only: true,
        fixed_point_scale: CONTRACT_FIXED_POINT_SCALE,
        wasm_features,
        host_functions,
        max_contract_bytes: MAX_CONTRACT_BYTECODE,
        max_storage_value_bytes: MAX_STORAGE_VALUE,
        max_storage_per_contract_bytes: MAX_STORAGE_TOTAL,
        max_call_depth: MAX_CALL_DEPTH,
        upgrade_policy,
        supported_verification_backends,
    })
    .expect("contract platform profile fingerprint must serialize");
    hash_bytes(&encoded).to_hex()
}

pub fn supported_contract_verification_backends() -> Vec<ContractVerificationBackendCapability> {
    vec![
        ContractVerificationBackendCapability {
            language: ContractSourceLanguage::Wat,
            direct_bytecode_reproduction: true,
            requires_bytecode_witness: false,
            requires_build_recipe: false,
        },
        ContractVerificationBackendCapability {
            language: ContractSourceLanguage::Rust,
            direct_bytecode_reproduction: false,
            requires_bytecode_witness: true,
            requires_build_recipe: true,
        },
        ContractVerificationBackendCapability {
            language: ContractSourceLanguage::AssemblyScript,
            direct_bytecode_reproduction: false,
            requires_bytecode_witness: true,
            requires_build_recipe: true,
        },
    ]
}

pub fn contract_platform_capabilities() -> ContractPlatformCapabilities {
    let (wasm_features, host_functions, upgrade_policy, supported_verification_backends) =
        contract_platform_scope_components();
    let profile_id = compute_contract_platform_profile_id(
        &wasm_features,
        &host_functions,
        &upgrade_policy,
        &supported_verification_backends,
    );
    ContractPlatformCapabilities {
        profile_version: CONTRACT_PLATFORM_PROFILE_VERSION,
        profile_id,
        contract_vm_profile_id: CONTRACT_VM_PROFILE_ID.to_string(),
        contract_vm_profile_version: CONTRACT_VM_PROFILE_VERSION,
        integer_only: true,
        fixed_point_scale: CONTRACT_FIXED_POINT_SCALE,
        wasm_features,
        host_functions,
        max_contract_bytes: MAX_CONTRACT_BYTECODE,
        max_storage_value_bytes: MAX_STORAGE_VALUE,
        max_storage_per_contract_bytes: MAX_STORAGE_TOTAL,
        max_call_depth: MAX_CALL_DEPTH,
        upgrade_policy,
        supported_verification_backends,
    }
}

/// Canonical, authenticated summary committed in the contract trie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractVerificationRecord {
    /// Verification backend / accepted source language.
    pub language: ContractSourceLanguage,
    /// Normalized compiler/toolchain label authenticated by the canonical
    /// verification record.
    #[serde(default)]
    pub compiler: String,
    /// Hash of the canonical published source text.
    pub source_hash: Hash256,
    /// Hash of an authenticated bytecode reproduction witness, if the backend
    /// uses one. For Rust and AssemblyScript source bundles this is the
    /// canonical WAT witness that reproduced the deployed bytecode.
    #[serde(default)]
    pub bytecode_witness_hash: Option<Hash256>,
    /// Hash of an authenticated higher-level build recipe, when the backend
    /// uses one. For Rust and AssemblyScript source bundles this binds the
    /// canonical compiler and build projection used for provenance.
    #[serde(default)]
    pub build_recipe_hash: Option<Hash256>,
    /// Block height at which the verification record became canonical.
    pub verified_at_block: u64,
}

/// User-submitted source proof for deterministic verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractSourceProof {
    /// Accepted source language.
    pub language: ContractSourceLanguage,
    /// Optional toolchain label kept for transparency in the published source.
    #[serde(default)]
    pub compiler: String,
    /// Source text submitted for reproducible verification.
    pub source_code: String,
    /// Optional bytecode reproduction witness. For Rust source bundles this
    /// and AssemblyScript source bundles this must be WAT that
    /// deterministically reproduces the deployed bytecode.
    #[serde(default)]
    pub bytecode_witness: Option<String>,
}

/// Canonical published source persisted off-trie for API serving and snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedContractSource {
    /// Accepted source language.
    pub language: ContractSourceLanguage,
    /// Optional compiler/toolchain label provided by the publisher.
    #[serde(default)]
    pub compiler: String,
    /// Canonical source text. For WAT verification this is the canonical
    /// wasmprinter rendering of the deployed bytecode. For Rust and
    /// AssemblyScript verification this is the canonical JSON source bundle.
    pub source_code: String,
    /// Hash of `source_code`.
    pub source_hash: Hash256,
    /// Canonical authenticated bytecode reproduction witness, if one exists.
    /// For Rust and AssemblyScript verification this is the canonical WAT
    /// witness that reproduced the deployed bytecode.
    #[serde(default)]
    pub bytecode_witness: Option<String>,
    /// Hash of `bytecode_witness`, when present.
    #[serde(default)]
    pub bytecode_witness_hash: Option<Hash256>,
    /// Canonical authenticated higher-level build recipe, when one exists.
    /// For Rust and AssemblyScript verification this captures the canonical
    /// higher-level build projection that the provenance model authenticates.
    #[serde(default)]
    pub build_recipe: Option<String>,
    /// Hash of `build_recipe`, when present.
    #[serde(default)]
    pub build_recipe_hash: Option<Hash256>,
    /// Bytecode hash this source was verified against.
    pub bytecode_hash: Hash256,
}

/// Consensus-committed callable export metadata for deployed contract bytecode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractExportMetadata {
    pub profile_id: String,
    pub profile_version: u32,
    pub bytecode_hash: Hash256,
    pub has_memory_export: bool,
    pub callable_exports: Vec<String>,
    pub callable_exports_hash: Hash256,
}

impl ContractExportMetadata {
    pub fn new(
        bytecode_hash: Hash256,
        has_memory_export: bool,
        mut callable_exports: Vec<String>,
    ) -> std::result::Result<Self, String> {
        callable_exports.sort();
        callable_exports.dedup();
        let callable_exports_hash = hash_callable_exports(&callable_exports)?;
        let metadata = Self {
            profile_id: CONTRACT_VM_PROFILE_ID.to_string(),
            profile_version: CONTRACT_VM_PROFILE_VERSION,
            bytecode_hash,
            has_memory_export,
            callable_exports,
            callable_exports_hash,
        };
        metadata.validate_for_bytecode_hash(bytecode_hash)?;
        Ok(metadata)
    }

    pub fn empty_for_bytecode_hash(bytecode_hash: Hash256) -> Self {
        Self {
            profile_id: CONTRACT_VM_PROFILE_ID.to_string(),
            profile_version: CONTRACT_VM_PROFILE_VERSION,
            bytecode_hash,
            has_memory_export: false,
            callable_exports: Vec::new(),
            callable_exports_hash: hash_callable_exports(&Vec::new())
                .expect("empty callable export set should hash"),
        }
    }

    pub fn callable(&self, function: &str) -> bool {
        self.has_memory_export
            && !function.is_empty()
            && self
                .callable_exports
                .binary_search_by(|candidate| candidate.as_str().cmp(function))
                .is_ok()
    }

    pub fn validate_for_bytecode_hash(
        &self,
        expected_bytecode_hash: Hash256,
    ) -> std::result::Result<(), String> {
        if self.profile_id != CONTRACT_VM_PROFILE_ID {
            return Err(format!(
                "Contract export metadata profile_id {} does not match {}",
                self.profile_id, CONTRACT_VM_PROFILE_ID
            ));
        }
        if self.profile_version != CONTRACT_VM_PROFILE_VERSION {
            return Err(format!(
                "Contract export metadata profile_version {} does not match {}",
                self.profile_version, CONTRACT_VM_PROFILE_VERSION
            ));
        }
        if self.bytecode_hash != expected_bytecode_hash {
            return Err(format!(
                "Contract export metadata bytecode_hash {} does not match record bytecode_hash {}",
                self.bytecode_hash, expected_bytecode_hash
            ));
        }
        if self.callable_exports.len() > MAX_CONTRACT_CALLABLE_EXPORTS {
            return Err(format!(
                "Contract export metadata has {} callable exports, exceeding {}",
                self.callable_exports.len(),
                MAX_CONTRACT_CALLABLE_EXPORTS
            ));
        }
        for export in &self.callable_exports {
            if export.is_empty() {
                return Err("Contract export metadata contains an empty export name".to_string());
            }
            if export.len() > MAX_CONTRACT_EXPORT_NAME_BYTES {
                return Err(format!(
                    "Contract export metadata export '{}' exceeds {} bytes",
                    export, MAX_CONTRACT_EXPORT_NAME_BYTES
                ));
            }
        }
        if self
            .callable_exports
            .windows(2)
            .any(|window| window[0] >= window[1])
        {
            return Err(
                "Contract export metadata callable exports must be sorted and unique".to_string(),
            );
        }
        let expected_hash = hash_callable_exports(&self.callable_exports)?;
        if self.callable_exports_hash != expected_hash {
            return Err(format!(
                "Contract export metadata callable_exports_hash {} does not match {}",
                self.callable_exports_hash, expected_hash
            ));
        }
        Ok(())
    }
}

pub fn hash_callable_exports(callable_exports: &[String]) -> std::result::Result<Hash256, String> {
    bincode::serialize(callable_exports)
        .map(|encoded| hash_bytes(&encoded))
        .map_err(|error| format!("Contract callable exports could not be hashed: {error}"))
}

/// On-chain record for a deployed smart contract.
#[derive(Debug, Clone)]
pub struct ContractRecord {
    /// Unique contract address: hash(deployer + nonce + bytecode_hash).
    pub address: Address,
    /// The address that deployed this immutable contract release.
    pub deployer: Address,
    /// SHA-256 hash of the WASM bytecode.
    pub bytecode_hash: Hash256,
    /// Deterministic callable export metadata authenticated with contract state.
    pub export_metadata: ContractExportMetadata,
    /// Block at which the contract was first deployed.
    pub created_at_block: u64,
    /// Block of the most recent metadata mutation for this immutable contract
    /// record (same as created_at_block if unchanged since deploy).
    pub updated_at_block: u64,
    /// Whether the contract is active and callable.
    pub is_active: bool,
    /// Published authenticated ABI (function signatures).
    ///
    /// When present, `abi_hash` must also be present and match the
    /// serialized ABI bytes.
    pub abi: Option<ContractAbi>,
    /// Hash of the published authenticated ABI payload, when one exists.
    pub abi_hash: Option<Hash256>,
    /// Source code verification status.
    pub verified: bool,
    /// Hash of verified source code (if verified).
    pub source_hash: Option<Hash256>,
    /// Authenticated verification summary committed under `state_root`.
    pub verification: Option<ContractVerificationRecord>,
    /// Storage deposit locked for the retained contract metadata row,
    /// including authenticated ABI payloads committed on-chain.
    ///
    /// This remains locked as long as the contract record is durably retained,
    /// including after contract deactivation.
    pub storage_deposit: u64,
    /// Storage deposit locked for the persisted canonical verified source
    /// payload served via `/v1/contracts/:address/source`.
    ///
    /// This remains locked as long as the authenticated source provenance is
    /// retained for the contract, including after contract deactivation.
    pub verified_source_storage_deposit: u64,
    /// Total bytes currently stored in this contract's key-value storage.
    /// Computed from the contract's logical keys and values, not RocksDB overhead.
    pub storage_bytes: u64,
    /// Storage reserve locked against dynamic contract KV growth (micro-ZIN).
    /// Increased/decreased as the contract's storage footprint changes.
    pub storage_reserve: u64,
    /// Authenticated hash of the contract's logical key-value storage.
    ///
    /// This is committed under `state_root` and must match any exported or
    /// restored contract storage projection.
    pub storage_root: Hash256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContractRecordWire {
    pub address: Address,
    pub deployer: Address,
    pub bytecode_hash: Hash256,
    pub export_metadata: ContractExportMetadata,
    pub created_at_block: u64,
    pub updated_at_block: u64,
    pub is_active: bool,
    #[serde(default)]
    pub abi: Option<ContractAbi>,
    #[serde(default)]
    pub abi_hash: Option<Hash256>,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub source_hash: Option<Hash256>,
    #[serde(default)]
    pub verification: Option<ContractVerificationRecord>,
    #[serde(default)]
    pub storage_deposit: u64,
    #[serde(default)]
    pub verified_source_storage_deposit: u64,
    #[serde(default)]
    pub storage_bytes: u64,
    #[serde(default)]
    pub storage_reserve: u64,
    #[serde(default)]
    pub storage_root: Hash256,
}

/// Contract ABI — describes the functions a contract exports.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractAbi {
    /// Contract name (human-readable).
    pub name: String,
    /// Version string (e.g. "1.0.0").
    pub version: String,
    /// Exported functions.
    pub functions: Vec<FunctionSignature>,
}

/// Stable deployer-owned route key for immutable contract releases.
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContractRouteKey {
    pub deployer: Address,
    pub route_name: String,
}

impl ContractRouteKey {
    pub fn new(
        deployer: Address,
        route_name: impl Into<String>,
    ) -> std::result::Result<Self, String> {
        let route_name = route_name.into();
        Ok(Self {
            deployer,
            route_name: validate_and_normalize_contract_route_name(&route_name)?,
        })
    }
}

/// Stable alias pointing at the current immutable contract release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractRouteRecord {
    pub deployer: Address,
    pub route_name: String,
    pub target_contract_address: Address,
    /// Monotonic route revision counter. Incremented whenever the route target changes.
    pub revision: u32,
    pub created_at_block: u64,
    pub updated_at_block: u64,
    #[serde(default)]
    pub storage_deposit: u64,
}

impl ContractRecord {
    pub fn validate_export_metadata_state(&self) -> std::result::Result<(), String> {
        self.export_metadata
            .validate_for_bytecode_hash(self.bytecode_hash)
    }

    pub fn validate_canonical_abi_state(&self) -> std::result::Result<(), String> {
        match (&self.abi, self.abi_hash) {
            (None, None) => Ok(()),
            (Some(abi), Some(abi_hash)) => {
                let computed = hash_contract_abi(abi)
                    .ok_or_else(|| "Contract ABI could not be canonically hashed".to_string())?;
                if computed == abi_hash {
                    Ok(())
                } else {
                    Err(format!(
                        "Contract {} carries an ABI payload that does not match its committed abi_hash",
                        self.address
                    ))
                }
            }
            (Some(_), None) => Err(format!(
                "Contract {} carries an ABI payload without a committed abi_hash",
                self.address
            )),
            (None, Some(_)) => Err(format!(
                "Contract {} carries an abi_hash without a matching ABI payload",
                self.address
            )),
        }
    }

    pub fn authenticated_abi(&self) -> Option<&ContractAbi> {
        self.validate_canonical_abi_state().ok()?;
        self.abi.as_ref()
    }

    pub fn set_authenticated_abi(
        &mut self,
        abi: ContractAbi,
    ) -> std::result::Result<Hash256, String> {
        let abi_hash = hash_contract_abi(&abi)
            .ok_or_else(|| "Contract ABI could not be canonically hashed".to_string())?;
        self.abi = Some(abi);
        self.abi_hash = Some(abi_hash);
        Ok(abi_hash)
    }
}

impl From<ContractRecordWire> for ContractRecord {
    fn from(wire: ContractRecordWire) -> Self {
        Self {
            address: wire.address,
            deployer: wire.deployer,
            bytecode_hash: wire.bytecode_hash,
            export_metadata: wire.export_metadata,
            created_at_block: wire.created_at_block,
            updated_at_block: wire.updated_at_block,
            is_active: wire.is_active,
            abi: wire.abi,
            abi_hash: wire.abi_hash,
            verified: wire.verified,
            source_hash: wire.source_hash,
            verification: wire.verification,
            storage_deposit: wire.storage_deposit,
            verified_source_storage_deposit: wire.verified_source_storage_deposit,
            storage_bytes: wire.storage_bytes,
            storage_reserve: wire.storage_reserve,
            storage_root: wire.storage_root,
        }
    }
}

impl From<&ContractRecord> for ContractRecordWire {
    fn from(record: &ContractRecord) -> Self {
        Self {
            address: record.address.clone(),
            deployer: record.deployer.clone(),
            bytecode_hash: record.bytecode_hash,
            export_metadata: record.export_metadata.clone(),
            created_at_block: record.created_at_block,
            updated_at_block: record.updated_at_block,
            is_active: record.is_active,
            abi: record.abi.clone(),
            abi_hash: record.abi_hash,
            verified: record.verified,
            source_hash: record.source_hash,
            verification: record.verification.clone(),
            storage_deposit: record.storage_deposit,
            verified_source_storage_deposit: record.verified_source_storage_deposit,
            storage_bytes: record.storage_bytes,
            storage_reserve: record.storage_reserve,
            storage_root: record.storage_root,
        }
    }
}

impl Serialize for ContractRecord {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.validate_export_metadata_state()
            .map_err(serde::ser::Error::custom)?;
        self.validate_canonical_abi_state()
            .map_err(serde::ser::Error::custom)?;
        ContractRecordWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ContractRecord {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let record = ContractRecord::from(ContractRecordWire::deserialize(deserializer)?);
        record
            .validate_export_metadata_state()
            .map_err(serde::de::Error::custom)?;
        record
            .validate_canonical_abi_state()
            .map_err(serde::de::Error::custom)?;
        Ok(record)
    }
}

pub fn compute_contract_storage_root(storage: &BTreeMap<Vec<u8>, Vec<u8>>) -> Hash256 {
    if storage.is_empty() {
        return Hash256::zero();
    }

    let encoded = bincode::serialize(storage)
        .unwrap_or_else(|err| panic!("contract storage root serialization failed: {err}"));
    hash_bytes(&encoded)
}

pub fn compute_contract_storage_root_from_hash_map(storage: &HashMap<Vec<u8>, Vec<u8>>) -> Hash256 {
    if storage.is_empty() {
        return Hash256::zero();
    }

    let ordered: BTreeMap<Vec<u8>, Vec<u8>> = storage
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    compute_contract_storage_root(&ordered)
}

pub fn contract_storage_total_bytes(storage: &BTreeMap<Vec<u8>, Vec<u8>>) -> u64 {
    storage
        .iter()
        .map(|(key, value)| key.len().saturating_add(value.len()) as u64)
        .sum()
}

pub fn verify_contract_storage_projection(
    record: &ContractRecord,
    storage: Option<&BTreeMap<Vec<u8>, Vec<u8>>>,
) -> std::result::Result<(), String> {
    let actual_root = storage
        .map(compute_contract_storage_root)
        .unwrap_or_else(Hash256::zero);
    if record.storage_root != actual_root {
        return Err(format!(
            "contract {} storage_root mismatch: record commits {} but projection hashes to {}",
            record.address, record.storage_root, actual_root
        ));
    }

    let actual_bytes = storage.map(contract_storage_total_bytes).unwrap_or(0);
    if record.storage_bytes != actual_bytes {
        return Err(format!(
            "contract {} storage_bytes mismatch: record commits {} but projection contains {}",
            record.address, record.storage_bytes, actual_bytes
        ));
    }

    Ok(())
}

pub fn sort_contract_events_canonically(events: &mut [ContractEvent]) {
    events.sort_by(|a, b| {
        a.block_number
            .cmp(&b.block_number)
            .then_with(|| a.contract_address.cmp(&b.contract_address))
            .then_with(|| a.log_index.cmp(&b.log_index))
            .then_with(|| a.tx_hash.cmp(&b.tx_hash))
            .then_with(|| a.topic.cmp(&b.topic))
            .then_with(|| a.data.cmp(&b.data))
    });
}

pub fn hash_contract_event(event: &ContractEvent) -> Hash256 {
    let encoded = bincode::serialize(event)
        .unwrap_or_else(|error| panic!("contract event serialization failed: {error}"));
    hash_bytes(&encoded)
}

pub fn compute_contract_event_block_root(events: &[ContractEvent]) -> Hash256 {
    if events.is_empty() {
        return Hash256::zero();
    }

    let mut sorted = events.to_vec();
    sorted.sort_by(|a, b| {
        a.contract_address
            .cmp(&b.contract_address)
            .then_with(|| a.log_index.cmp(&b.log_index))
            .then_with(|| a.tx_hash.cmp(&b.tx_hash))
            .then_with(|| a.topic.cmp(&b.topic))
            .then_with(|| a.data.cmp(&b.data))
    });
    let leaf_hashes: Vec<Hash256> = sorted.iter().map(hash_contract_event).collect();
    crate::crypto::MerkleTree::root_from_hashes_owned(leaf_hashes)
}

pub fn advance_contract_event_archive_accumulator(
    previous: Hash256,
    block_number: u64,
    block_events: &[ContractEvent],
) -> Hash256 {
    if block_events.is_empty() {
        return previous;
    }

    let block_root = compute_contract_event_block_root(block_events);
    let mut buffer = Vec::with_capacity(80);
    buffer.extend_from_slice(previous.as_bytes());
    buffer.extend_from_slice(&block_number.to_be_bytes());
    buffer.extend_from_slice(&(block_events.len() as u64).to_be_bytes());
    buffer.extend_from_slice(block_root.as_bytes());
    hash_bytes(&buffer)
}

pub fn compute_contract_event_archive_accumulator(events: &[ContractEvent]) -> Hash256 {
    if events.is_empty() {
        return Hash256::zero();
    }

    let mut sorted = events.to_vec();
    sort_contract_events_canonically(&mut sorted);

    let mut accumulator = Hash256::zero();
    let mut start = 0usize;
    while start < sorted.len() {
        let block_number = sorted[start].block_number;
        let mut end = start + 1;
        while end < sorted.len() && sorted[end].block_number == block_number {
            end += 1;
        }
        accumulator = advance_contract_event_archive_accumulator(
            accumulator,
            block_number,
            &sorted[start..end],
        );
        start = end;
    }

    accumulator
}

pub fn verify_contract_event_archive_accumulator(
    expected: Hash256,
    events: &[ContractEvent],
) -> std::result::Result<(), String> {
    let actual = compute_contract_event_archive_accumulator(events);
    if expected != actual {
        return Err(format!(
            "contract event archive accumulator mismatch: committed {} but projection hashes to {}",
            expected, actual
        ));
    }
    Ok(())
}

/// A single function signature in a contract ABI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Function name (must match the WASM export name).
    pub name: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Input parameters.
    pub params: Vec<AbiParam>,
    /// Return type description.
    #[serde(default)]
    pub returns: Vec<AbiParam>,
    /// Whether this function modifies state (false = read-only / view).
    #[serde(default)]
    pub mutates: bool,
}

/// A parameter in a function signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbiParam {
    /// Parameter name.
    pub name: String,
    /// Type description (e.g. "u64", "Address", "Vec<u8>", "String").
    pub ty: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
}

/// Data payload for a ContractDeploy transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDeployData {
    /// WASM bytecode (max 1 MB).
    pub bytecode: Vec<u8>,
}

/// Data payload for a ContractVerify transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractVerifyData {
    /// Address of the deployed contract whose source is being published.
    pub contract_address: Address,
    /// Deterministic source proof to verify against deployed bytecode.
    pub proof: ContractSourceProof,
}

/// Data payload for a ContractPublishAbi transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractPublishAbiData {
    /// Address of the deployed contract whose ABI is being published.
    pub contract_address: Address,
    /// Authenticated ABI payload for the immutable contract bytecode.
    pub abi: ContractAbi,
}

/// Data payload for a ContractRouteUpdate transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRouteUpdateData {
    /// Stable route name inside the sender/deployer namespace.
    pub route_name: String,
    /// Current immutable contract release the route should target.
    pub target_contract_address: Address,
}

/// Data payload for a ContractRouteCall transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRouteCallData {
    /// Route owner namespace.
    pub deployer: Address,
    /// Stable route name inside the deployer namespace.
    pub route_name: String,
    /// Name of the function to invoke on the current route target.
    pub function: String,
    /// Serialized function arguments.
    pub args: Vec<u8>,
    /// Maximum gas the caller is willing to spend on contract execution.
    pub gas_limit: u64,
}

/// Data payload for a ContractCall transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCallData {
    /// Address of the contract to call.
    pub contract_address: Address,
    /// Name of the function to invoke.
    pub function: String,
    /// Serialized function arguments.
    pub args: Vec<u8>,
    /// Maximum gas the caller is willing to spend on contract execution.
    pub gas_limit: u64,
}

pub fn derive_contract_address_from_bytecode_hash(
    deployer: &Address,
    nonce: u64,
    bytecode_hash: &Hash256,
) -> Address {
    let mut preimage = Vec::with_capacity(
        deployer.0.len() + std::mem::size_of::<u64>() + bytecode_hash.as_bytes().len(),
    );
    preimage.extend_from_slice(&deployer.0);
    preimage.extend_from_slice(&nonce.to_be_bytes());
    preimage.extend_from_slice(bytecode_hash.as_bytes());
    let hash = hash_bytes(&preimage);
    let mut bytes = [0u8; 20];
    bytes.copy_from_slice(&hash.0[12..32]);
    Address(bytes)
}

pub fn derive_contract_address(deployer: &Address, nonce: u64, bytecode: &[u8]) -> Address {
    let bytecode_hash = hash_bytes(bytecode);
    derive_contract_address_from_bytecode_hash(deployer, nonce, &bytecode_hash)
}

pub fn validate_and_normalize_contract_route_name(
    route_name: &str,
) -> std::result::Result<String, String> {
    let trimmed = route_name.trim();
    if trimmed.is_empty() {
        return Err("Contract route name must not be empty".to_string());
    }
    if trimmed.len() > MAX_CONTRACT_ROUTE_NAME_BYTES {
        return Err(format!(
            "Contract route name too long: {} > {} bytes",
            trimmed.len(),
            MAX_CONTRACT_ROUTE_NAME_BYTES
        ));
    }
    if trimmed.starts_with('.') || trimmed.ends_with('.') {
        return Err("Contract route name must not start or end with '.'".to_string());
    }
    let mut normalized = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if ch.is_ascii_uppercase() {
            return Err("Contract route names must be lowercase ASCII".to_string());
        }
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '-' | '_' | '.') {
            normalized.push(ch);
        } else {
            return Err(
                "Contract route names may only contain lowercase ASCII letters, digits, '.', '-', and '_'"
                    .to_string(),
            );
        }
    }
    Ok(normalized)
}

pub fn hash_contract_abi(abi: &ContractAbi) -> Option<Hash256> {
    bincode::serialize(abi)
        .ok()
        .map(|encoded| hash_bytes(&encoded))
}

pub fn validate_contract_abi_shape(abi: &ContractAbi) -> std::result::Result<Hash256, String> {
    if abi.name.trim().is_empty() {
        return Err("Contract ABI name must not be empty".to_string());
    }
    if abi.version.trim().is_empty() {
        return Err("Contract ABI version must not be empty".to_string());
    }

    let encoded = bincode::serialize(abi)
        .map_err(|error| format!("Failed to encode contract ABI: {}", error))?;
    if encoded.len() > MAX_CONTRACT_ABI_BYTES {
        return Err(format!(
            "Contract ABI too large: {} > {} bytes",
            encoded.len(),
            MAX_CONTRACT_ABI_BYTES
        ));
    }

    let mut seen = HashSet::new();
    for function in &abi.functions {
        let name = function.name.trim();
        if name.is_empty() {
            return Err("Contract ABI function name must not be empty".to_string());
        }
        if !seen.insert(name.to_string()) {
            return Err(format!(
                "Contract ABI contains duplicate function '{}'",
                name
            ));
        }
    }

    Ok(hash_bytes(&encoded))
}

pub fn validate_top_level_contract_call_gas_limit(
    gas_limit: u64,
) -> std::result::Result<(), String> {
    if gas_limit == 0 {
        return Err("ContractCall gas_limit must be > 0".to_string());
    }

    if gas_limit > MAX_CONTRACT_GAS {
        return Err(format!(
            "Gas limit {} exceeds max {}",
            gas_limit, MAX_CONTRACT_GAS
        ));
    }

    Ok(())
}

pub fn validate_top_level_contract_call_target(
    contract_address: &Address,
    gas_limit: u64,
    contract: Option<ContractRecord>,
) -> std::result::Result<ContractRecord, String> {
    let contract = contract.ok_or_else(|| format!("Contract {} not found", contract_address))?;

    if !contract.is_active {
        return Err(format!("Contract {} is inactive", contract_address));
    }

    validate_top_level_contract_call_gas_limit(gas_limit)?;

    Ok(contract)
}

pub fn validate_top_level_contract_route_call_target(
    deployer: &Address,
    route_name: &str,
    gas_limit: u64,
    route: Option<ContractRouteRecord>,
    contract: Option<ContractRecord>,
) -> std::result::Result<(ContractRouteRecord, ContractRecord), String> {
    let route_key = ContractRouteKey::new(deployer.clone(), route_name.to_string())?;
    let route = route.ok_or_else(|| {
        format!(
            "Contract route {}::{} not found",
            route_key.deployer, route_key.route_name
        )
    })?;
    let contract = validate_top_level_contract_call_target(
        &route.target_contract_address,
        gas_limit,
        contract,
    )?;
    Ok((route, contract))
}

pub fn contract_upgrade_unsupported_error() -> String {
    CONTRACT_UPGRADE_UNSUPPORTED_MSG.to_string()
}

/// An event emitted by a contract during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractEvent {
    /// The contract that emitted this event.
    pub contract_address: Address,
    /// Event topic (indexed, max 64 bytes). e.g. "Transfer", "Approval".
    pub topic: String,
    /// Event data payload (not indexed, max 4 KB).
    pub data: Vec<u8>,
    /// Block in which the event was emitted.
    pub block_number: u64,
    /// Transaction that triggered the event.
    pub tx_hash: Hash256,
    /// Monotonic position within this contract's emitted events for the block.
    /// This does not reset per transaction; `tx_hash` identifies the origin tx.
    pub log_index: u32,
}

/// Result of a contract execution.
#[derive(Debug, Clone)]
pub struct ContractExecResult {
    /// Whether execution succeeded.
    pub success: bool,
    /// Whether execution failed due to an infrastructure/state-read fault
    /// rather than ordinary contract logic or a WASM trap.
    pub fatal_error: bool,
    /// Return data from the contract function.
    pub return_data: Vec<u8>,
    /// Gas consumed during execution.
    pub gas_used: u64,
    /// Events emitted during execution.
    pub events: Vec<ContractEvent>,
    /// Error message if execution failed.
    pub error: Option<String>,
    /// Balance changes to apply on success: (address, signed delta).
    pub balance_deltas: Vec<(Address, i64)>,
    /// Storage writes to apply on success, namespaced by contract address.
    pub storage_writes: ContractStorageWrites,
    /// Access tokens generated by host_tool_invoke during execution.
    pub pending_access_tokens: Vec<crate::primitives::tool::AccessToken>,
    /// Token metadata, balances, and allowances staged during execution.
    /// The node commits these only after all post-execution validation passes.
    pub token_writes: ContractTokenWrites,
    /// Final event_counter value after execution. Used by parent contracts
    /// to advance their own counter past child values, ensuring token_id
    /// uniqueness when the same child contract is called multiple times.
    pub final_event_counter: u32,
}

/// Storage writes emitted by a contract execution tree, grouped by the
/// contract address whose storage namespace they modify.
pub type ContractStorageWrites = BTreeMap<Address, Vec<(Vec<u8>, Option<Vec<u8>>)>>;

/// Token state updates emitted by a contract execution tree.
///
/// These remain staged until the node accepts the overall contract execution
/// after storage accounting, ZIN balance validation, and routing checks.
#[derive(Debug, Clone, Default)]
pub struct ContractTokenWrites {
    pub tokens: HashMap<Hash256, crate::primitives::token::TokenMetadata>,
    pub tokens_removed: HashSet<Hash256>,
    pub token_balances: HashMap<(Hash256, Address), u64>,
    pub token_balances_removed: HashSet<(Hash256, Address)>,
    pub token_balance_storage_deposits:
        HashMap<(Hash256, Address), crate::primitives::token::TokenSecondaryStateStorageDeposit>,
    pub token_balance_storage_deposits_removed: HashSet<(Hash256, Address)>,
    pub token_allowances: HashMap<crate::primitives::token::AllowanceKey, u64>,
    pub token_allowances_removed: HashSet<crate::primitives::token::AllowanceKey>,
    pub token_allowance_storage_deposits: HashMap<
        crate::primitives::token::AllowanceKey,
        crate::primitives::token::TokenSecondaryStateStorageDeposit,
    >,
    pub token_allowance_storage_deposits_removed: HashSet<crate::primitives::token::AllowanceKey>,
}

impl ContractTokenWrites {
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
            && self.tokens_removed.is_empty()
            && self.token_balances.is_empty()
            && self.token_balances_removed.is_empty()
            && self.token_balance_storage_deposits.is_empty()
            && self.token_balance_storage_deposits_removed.is_empty()
            && self.token_allowances.is_empty()
            && self.token_allowances_removed.is_empty()
            && self.token_allowance_storage_deposits.is_empty()
            && self.token_allowance_storage_deposits_removed.is_empty()
    }

    pub fn merge_from(&mut self, other: &Self) {
        for token_id in &other.tokens_removed {
            self.tokens.remove(token_id);
            self.tokens_removed.insert(*token_id);
        }
        for (token_id, token) in &other.tokens {
            self.tokens_removed.remove(token_id);
            self.tokens.insert(*token_id, token.clone());
        }

        for key in &other.token_balances_removed {
            self.token_balances.remove(key);
            self.token_balances_removed.insert(key.clone());
        }
        for (key, balance) in &other.token_balances {
            self.token_balances_removed.remove(key);
            self.token_balances.insert(key.clone(), *balance);
        }
        for key in &other.token_balance_storage_deposits_removed {
            self.token_balance_storage_deposits.remove(key);
            self.token_balance_storage_deposits_removed
                .insert(key.clone());
        }
        for (key, record) in &other.token_balance_storage_deposits {
            self.token_balance_storage_deposits_removed.remove(key);
            self.token_balance_storage_deposits
                .insert(key.clone(), record.clone());
        }

        for key in &other.token_allowances_removed {
            self.token_allowances.remove(key);
            self.token_allowances_removed.insert(key.clone());
        }
        for (key, amount) in &other.token_allowances {
            self.token_allowances_removed.remove(key);
            self.token_allowances.insert(key.clone(), *amount);
        }
        for key in &other.token_allowance_storage_deposits_removed {
            self.token_allowance_storage_deposits.remove(key);
            self.token_allowance_storage_deposits_removed
                .insert(key.clone());
        }
        for (key, record) in &other.token_allowance_storage_deposits {
            self.token_allowance_storage_deposits_removed.remove(key);
            self.token_allowance_storage_deposits
                .insert(key.clone(), record.clone());
        }
    }
}

/// Maximum WASM bytecode size (1 MB).
pub const MAX_CONTRACT_BYTECODE: usize = 1024 * 1024;

/// Maximum contract storage key length (64 bytes).
pub const MAX_STORAGE_KEY: usize = 64;

/// Maximum contract storage value length (64 KB).
pub const MAX_STORAGE_VALUE: usize = 64 * 1024;

/// Maximum total storage per contract (10 MB).
pub const MAX_STORAGE_TOTAL: usize = 10 * 1024 * 1024;

/// Maximum event topic length (64 bytes).
pub const MAX_EVENT_TOPIC: usize = 64;

/// Maximum event data length (4 KB).
pub const MAX_EVENT_DATA: usize = 4 * 1024;

/// Maximum call stack depth for cross-contract calls.
pub const MAX_CALL_DEPTH: u32 = 8;

/// Maximum gas per ContractCall transaction.
pub const MAX_CONTRACT_GAS: u64 = 10_000_000;

/// Maximum linear memory per contract instance (16 MB).
pub const MAX_CONTRACT_LINEAR_MEMORY_BYTES: usize = 16 * 1024 * 1024;

/// Fuel conversion for pure WASM computation.
pub const WASM_FUEL_PER_GAS: u64 = 10;

/// Maximum WASM fuel budget at the maximum contract gas limit.
pub const WASM_FUEL_LIMIT: u64 = MAX_CONTRACT_GAS * WASM_FUEL_PER_GAS;

#[cfg(test)]
mod tests {
    use super::*;

    fn test_contract_record() -> ContractRecord {
        ContractRecord {
            address: Address::zero(),
            deployer: Address::zero(),
            bytecode_hash: Hash256::zero(),
            export_metadata: ContractExportMetadata::empty_for_bytecode_hash(Hash256::zero()),
            created_at_block: 0,
            updated_at_block: 0,
            is_active: true,
            abi: None,
            abi_hash: None,
            verified: false,
            source_hash: None,
            verification: None,
            storage_deposit: 0,
            verified_source_storage_deposit: 0,
            storage_bytes: 0,
            storage_reserve: 0,
            storage_root: Hash256::zero(),
        }
    }

    #[test]
    fn test_validate_top_level_contract_call_gas_limit_rejects_zero() {
        let error = validate_top_level_contract_call_gas_limit(0)
            .expect_err("zero-gas top-level calls should be rejected");
        assert_eq!(error, "ContractCall gas_limit must be > 0");
    }

    #[test]
    fn test_validate_top_level_contract_call_target_rejects_zero_gas_limit() {
        let error = validate_top_level_contract_call_target(
            &Address::zero(),
            0,
            Some(test_contract_record()),
        )
        .expect_err("zero-gas top-level call target should be rejected");
        assert_eq!(error, "ContractCall gas_limit must be > 0");
    }

    #[test]
    fn test_contract_platform_profile_is_stable_and_matches_capabilities() {
        let capabilities = contract_platform_capabilities();
        assert_eq!(
            capabilities.profile_version,
            CONTRACT_PLATFORM_PROFILE_VERSION,
        );

        let (wasm_features, host_functions, upgrade_policy, supported_verification_backends) =
            contract_platform_scope_components();
        let expected = compute_contract_platform_profile_id(
            &wasm_features,
            &host_functions,
            &upgrade_policy,
            &supported_verification_backends,
        );
        assert_eq!(capabilities.profile_id, expected);
        assert_eq!(capabilities.profile_id.len(), 64);
        assert_eq!(capabilities.contract_vm_profile_id, CONTRACT_VM_PROFILE_ID);
        assert!(capabilities.integer_only);
        assert_eq!(capabilities.fixed_point_scale, CONTRACT_FIXED_POINT_SCALE);
        assert_eq!(capabilities.wasm_features, wasm_features);
        assert_eq!(capabilities.host_functions, host_functions);
    }

    #[test]
    fn test_verify_contract_storage_projection_rejects_tampered_payload() {
        let mut record = test_contract_record();
        let mut storage = BTreeMap::new();
        storage.insert(b"k".to_vec(), b"v".to_vec());
        record.storage_root = compute_contract_storage_root(&storage);
        record.storage_bytes = contract_storage_total_bytes(&storage);

        verify_contract_storage_projection(&record, Some(&storage))
            .expect("matching storage projection must validate");

        storage.insert(b"k".to_vec(), b"tampered".to_vec());
        let error = verify_contract_storage_projection(&record, Some(&storage))
            .expect_err("tampered storage projection must fail");
        assert!(
            error.contains("storage_root mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_contract_event_archive_accumulator_is_order_independent() {
        let contract_a = Address([0x11; 20]);
        let contract_b = Address([0x22; 20]);
        let tx_a = hash_bytes(b"tx-a");
        let tx_b = hash_bytes(b"tx-b");
        let first = ContractEvent {
            contract_address: contract_a.clone(),
            topic: "A".to_string(),
            data: b"1".to_vec(),
            block_number: 5,
            tx_hash: tx_a,
            log_index: 0,
        };
        let second = ContractEvent {
            contract_address: contract_b,
            topic: "B".to_string(),
            data: b"2".to_vec(),
            block_number: 5,
            tx_hash: tx_b,
            log_index: 0,
        };
        let third = ContractEvent {
            contract_address: contract_a,
            topic: "C".to_string(),
            data: b"3".to_vec(),
            block_number: 6,
            tx_hash: tx_b,
            log_index: 1,
        };

        let baseline = compute_contract_event_archive_accumulator(&[
            first.clone(),
            second.clone(),
            third.clone(),
        ]);
        let reordered = compute_contract_event_archive_accumulator(&[third, second, first]);

        assert_eq!(baseline, reordered);
    }

    #[test]
    fn test_verify_contract_event_archive_accumulator_rejects_tampered_payload() {
        let contract = Address([0x33; 20]);
        let event = ContractEvent {
            contract_address: contract,
            topic: "Transfer".to_string(),
            data: b"payload".to_vec(),
            block_number: 9,
            tx_hash: hash_bytes(b"tx"),
            log_index: 0,
        };
        let committed = compute_contract_event_archive_accumulator(&[event.clone()]);
        verify_contract_event_archive_accumulator(committed, &[event.clone()])
            .expect("matching event archive must validate");

        let mut tampered = event;
        tampered.data = b"tampered".to_vec();
        let error = verify_contract_event_archive_accumulator(committed, &[tampered])
            .expect_err("tampered event archive must fail");
        assert!(
            error.contains("accumulator mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_validate_contract_abi_shape_rejects_empty_name() {
        let error = validate_contract_abi_shape(&ContractAbi {
            name: String::new(),
            version: "1.0.0".to_string(),
            functions: vec![],
        })
        .expect_err("empty ABI name must fail");
        assert_eq!(error, "Contract ABI name must not be empty");
    }

    #[test]
    fn test_validate_contract_abi_shape_rejects_duplicate_functions() {
        let error = validate_contract_abi_shape(&ContractAbi {
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            functions: vec![
                FunctionSignature {
                    name: "run".to_string(),
                    description: String::new(),
                    params: vec![],
                    returns: vec![],
                    mutates: false,
                },
                FunctionSignature {
                    name: "run".to_string(),
                    description: String::new(),
                    params: vec![],
                    returns: vec![],
                    mutates: true,
                },
            ],
        })
        .expect_err("duplicate ABI functions must fail");
        assert!(
            error.contains("duplicate function"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_authenticated_abi_requires_matching_hash() {
        let abi = ContractAbi {
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            functions: vec![],
        };
        let mut record = test_contract_record();
        record.abi = Some(abi.clone());
        assert!(record.authenticated_abi().is_none());

        record.abi_hash = hash_contract_abi(&abi);
        assert_eq!(
            record
                .authenticated_abi()
                .map(|published| published.name.as_str()),
            Some("demo")
        );
    }

    #[test]
    fn test_contract_record_serialization_rejects_abi_without_hash() {
        let mut record = test_contract_record();
        record.abi = Some(ContractAbi {
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            functions: vec![],
        });

        let error =
            bincode::serialize(&record).expect_err("invalid contract ABI state must not serialize");
        assert!(
            error.to_string().contains("without a committed abi_hash"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn test_contract_export_metadata_validation_rejects_malformed_state() {
        let bytecode_hash = hash_bytes(b"metadata-bytecode");
        let metadata = ContractExportMetadata::new(
            bytecode_hash,
            true,
            vec!["view".to_string(), "run".to_string()],
        )
        .expect("metadata should normalize sorted exports");
        assert_eq!(
            metadata.callable_exports,
            vec!["run".to_string(), "view".to_string()]
        );
        assert!(metadata.callable("run"));

        let mut wrong_hash = metadata.clone();
        wrong_hash.bytecode_hash = hash_bytes(b"other");
        assert!(wrong_hash
            .validate_for_bytecode_hash(bytecode_hash)
            .expect_err("wrong bytecode hash must fail")
            .contains("bytecode_hash"));

        let mut unsorted = metadata.clone();
        unsorted.callable_exports = vec!["view".to_string(), "run".to_string()];
        unsorted.callable_exports_hash =
            hash_callable_exports(&unsorted.callable_exports).expect("hash unsorted exports");
        assert!(unsorted
            .validate_for_bytecode_hash(bytecode_hash)
            .expect_err("unsorted exports must fail")
            .contains("sorted and unique"));

        let mut duplicate = metadata.clone();
        duplicate.callable_exports = vec!["run".to_string(), "run".to_string()];
        duplicate.callable_exports_hash =
            hash_callable_exports(&duplicate.callable_exports).expect("hash duplicate exports");
        assert!(duplicate
            .validate_for_bytecode_hash(bytecode_hash)
            .expect_err("duplicate exports must fail")
            .contains("sorted and unique"));

        let mut bad_export_hash = metadata;
        bad_export_hash.callable_exports_hash = Hash256::zero();
        assert!(bad_export_hash
            .validate_for_bytecode_hash(bytecode_hash)
            .expect_err("bad export hash must fail")
            .contains("callable_exports_hash"));
    }

    #[test]
    fn test_contract_record_deserialization_rejects_abi_without_hash() {
        #[derive(Serialize)]
        struct InvalidContractRecordWire {
            address: Address,
            deployer: Address,
            bytecode_hash: Hash256,
            export_metadata: ContractExportMetadata,
            created_at_block: u64,
            updated_at_block: u64,
            is_active: bool,
            abi: Option<ContractAbi>,
            abi_hash: Option<Hash256>,
            verified: bool,
            source_hash: Option<Hash256>,
            verification: Option<ContractVerificationRecord>,
            storage_deposit: u64,
            verified_source_storage_deposit: u64,
            storage_bytes: u64,
            storage_reserve: u64,
            storage_root: Hash256,
        }

        let bytes = bincode::serialize(&InvalidContractRecordWire {
            address: Address::zero(),
            deployer: Address::zero(),
            bytecode_hash: Hash256::zero(),
            export_metadata: ContractExportMetadata::empty_for_bytecode_hash(Hash256::zero()),
            created_at_block: 0,
            updated_at_block: 0,
            is_active: true,
            abi: Some(ContractAbi {
                name: "demo".to_string(),
                version: "1.0.0".to_string(),
                functions: vec![],
            }),
            abi_hash: None,
            verified: false,
            source_hash: None,
            verification: None,
            storage_deposit: 0,
            verified_source_storage_deposit: 0,
            storage_bytes: 0,
            storage_reserve: 0,
            storage_root: Hash256::zero(),
        })
        .expect("serialize invalid wire contract record");

        let error = bincode::deserialize::<ContractRecord>(&bytes)
            .expect_err("invalid contract ABI state must not deserialize");
        assert!(
            error.to_string().contains("without a committed abi_hash"),
            "unexpected error: {error}"
        );
    }
}
