use serde::{Deserialize, Serialize};

use crate::crypto::{hash_bytes, Address, Hash256, PublicKey};

pub const RPC_READ_DELEGATION_VERSION: u16 = 1;
pub const RPC_READ_DELEGATION_ID_DOMAIN: &[u8] = b"zincha-rpc-read-delegation-id-v1";
pub const RPC_READ_DELEGATION_MIN_LIFETIME_MS: u64 = 60 * 60 * 1_000;
pub const RPC_READ_DELEGATION_DEFAULT_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
pub const RPC_READ_DELEGATION_MAX_LIFETIME_MS: u64 = 90 * 24 * 60 * 60 * 1_000;
pub const MAX_RPC_READ_DELEGATIONS_PER_DELEGATOR: usize = 32;
pub const MAX_RPC_READ_DELEGATION_SERVICE_ID_CHARS: usize = 256;

pub const RPC_READ_SCOPE_TASK_READ: u64 = 1 << 0;
pub const RPC_READ_SCOPE_TASK_LIFECYCLE_READ: u64 = 1 << 1;
pub const RPC_READ_SCOPE_AGREEMENT_READ: u64 = 1 << 2;
pub const RPC_READ_SCOPE_AGREEMENT_LIFECYCLE_READ: u64 = 1 << 3;
pub const RPC_READ_SCOPE_TOOL_JOB_READ: u64 = 1 << 4;
pub const RPC_READ_SCOPE_TOOL_JOB_LIFECYCLE_READ: u64 = 1 << 5;
pub const RPC_READ_SCOPE_TOOL_USAGE_SESSION_READ: u64 = 1 << 6;
pub const RPC_READ_SCOPE_TOOL_USAGE_SESSION_LIFECYCLE_READ: u64 = 1 << 7;
pub const RPC_READ_SCOPE_ALL: u64 = (1 << 8) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum RpcReadScope {
    TaskRead = 0,
    TaskLifecycleRead = 1,
    AgreementRead = 2,
    AgreementLifecycleRead = 3,
    ToolJobRead = 4,
    ToolJobLifecycleRead = 5,
    ToolUsageSessionRead = 6,
    ToolUsageSessionLifecycleRead = 7,
}

impl RpcReadScope {
    pub const ALL: [Self; 8] = [
        Self::TaskRead,
        Self::TaskLifecycleRead,
        Self::AgreementRead,
        Self::AgreementLifecycleRead,
        Self::ToolJobRead,
        Self::ToolJobLifecycleRead,
        Self::ToolUsageSessionRead,
        Self::ToolUsageSessionLifecycleRead,
    ];

    pub const fn mask(self) -> u64 {
        1_u64 << self as u8
    }
}

pub fn rpc_read_scope_mask(scopes: impl IntoIterator<Item = RpcReadScope>) -> u64 {
    scopes
        .into_iter()
        .fold(0, |mask, scope| mask | scope.mask())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReadDelegationGrantData {
    pub delegate_public_key: [u8; 32],
    pub service_id: String,
    pub scope_mask: u64,
    pub expires_at_ms: u64,
}

impl RpcReadDelegationGrantData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReadDelegationRevokeData {
    pub delegation_id: Hash256,
}

impl RpcReadDelegationRevokeData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcReadDelegation {
    pub version: u16,
    pub delegation_id: Hash256,
    pub delegator: Address,
    pub delegate: Address,
    pub delegate_public_key: [u8; 32],
    pub service_id: String,
    pub service_id_hash: Hash256,
    pub scope_mask: u64,
    pub created_at_block: u64,
    pub updated_at_block: u64,
    pub expires_at_ms: u64,
    pub storage_deposit: u64,
}

impl RpcReadDelegation {
    pub fn grants(&self, required_scope: u64, now_ms: u64) -> bool {
        self.expires_at_ms > now_ms && self.scope_mask & required_scope == required_scope
    }
}

pub fn validate_rpc_read_delegation_service_id(service_id: &str) -> Result<(), String> {
    if service_id.is_empty() || service_id.trim() != service_id {
        return Err(
            "delegation service_id must be non-empty and must not have surrounding whitespace"
                .into(),
        );
    }
    if service_id.chars().count() > MAX_RPC_READ_DELEGATION_SERVICE_ID_CHARS {
        return Err(format!(
            "delegation service_id exceeds {} Unicode scalar values",
            MAX_RPC_READ_DELEGATION_SERVICE_ID_CHARS
        ));
    }
    if service_id.chars().any(char::is_control) {
        return Err("delegation service_id must not contain control characters".into());
    }
    Ok(())
}

pub fn rpc_read_delegation_id(
    delegator: &Address,
    delegate_public_key: &[u8; 32],
    service_id: &str,
) -> Hash256 {
    let service_id_bytes = service_id.as_bytes();
    let mut bytes = Vec::with_capacity(
        RPC_READ_DELEGATION_ID_DOMAIN.len() + 20 + 32 + 4 + service_id_bytes.len(),
    );
    bytes.extend_from_slice(RPC_READ_DELEGATION_ID_DOMAIN);
    bytes.extend_from_slice(&delegator.0);
    bytes.extend_from_slice(delegate_public_key);
    bytes.extend_from_slice(&(service_id_bytes.len() as u32).to_be_bytes());
    bytes.extend_from_slice(service_id_bytes);
    hash_bytes(&bytes)
}

pub fn rpc_read_delegate_address(public_key: &[u8; 32]) -> Result<Address, String> {
    PublicKey::from_bytes(public_key)
        .map(|key| key.to_address())
        .map_err(|error| format!("invalid delegation public key: {error}"))
}

pub fn rpc_read_service_id_hash(service_id: &str) -> Hash256 {
    hash_bytes(service_id.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_id_is_domain_separated_and_stable() {
        let delegator = Address([7; 20]);
        let public_key = [9; 32];
        let first = rpc_read_delegation_id(&delegator, &public_key, "provider/conversations");
        assert_eq!(
            first,
            rpc_read_delegation_id(&delegator, &public_key, "provider/conversations")
        );
        assert_ne!(
            first,
            rpc_read_delegation_id(&delegator, &public_key, "other/conversations")
        );
    }

    #[test]
    fn service_id_and_scope_bounds_are_explicit() {
        assert!(validate_rpc_read_delegation_service_id("provider/conversations").is_ok());
        assert!(validate_rpc_read_delegation_service_id(" provider/conversations").is_err());
        assert!(validate_rpc_read_delegation_service_id("").is_err());
        assert_eq!(RPC_READ_SCOPE_ALL, 0xff);
        assert_eq!(rpc_read_scope_mask(RpcReadScope::ALL), RPC_READ_SCOPE_ALL);
        assert_eq!(
            rpc_read_scope_mask([RpcReadScope::TaskRead, RpcReadScope::AgreementRead]),
            RPC_READ_SCOPE_TASK_READ | RPC_READ_SCOPE_AGREEMENT_READ
        );
    }
}
