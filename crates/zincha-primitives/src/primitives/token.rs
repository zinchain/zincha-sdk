use serde::{Deserialize, Serialize};

use crate::crypto::{Address, Hash256};

/// Storage-deposit record for a durable token secondary-state row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenSecondaryStateStorageDeposit {
    pub payer: Address,
    pub amount: u64,
}

/// ZIP-20 token metadata — stored per-token in state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub token_id: Hash256,
    pub name: String,
    /// Ticker symbol (max 10 chars, uppercase).
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: u64,
    /// Maximum supply (0 = unlimited).
    pub max_supply: u64,
    pub burnable: bool,
    pub creator: Address,
    /// Address authorized to mint. `None` means minting is permanently disabled.
    pub mint_authority: Option<Address>,
    pub created_at_block: u64,
    /// Arbitrary JSON metadata (icon URL, description, etc). Max 4 KB.
    pub metadata: Vec<u8>,
    /// Storage deposit locked for this token entry (micro-ZIN).
    /// Refunded when the token is destroyed.
    #[serde(default)]
    pub storage_deposit: u64,
}

/// Data payload for TokenCreate transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCreateData {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub initial_supply: u64,
    pub max_supply: u64,
    pub burnable: bool,
    /// Address authorized to mint. `None` creates an irrevocably fixed-supply token.
    pub mint_authority: Option<Address>,
    /// Arbitrary metadata (max 4 KB).
    #[serde(default)]
    pub metadata: Vec<u8>,
}

/// Data payload for TokenMint transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMintData {
    pub token_id: Hash256,
    pub to: Address,
    pub amount: u64,
}

/// Data payload for TokenTransfer transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransferData {
    pub token_id: Hash256,
    pub to: Address,
    pub amount: u64,
}

/// Data payload for TokenApprove transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenApproveData {
    pub token_id: Hash256,
    pub spender: Address,
    pub amount: u64,
}

/// Data payload for TokenBurn transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBurnData {
    pub token_id: Hash256,
    pub amount: u64,
}

/// Data payload for TokenUpdateAuthority transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUpdateAuthorityData {
    pub token_id: Hash256,
    /// New mint authority. `None` permanently renounces minting.
    pub mint_authority: Option<Address>,
}

/// Composite key for allowances: (token_id, owner, spender).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AllowanceKey {
    pub token_id: Hash256,
    pub owner: Address,
    pub spender: Address,
}

/// Maximum token symbol length.
pub const MAX_TOKEN_SYMBOL: usize = 10;
/// Maximum token metadata size.
pub const MAX_TOKEN_METADATA: usize = 4096;

impl TokenMetadata {
    pub fn mintable(&self) -> bool {
        self.mint_authority.is_some()
    }
}

pub fn derive_token_id(creator: &Address, symbol: &str, nonce: u64) -> Hash256 {
    crate::crypto::hash_bytes(format!("{}:{}:{}", creator.to_hex(), symbol, nonce).as_bytes())
}
