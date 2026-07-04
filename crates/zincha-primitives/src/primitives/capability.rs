use serde::{Deserialize, Serialize};

use crate::crypto::Address;

pub const CAPABILITY_CATALOG_VERSION: u32 = 1;
pub const MAX_CAPABILITY_SLUG_BYTES: usize = 128;
pub const MAX_CAPABILITY_ALIASES: usize = 32;
pub const MAX_CAPABILITY_TEXT_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Active,
    Pending,
    Rejected,
    Deprecated,
}

impl CapabilityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Rejected => "rejected",
            Self::Deprecated => "deprecated",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "active" => Some(Self::Active),
            "pending" => Some(Self::Pending),
            "rejected" => Some(Self::Rejected),
            "deprecated" => Some(Self::Deprecated),
            _ => None,
        }
    }
}

impl Default for CapabilityStatus {
    fn default() -> Self {
        Self::Active
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySource {
    Seed,
    UserProposed,
    Curated,
}

impl Default for CapabilitySource {
    fn default() -> Self {
        Self::Seed
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityUsageSummary {
    #[serde(default)]
    pub agent_count: u64,
    #[serde(default)]
    pub tool_count: u64,
    #[serde(default)]
    pub open_task_count: u64,
    #[serde(default)]
    pub market_sample_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCatalogEntry {
    pub slug: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub status: CapabilityStatus,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub examples: Vec<String>,
    #[serde(default)]
    pub related: Vec<String>,
    #[serde(default)]
    pub proposer: Option<Address>,
    #[serde(default)]
    pub source: CapabilitySource,
    #[serde(default)]
    pub created_at_block: u64,
    #[serde(default)]
    pub updated_at_block: u64,
    #[serde(default)]
    pub usage: CapabilityUsageSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProposeData {
    pub slug: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub examples: Vec<String>,
    #[serde(default)]
    pub related: Vec<String>,
}

impl CapabilityProposeData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityApproveData {
    pub slug: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub parent: Option<Option<String>>,
    #[serde(default)]
    pub aliases: Option<Vec<String>>,
    #[serde(default)]
    pub keywords: Option<Vec<String>>,
    #[serde(default)]
    pub examples: Option<Vec<String>>,
    #[serde(default)]
    pub related: Option<Vec<String>>,
}

impl CapabilityApproveData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRejectData {
    pub slug: String,
    #[serde(default)]
    pub reason: String,
}

impl CapabilityRejectData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeprecateData {
    pub slug: String,
    pub replacement: String,
    #[serde(default)]
    pub reason: String,
}

impl CapabilityDeprecateData {
    pub fn decode(bytes: &[u8]) -> std::result::Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

pub fn normalize_capability_slug(raw: &str) -> std::result::Result<String, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("capability slug is required".to_string());
    }
    if value.len() > MAX_CAPABILITY_SLUG_BYTES {
        return Err(format!(
            "capability slug too long: {} > {} bytes",
            value.len(),
            MAX_CAPABILITY_SLUG_BYTES
        ));
    }
    if value != value.to_ascii_lowercase() {
        return Err("capability slug must be lowercase ASCII".to_string());
    }
    if value.contains(['/', '_', ' ', '\t', '\n', '\r']) {
        return Err(
            "capability slug must not contain whitespace, slash, or underscore".to_string(),
        );
    }
    if value.starts_with('.') || value.ends_with('.') || value.contains("..") {
        return Err("capability slug must use non-empty dotted segments".to_string());
    }

    let segments: Vec<&str> = value.split('.').collect();
    if segments.len() < 2 || segments.len() > 8 {
        return Err("capability slug must contain 2 to 8 dotted segments".to_string());
    }
    for segment in segments {
        let mut chars = segment.chars();
        let Some(first) = chars.next() else {
            return Err("capability slug segment cannot be empty".to_string());
        };
        if !first.is_ascii_lowercase() {
            return Err(
                "each capability slug segment must start with a lowercase letter".to_string(),
            );
        }
        if !chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-') {
            return Err(
                "capability slug segments may contain only lowercase letters, digits, and hyphen"
                    .to_string(),
            );
        }
    }
    Ok(value.to_string())
}
