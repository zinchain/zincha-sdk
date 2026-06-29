use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseName {
    Polaris,
    Vega,
    Sirius,
    Altair,
    Lyra,
}

impl ReleaseName {
    pub fn parse_alias(raw: &str) -> Option<Self> {
        let normalized = raw.trim().to_ascii_lowercase().replace('_', "-");
        match normalized.as_str() {
            "polaris" | "devnet" => Some(Self::Polaris),
            "vega" | "public-testnet" | "testnet" => Some(Self::Vega),
            "sirius" | "incentivized-testnet" | "incentivized" => Some(Self::Sirius),
            "altair" | "mainnet" => Some(Self::Altair),
            "lyra" | "mainnet-upgrade" => Some(Self::Lyra),
            _ => None,
        }
    }

    pub fn spec(self) -> ReleaseSpec {
        release_spec(self)
    }

    pub fn slug(self) -> &'static str {
        self.spec().slug
    }

    pub fn display_name(self) -> &'static str {
        self.spec().display_name
    }
}

impl fmt::Display for ReleaseName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.slug())
    }
}

impl FromStr for ReleaseName {
    type Err = ReleaseParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse_alias(raw).ok_or_else(|| ReleaseParseError {
            value: raw.to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseParseError {
    value: String,
}

impl fmt::Display for ReleaseParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown release {}; expected one of polaris, vega, sirius, altair, lyra",
            self.value
        )
    }
}

impl std::error::Error for ReleaseParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseStage {
    Devnet,
    PublicTestnet,
    IncentivizedTestnet,
    Mainnet,
    MainnetUpgrade,
}

impl ReleaseStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Devnet => "devnet",
            Self::PublicTestnet => "public-testnet",
            Self::IncentivizedTestnet => "incentivized-testnet",
            Self::Mainnet => "mainnet",
            Self::MainnetUpgrade => "mainnet-upgrade",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseSpec {
    pub name: ReleaseName,
    pub slug: &'static str,
    pub display_name: &'static str,
    pub stage: ReleaseStage,
    pub chain_id: &'static str,
    pub canonical_rpc_url: &'static str,
    pub canonical_websocket_url: &'static str,
    pub boot_nodes: &'static [&'static str],
    pub explorer_url: Option<&'static str>,
    pub faucet_url: Option<&'static str>,
}

const NO_BOOT_NODES: &[&str] = &[];
const VEGA_BOOT_NODES: &[&str] = &[
    "/dns4/boot-1.vega.zincha.com/tcp/30333",
    "/dns4/boot-2.vega.zincha.com/tcp/30333",
];
const SIRIUS_BOOT_NODES: &[&str] = &[
    "/dns4/boot-1.sirius.zincha.com/tcp/30333",
    "/dns4/boot-2.sirius.zincha.com/tcp/30333",
];

pub fn release_spec(name: ReleaseName) -> ReleaseSpec {
    match name {
        ReleaseName::Polaris => ReleaseSpec {
            name,
            slug: "polaris",
            display_name: "Polaris",
            stage: ReleaseStage::Devnet,
            chain_id: "zincha-polaris-1",
            canonical_rpc_url: "https://polaris.zincha.com",
            canonical_websocket_url: "wss://polaris.zincha.com",
            boot_nodes: NO_BOOT_NODES,
            explorer_url: Some("https://polaris.zinscan.com"),
            faucet_url: Some("https://faucet.polaris.zincha.com"),
        },
        ReleaseName::Vega => ReleaseSpec {
            name,
            slug: "vega",
            display_name: "Vega",
            stage: ReleaseStage::PublicTestnet,
            chain_id: "zincha-vega-1",
            canonical_rpc_url: "https://vega.zincha.com",
            canonical_websocket_url: "wss://vega.zincha.com",
            boot_nodes: VEGA_BOOT_NODES,
            explorer_url: Some("https://vega.zinscan.com"),
            faucet_url: Some("https://faucet.vega.zincha.com"),
        },
        ReleaseName::Sirius => ReleaseSpec {
            name,
            slug: "sirius",
            display_name: "Sirius",
            stage: ReleaseStage::IncentivizedTestnet,
            chain_id: "zincha-sirius-1",
            canonical_rpc_url: "https://sirius.zincha.com",
            canonical_websocket_url: "wss://sirius.zincha.com",
            boot_nodes: SIRIUS_BOOT_NODES,
            explorer_url: Some("https://sirius.zinscan.com"),
            faucet_url: Some("https://faucet.sirius.zincha.com"),
        },
        ReleaseName::Altair => ReleaseSpec {
            name,
            slug: "altair",
            display_name: "Altair",
            stage: ReleaseStage::Mainnet,
            chain_id: "zincha-altair-1",
            canonical_rpc_url: "https://altair.zincha.com",
            canonical_websocket_url: "wss://altair.zincha.com",
            boot_nodes: NO_BOOT_NODES,
            explorer_url: Some("https://altair.zinscan.com"),
            faucet_url: None,
        },
        ReleaseName::Lyra => ReleaseSpec {
            name,
            slug: "lyra",
            display_name: "Lyra",
            stage: ReleaseStage::MainnetUpgrade,
            chain_id: "zincha-altair-1",
            canonical_rpc_url: "https://lyra.zincha.com",
            canonical_websocket_url: "wss://lyra.zincha.com",
            boot_nodes: NO_BOOT_NODES,
            explorer_url: Some("https://lyra.zinscan.com"),
            faucet_url: None,
        },
    }
}

pub fn release_from_chain_id(chain_id: &str) -> Option<ReleaseName> {
    match chain_id {
        "zincha-polaris-1" => Some(ReleaseName::Polaris),
        "zincha-vega-1" => Some(ReleaseName::Vega),
        "zincha-sirius-1" => Some(ReleaseName::Sirius),
        "zincha-altair-1" => Some(ReleaseName::Altair),
        _ => None,
    }
}

pub fn spec_for_chain_id(chain_id: &str) -> Option<ReleaseSpec> {
    release_from_chain_id(chain_id).map(release_spec)
}

pub fn canonical_rpc_url_for_alias(raw: &str) -> Option<&'static str> {
    ReleaseName::parse_alias(raw).map(|name| name.spec().canonical_rpc_url)
}

pub fn canonical_websocket_url_for_alias(raw: &str) -> Option<&'static str> {
    ReleaseName::parse_alias(raw).map(|name| name.spec().canonical_websocket_url)
}
