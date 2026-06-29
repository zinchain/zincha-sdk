"""Release catalog shared with the Rust node release branding."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass(frozen=True)
class ReleaseSpec:
    name: str
    slug: str
    display_name: str
    stage: str
    chain_id: str
    canonical_rpc_url: str
    canonical_websocket_url: str
    boot_nodes: Tuple[str, ...]
    explorer_url: Optional[str] = None
    faucet_url: Optional[str] = None


_VEGA_BOOT_NODES = (
    "/dns4/boot-1.vega.zincha.com/tcp/30333",
    "/dns4/boot-2.vega.zincha.com/tcp/30333",
)

_SIRIUS_BOOT_NODES = (
    "/dns4/boot-1.sirius.zincha.com/tcp/30333",
    "/dns4/boot-2.sirius.zincha.com/tcp/30333",
)


RELEASES: Dict[str, ReleaseSpec] = {
    "polaris": ReleaseSpec(
        name="polaris",
        slug="polaris",
        display_name="Polaris",
        stage="devnet",
        chain_id="zincha-polaris-1",
        canonical_rpc_url="https://polaris.zincha.com",
        canonical_websocket_url="wss://polaris.zincha.com",
        boot_nodes=(),
        explorer_url="https://explorer.polaris.zincha.com",
        faucet_url="https://faucet.polaris.zincha.com",
    ),
    "vega": ReleaseSpec(
        name="vega",
        slug="vega",
        display_name="Vega",
        stage="public-testnet",
        chain_id="zincha-vega-1",
        canonical_rpc_url="https://vega.zincha.com",
        canonical_websocket_url="wss://vega.zincha.com",
        boot_nodes=_VEGA_BOOT_NODES,
        explorer_url="https://vega.zinscan.com",
        faucet_url="https://faucet.vega.zincha.com",
    ),
    "sirius": ReleaseSpec(
        name="sirius",
        slug="sirius",
        display_name="Sirius",
        stage="incentivized-testnet",
        chain_id="zincha-sirius-1",
        canonical_rpc_url="https://sirius.zincha.com",
        canonical_websocket_url="wss://sirius.zincha.com",
        boot_nodes=_SIRIUS_BOOT_NODES,
        explorer_url="https://explorer.sirius.zincha.com",
        faucet_url="https://faucet.sirius.zincha.com",
    ),
    "altair": ReleaseSpec(
        name="altair",
        slug="altair",
        display_name="Altair",
        stage="mainnet",
        chain_id="zincha-altair-1",
        canonical_rpc_url="https://altair.zincha.com",
        canonical_websocket_url="wss://altair.zincha.com",
        boot_nodes=(),
        explorer_url="https://explorer.altair.zincha.com",
    ),
    "lyra": ReleaseSpec(
        name="lyra",
        slug="lyra",
        display_name="Lyra",
        stage="mainnet-upgrade",
        chain_id="zincha-altair-1",
        canonical_rpc_url="https://lyra.zincha.com",
        canonical_websocket_url="wss://lyra.zincha.com",
        boot_nodes=(),
        explorer_url="https://explorer.lyra.zincha.com",
    ),
}


def parse_release_name(value: str) -> str:
    normalized = value.strip().lower().replace("_", "-")
    if normalized in ("polaris", "devnet"):
        return "polaris"
    if normalized in ("vega", "public-testnet", "testnet"):
        return "vega"
    if normalized in ("sirius", "incentivized-testnet", "incentivized"):
        return "sirius"
    if normalized in ("altair", "mainnet"):
        return "altair"
    if normalized in ("lyra", "mainnet-upgrade"):
        return "lyra"
    raise ValueError(
        "unknown release %s; expected polaris, vega, sirius, altair, or lyra" % value
    )


def release_spec(name: str) -> ReleaseSpec:
    return RELEASES[parse_release_name(name)]


def release_from_chain_id(chain_id: str) -> Optional[str]:
    if chain_id == "zincha-polaris-1":
        return "polaris"
    if chain_id == "zincha-vega-1":
        return "vega"
    if chain_id == "zincha-sirius-1":
        return "sirius"
    if chain_id == "zincha-altair-1":
        return "altair"
    return None


def is_mainnet_release(name: str) -> bool:
    return release_spec(name).stage in ("mainnet", "mainnet-upgrade")
