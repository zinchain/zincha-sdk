import type { ReleaseName, ReleaseSpec } from "./types.ts";

const VEGA_BOOT_NODES = [
  "/dns4/boot-1.vega.zincha.com/tcp/30333",
  "/dns4/boot-2.vega.zincha.com/tcp/30333",
] as const;

const SIRIUS_BOOT_NODES = [
  "/dns4/boot-1.sirius.zincha.com/tcp/30333",
  "/dns4/boot-2.sirius.zincha.com/tcp/30333",
] as const;

export const RELEASES: Record<ReleaseName, ReleaseSpec> = {
  polaris: {
    name: "polaris",
    slug: "polaris",
    displayName: "Polaris",
    stage: "devnet",
    chainId: "zincha-polaris-1",
    canonicalRpcUrl: "https://polaris.zincha.com",
    canonicalWebsocketUrl: "wss://polaris.zincha.com",
    bootNodes: [],
    explorerUrl: "https://explorer.polaris.zincha.com",
    faucetUrl: "https://faucet.polaris.zincha.com",
  },
  vega: {
    name: "vega",
    slug: "vega",
    displayName: "Vega",
    stage: "public-testnet",
    chainId: "zincha-vega-1",
    canonicalRpcUrl: "https://vega.zincha.com",
    canonicalWebsocketUrl: "wss://vega.zincha.com",
    bootNodes: VEGA_BOOT_NODES,
    explorerUrl: "https://vega.zinscan.com",
    faucetUrl: "https://faucet.vega.zincha.com",
  },
  sirius: {
    name: "sirius",
    slug: "sirius",
    displayName: "Sirius",
    stage: "incentivized-testnet",
    chainId: "zincha-sirius-1",
    canonicalRpcUrl: "https://sirius.zincha.com",
    canonicalWebsocketUrl: "wss://sirius.zincha.com",
    bootNodes: SIRIUS_BOOT_NODES,
    explorerUrl: "https://explorer.sirius.zincha.com",
    faucetUrl: "https://faucet.sirius.zincha.com",
  },
  altair: {
    name: "altair",
    slug: "altair",
    displayName: "Altair",
    stage: "mainnet",
    chainId: "zincha-altair-1",
    canonicalRpcUrl: "https://altair.zincha.com",
    canonicalWebsocketUrl: "wss://altair.zincha.com",
    bootNodes: [],
    explorerUrl: "https://explorer.altair.zincha.com",
  },
  lyra: {
    name: "lyra",
    slug: "lyra",
    displayName: "Lyra",
    stage: "mainnet-upgrade",
    chainId: "zincha-altair-1",
    canonicalRpcUrl: "https://lyra.zincha.com",
    canonicalWebsocketUrl: "wss://lyra.zincha.com",
    bootNodes: [],
    explorerUrl: "https://explorer.lyra.zincha.com",
  },
};

export function parseReleaseName(value: string): ReleaseName {
  const normalized = value.trim().toLowerCase().replaceAll("_", "-");
  switch (normalized) {
    case "polaris":
    case "devnet":
      return "polaris";
    case "vega":
    case "public-testnet":
    case "testnet":
      return "vega";
    case "sirius":
    case "incentivized-testnet":
    case "incentivized":
      return "sirius";
    case "altair":
    case "mainnet":
      return "altair";
    case "lyra":
    case "mainnet-upgrade":
      return "lyra";
    default:
      throw new Error(
        `unknown release ${value}; expected polaris, vega, sirius, altair, or lyra`,
      );
  }
}

export function releaseSpec(name: ReleaseName | string): ReleaseSpec {
  return RELEASES[parseReleaseName(name)];
}

export function releaseFromChainId(chainId: string): ReleaseName | undefined {
  switch (chainId) {
    case "zincha-polaris-1":
      return "polaris";
    case "zincha-vega-1":
      return "vega";
    case "zincha-sirius-1":
      return "sirius";
    case "zincha-altair-1":
      return "altair";
    default:
      return undefined;
  }
}

export function isMainnetRelease(name: ReleaseName | string): boolean {
  const stage = releaseSpec(name).stage;
  return stage === "mainnet" || stage === "mainnet-upgrade";
}
