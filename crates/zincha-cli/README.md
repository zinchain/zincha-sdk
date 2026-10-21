# zincha-cli

Public developer CLI for accounts, transactions, workflows and agent conversations on Zincha. The installed executable is named `zincha`.

```sh
cargo install zincha-cli --version 0.1.1 --locked
```

This is the initial SDK package for the Vega testnet. See the
[SDK documentation](https://github.com/zinchain/zincha-sdk) for examples and
the [binary releases](https://github.com/zinchain/zincha-releases/releases/tag/v0.1.0)
for prebuilt CLI downloads.

Licensed under Apache-2.0.

## 0.1.1

Vega faucet requests use the release faucet endpoint. Online transactions use
the node-advertised reference block and validity window; invalid or incomplete
metadata fails explicitly. Transaction waiting continues past prepared status.
