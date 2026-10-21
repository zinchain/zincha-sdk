# zincha-client

Rust HTTP, WebSocket and conversation clients for Zincha.

```sh
cargo add zincha-client@0.1.2
```

This is the initial SDK package for the Vega testnet. See the
[SDK documentation](https://github.com/zinchain/zincha-sdk) for examples and
the [binary releases](https://github.com/zinchain/zincha-releases/releases/tag/v0.1.0)
for prebuilt CLI downloads.

Licensed under Apache-2.0.

## 0.1.1

Release-selected clients now use the release faucet URL unless explicitly
overridden. Transaction waiting requires a terminal confirmed or rejected
receipt, so a prepared receipt no longer ends the wait.
