#[tokio::main]
async fn main() -> anyhow::Result<()> {
    zincha_cli_core::run().await
}
