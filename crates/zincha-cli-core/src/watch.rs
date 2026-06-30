use crate::output::emit;
use crate::CliContext;
use anyhow::Result;
use clap::Parser;
use serde_json::Value;
use zincha_client::ZinchaClient;

#[derive(Debug, Parser)]
pub struct WatchCommand {
    #[arg(long, default_value = "/v1/chain/info")]
    pub path: String,
}

pub async fn run_watch(
    command: WatchCommand,
    client: ZinchaClient,
    context: &CliContext,
) -> Result<()> {
    let payload: Value = client.get(&command.path).await?;
    emit("watch", payload, context.json)
}
