use anyhow::Result;
use serde_json::Value;

pub fn emit(command: &'static str, payload: Value, json: bool) -> Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": 1,
                "ok": true,
                "command": command,
                "data": payload,
            }))?
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    }
    Ok(())
}
