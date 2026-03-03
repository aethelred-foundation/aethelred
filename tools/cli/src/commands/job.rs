//! Job management commands.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::commands::api::{file_sha256_hex, print_value, read_file_string, ApiClient};
use crate::config::Config;
use crate::JobCommands;

pub async fn run(cmd: JobCommands, config: &Config) -> Result<()> {
    let client = ApiClient::new(config)?;

    match cmd {
        JobCommands::Submit(args) => {
            let input_hash = file_sha256_hex(&args.input)?;
            let input_preview = read_file_string(&args.input).unwrap_or_default();
            let payload = json!({
                "model_id": args.model,
                "input_hash": input_hash,
                "input_preview": truncate_for_payload(&input_preview),
                "priority": args.priority,
                "timeout_seconds": args.timeout,
                "require_tee": args.require_tee,
                "generate_proof": args.generate_proof
            });
            let response = client
                .post_api("/aethelred/pouw/v1/jobs", &payload)
                .await
                .context("failed to submit job")?;
            print_value(&response, &config.output_format)?;

            if args.wait {
                let job_id = extract_job_id(&response)
                    .ok_or_else(|| anyhow!("could not infer job ID from submit response"))?;
                wait_for_completion(&client, config, &job_id, args.timeout).await?;
            }
        }
        JobCommands::List(args) => {
            let mut query: Vec<(&str, String)> = vec![("limit", args.limit.to_string())];
            if let Some(status) = args.status {
                query.push(("status", status));
            }
            if let Some(model) = args.model {
                query.push(("model_hash", model));
            }
            if args.mine {
                query.push(("mine", "true".to_string()));
            }

            let response = client
                .get_api("/aethelred/pouw/v1/jobs", &query)
                .await
                .context("failed to list jobs")?;
            print_value(&response, &config.output_format)?;
        }
        JobCommands::Get { job_id } => {
            let response = client
                .get_api(&format!("/aethelred/pouw/v1/jobs/{job_id}"), &[])
                .await
                .with_context(|| format!("failed to fetch job '{job_id}'"))?;
            print_value(&response, &config.output_format)?;
        }
        JobCommands::Wait { job_id, timeout } => {
            wait_for_completion(&client, config, &job_id, timeout).await?;
        }
        JobCommands::Cancel { job_id } => {
            let response = client
                .post_api(
                    &format!("/aethelred/pouw/v1/jobs/{job_id}/cancel"),
                    &json!({}),
                )
                .await
                .with_context(|| format!("failed to cancel job '{job_id}'"))?;
            print_value(&response, &config.output_format)?;
        }
        JobCommands::Logs { job_id, follow } => {
            if follow {
                follow_logs(&client, config, &job_id).await?;
            } else {
                let response = client
                    .get_api(&format!("/aethelred/pouw/v1/jobs/{job_id}/logs"), &[])
                    .await
                    .with_context(|| format!("failed to fetch logs for job '{job_id}'"))?;
                print_value(&response, &config.output_format)?;
            }
        }
        JobCommands::Retry { job_id } => {
            let response = client
                .post_api(
                    &format!("/aethelred/pouw/v1/jobs/{job_id}/retry"),
                    &json!({}),
                )
                .await
                .with_context(|| format!("failed to retry job '{job_id}'"))?;
            print_value(&response, &config.output_format)?;
        }
    }

    Ok(())
}

async fn wait_for_completion(
    client: &ApiClient,
    config: &Config,
    job_id: &str,
    timeout_seconds: u64,
) -> Result<()> {
    let started = Instant::now();
    let timeout = Duration::from_secs(timeout_seconds);

    loop {
        let response = client
            .get_api(&format!("/aethelred/pouw/v1/jobs/{job_id}"), &[])
            .await
            .with_context(|| format!("failed polling job '{job_id}'"))?;
        let status = extract_status(&response).unwrap_or("unknown".to_string());

        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            print_value(&response, &config.output_format)?;
            return Ok(());
        }
        if started.elapsed() > timeout {
            return Err(anyhow!(
                "timeout waiting for job '{job_id}' to complete after {}s",
                timeout_seconds
            ));
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn follow_logs(client: &ApiClient, config: &Config, job_id: &str) -> Result<()> {
    println!("Following logs for job '{job_id}' (Ctrl+C to stop)...");
    loop {
        let response = client
            .get_api(&format!("/aethelred/pouw/v1/jobs/{job_id}/logs"), &[])
            .await
            .with_context(|| format!("failed polling logs for job '{job_id}'"))?;
        print_value(&response, &config.output_format)?;
        sleep(Duration::from_secs(3)).await;
    }
}

fn extract_job_id(value: &Value) -> Option<String> {
    value
        .pointer("/job_id")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .or_else(|| {
            value
                .pointer("/job/id")
                .and_then(Value::as_str)
                .map(|s| s.to_string())
        })
}

fn extract_status(value: &Value) -> Option<String> {
    value
        .pointer("/status")
        .and_then(Value::as_str)
        .map(|s| s.to_lowercase())
        .or_else(|| {
            value
                .pointer("/job/status")
                .and_then(Value::as_str)
                .map(|s| s.to_lowercase())
        })
}

fn truncate_for_payload(input: &str) -> String {
    const MAX: usize = 2048;
    if input.len() <= MAX {
        return input.to_string();
    }
    input[..MAX].to_string()
}
