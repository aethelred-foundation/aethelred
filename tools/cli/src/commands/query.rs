//! Query commands.

use anyhow::{anyhow, Context, Result};
use serde_json::json;

use crate::commands::api::{print_value, ApiClient};
use crate::config::Config;
use crate::QueryArgs;

pub async fn run(args: QueryArgs, config: &Config) -> Result<()> {
    let client = ApiClient::new(config)?;
    let query_type = args.query_type.to_lowercase();

    let response = match query_type.as_str() {
        "status" => client.get_api("/v1/status", &[]).await,
        "block" => {
            let height = args
                .params
                .first()
                .ok_or_else(|| anyhow!("query 'block' requires a block height parameter"))?;
            client
                .get_api(
                    "/cosmos/base/tendermint/v1beta1/blocks/latest",
                    &[("height", height.clone())],
                )
                .await
        }
        "tx" => {
            let hash = args
                .params
                .first()
                .ok_or_else(|| anyhow!("query 'tx' requires a transaction hash"))?;
            client.get_api(&format!("/v1/transactions/{hash}"), &[]).await
        }
        "account" => {
            let address = args
                .params
                .first()
                .ok_or_else(|| anyhow!("query 'account' requires an address"))?;
            client.get_api(&format!("/v1/accounts/{address}"), &[]).await
        }
        "model" => {
            let model_id = args
                .params
                .first()
                .ok_or_else(|| anyhow!("query 'model' requires a model ID/hash"))?;
            client
                .get_api(&format!("/aethelred/pouw/v1/models/{model_id}"), &[])
                .await
        }
        "seal" => {
            let seal_id = args
                .params
                .first()
                .ok_or_else(|| anyhow!("query 'seal' requires a seal ID"))?;
            client
                .get_api(&format!("/aethelred/seal/v1/seals/{seal_id}"), &[])
                .await
        }
        "job" => {
            let job_id = args
                .params
                .first()
                .ok_or_else(|| anyhow!("query 'job' requires a job ID"))?;
            client
                .get_api(&format!("/aethelred/pouw/v1/jobs/{job_id}"), &[])
                .await
        }
        other => Err(anyhow!(
            "unsupported query type '{other}', expected one of: status, block, tx, account, model, seal, job"
        )),
    }
    .with_context(|| format!("query failed for type '{}'", args.query_type))?;

    if args.raw {
        println!("{}", serde_json::to_string(&response)?);
        return Ok(());
    }

    print_value(
        &json!({ "query": args.query_type, "result": response }),
        &config.output_format,
    )
}
