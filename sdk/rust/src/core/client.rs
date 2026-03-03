//! Main client for Aethelred SDK.

use reqwest::{Client, Response};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

use crate::core::config::{Config, Network};
use crate::core::error::{AethelredError, Result};
use crate::core::types::NodeInfo;
use crate::jobs::JobsModule;
use crate::models::ModelsModule;
use crate::seals::SealsModule;
use crate::validators::ValidatorsModule;
use crate::verification::VerificationModule;

/// Main client for interacting with Aethelred blockchain.
pub struct AethelredClient {
    config: Config,
    http: Client,
    jobs: JobsModule,
    seals: SealsModule,
    models: ModelsModule,
    validators: ValidatorsModule,
    verification: VerificationModule,
}

impl AethelredClient {
    /// Create a new client with the specified network.
    pub async fn new(network: Network) -> Result<Self> {
        Self::with_config(Config::new(network)).await
    }

    /// Create a new client with custom configuration.
    pub async fn with_config(config: Config) -> Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Content-Type", "application/json".parse().unwrap());
        headers.insert(
            "User-Agent",
            concat!("aethelred-sdk-rust/", env!("CARGO_PKG_VERSION"))
                .parse()
                .unwrap(),
        );

        if let Some(ref api_key) = config.api_key {
            headers.insert(
                "X-API-Key",
                api_key.parse().map_err(|_| AethelredError::Validation {
                    message: "Invalid API key".into(),
                    field: Some("api_key".into()),
                })?,
            );
        }

        let http = Client::builder()
            .timeout(config.timeout)
            .default_headers(headers)
            .build()?;

        let client = Arc::new(ClientInner {
            config: config.clone(),
            http,
        });

        Ok(Self {
            config,
            http: client.http.clone(),
            jobs: JobsModule::new(client.clone()),
            seals: SealsModule::new(client.clone()),
            models: ModelsModule::new(client.clone()),
            validators: ValidatorsModule::new(client.clone()),
            verification: VerificationModule::new(client),
        })
    }

    /// Create a mainnet client.
    pub async fn mainnet() -> Result<Self> {
        Self::new(Network::Mainnet).await
    }

    /// Create a testnet client.
    pub async fn testnet() -> Result<Self> {
        Self::new(Network::Testnet).await
    }

    /// Create a local client.
    pub async fn local() -> Result<Self> {
        Self::new(Network::Local).await
    }

    /// Get the jobs module.
    pub fn jobs(&self) -> &JobsModule {
        &self.jobs
    }

    /// Get the seals module.
    pub fn seals(&self) -> &SealsModule {
        &self.seals
    }

    /// Get the models module.
    pub fn models(&self) -> &ModelsModule {
        &self.models
    }

    /// Get the validators module.
    pub fn validators(&self) -> &ValidatorsModule {
        &self.validators
    }

    /// Get the verification module.
    pub fn verification(&self) -> &VerificationModule {
        &self.verification
    }

    /// Get node information.
    pub async fn get_node_info(&self) -> Result<NodeInfo> {
        let url = format!(
            "{}/cosmos/base/tendermint/v1beta1/node_info",
            self.config.get_rpc_url()
        );
        let resp: serde_json::Value = self.http.get(&url).send().await?.json().await?;
        let info = serde_json::from_value(resp["default_node_info"].clone())?;
        Ok(info)
    }

    /// Check if the node is healthy.
    pub async fn health_check(&self) -> bool {
        self.get_node_info().await.is_ok()
    }

    /// Get the RPC URL.
    pub fn rpc_url(&self) -> &str {
        self.config.get_rpc_url()
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> &str {
        self.config.get_chain_id()
    }
}

pub(crate) struct ClientInner {
    pub config: Config,
    pub http: Client,
}

impl ClientInner {
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.config.get_rpc_url(), path);
        let resp = self.http.get(&url).send().await?;
        self.handle_response(resp).await
    }

    pub async fn post<T: DeserializeOwned, B: Serialize>(&self, path: &str, body: &B) -> Result<T> {
        let url = format!("{}{}", self.config.get_rpc_url(), path);
        let resp = self.http.post(&url).json(body).send().await?;
        self.handle_response(resp).await
    }

    async fn handle_response<T: DeserializeOwned>(&self, resp: Response) -> Result<T> {
        let status = resp.status();

        if status == 429 {
            let retry_after = resp
                .headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());
            return Err(AethelredError::RateLimit { retry_after });
        }

        if !status.is_success() {
            let message = resp.text().await.unwrap_or_default();
            return Err(AethelredError::Http {
                status: status.as_u16(),
                message,
            });
        }

        let data = resp.json().await?;
        Ok(data)
    }
}
