//! Models module for Aethelred SDK.

use crate::core::client::ClientInner;
use crate::core::error::Result;
use crate::core::types::{PageRequest, RegisteredModel, UtilityCategory};
use std::sync::Arc;

const BASE_PATH: &str = "/aethelred/pouw/v1";

#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisterModelRequest {
    pub model_hash: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<UtilityCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_uri: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RegisterModelResponse {
    pub model_hash: String,
    pub tx_hash: String,
}

pub struct ModelsModule {
    client: Arc<ClientInner>,
}

impl ModelsModule {
    pub(crate) fn new(client: Arc<ClientInner>) -> Self {
        Self { client }
    }

    pub async fn register(&self, request: RegisterModelRequest) -> Result<RegisterModelResponse> {
        self.client
            .post(&format!("{}/models", BASE_PATH), &request)
            .await
    }

    pub async fn get(&self, model_hash: &str) -> Result<RegisteredModel> {
        #[derive(serde::Deserialize)]
        struct Response {
            model: RegisteredModel,
        }
        let resp: Response = self
            .client
            .get(&format!("{}/models/{}", BASE_PATH, model_hash))
            .await?;
        Ok(resp.model)
    }

    pub async fn list(&self, _pagination: Option<PageRequest>) -> Result<Vec<RegisteredModel>> {
        #[derive(serde::Deserialize)]
        struct Response {
            models: Vec<RegisteredModel>,
        }
        let resp: Response = self.client.get(&format!("{}/models", BASE_PATH)).await?;
        Ok(resp.models)
    }
}
