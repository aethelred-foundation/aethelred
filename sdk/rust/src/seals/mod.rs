//! Seals module for Aethelred SDK.

pub mod borrowed;

use crate::core::client::ClientInner;
use crate::core::error::Result;
use crate::core::types::{DigitalSeal, PageRequest, RegulatoryInfo};
use std::sync::Arc;

const BASE_PATH: &str = "/aethelred/seal/v1";

pub use borrowed::{
    parse_borrowed_seal_json, BorrowedDigitalSeal, BorrowedSealEnvelope, BorrowedTEEAttestation,
    BorrowedValidatorAttestation,
};

#[derive(Debug, Clone, serde::Serialize)]
pub struct CreateSealRequest {
    pub job_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regulatory_info: Option<RegulatoryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_blocks: Option<u64>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct CreateSealResponse {
    pub seal_id: String,
    pub tx_hash: String,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VerifySealResponse {
    pub valid: bool,
    pub seal: Option<DigitalSeal>,
    pub verification_details: std::collections::HashMap<String, bool>,
    pub errors: Vec<String>,
}

pub struct SealsModule {
    client: Arc<ClientInner>,
}

impl SealsModule {
    pub(crate) fn new(client: Arc<ClientInner>) -> Self {
        Self { client }
    }

    pub async fn create(&self, request: CreateSealRequest) -> Result<CreateSealResponse> {
        self.client
            .post(&format!("{}/seals", BASE_PATH), &request)
            .await
    }

    pub async fn get(&self, seal_id: &str) -> Result<DigitalSeal> {
        #[derive(serde::Deserialize)]
        struct Response {
            seal: DigitalSeal,
        }
        let resp: Response = self
            .client
            .get(&format!("{}/seals/{}", BASE_PATH, seal_id))
            .await?;
        Ok(resp.seal)
    }

    pub async fn list(&self, _pagination: Option<PageRequest>) -> Result<Vec<DigitalSeal>> {
        #[derive(serde::Deserialize)]
        struct Response {
            seals: Vec<DigitalSeal>,
        }
        let resp: Response = self.client.get(&format!("{}/seals", BASE_PATH)).await?;
        Ok(resp.seals)
    }

    pub async fn verify(&self, seal_id: &str) -> Result<VerifySealResponse> {
        self.client
            .get(&format!("{}/seals/{}/verify", BASE_PATH, seal_id))
            .await
    }

    pub async fn revoke(&self, seal_id: &str, reason: &str) -> Result<()> {
        #[derive(serde::Serialize)]
        struct Request<'a> {
            reason: &'a str,
        }
        self.client
            .post::<serde_json::Value, _>(
                &format!("{}/seals/{}/revoke", BASE_PATH, seal_id),
                &Request { reason },
            )
            .await?;
        Ok(())
    }
}
