//! Validators module for Aethelred SDK.

use crate::core::client::ClientInner;
use crate::core::error::Result;
use crate::core::types::{HardwareCapability, PageRequest, ValidatorStats};
use std::sync::Arc;

const BASE_PATH: &str = "/aethelred/pouw/v1";

pub struct ValidatorsModule {
    client: Arc<ClientInner>,
}

impl ValidatorsModule {
    pub(crate) fn new(client: Arc<ClientInner>) -> Self {
        Self { client }
    }

    pub async fn get_stats(&self, address: &str) -> Result<ValidatorStats> {
        self.client
            .get(&format!("{}/validators/{}/stats", BASE_PATH, address))
            .await
    }

    pub async fn list(&self, _pagination: Option<PageRequest>) -> Result<Vec<ValidatorStats>> {
        #[derive(serde::Deserialize)]
        struct Response {
            validators: Vec<ValidatorStats>,
        }
        let resp: Response = self
            .client
            .get(&format!("{}/validators", BASE_PATH))
            .await?;
        Ok(resp.validators)
    }

    pub async fn register_capability(
        &self,
        address: &str,
        capability: HardwareCapability,
    ) -> Result<()> {
        #[derive(serde::Serialize)]
        struct Request {
            hardware_capabilities: HardwareCapability,
        }
        self.client
            .post::<serde_json::Value, _>(
                &format!("{}/validators/{}/capability", BASE_PATH, address),
                &Request {
                    hardware_capabilities: capability,
                },
            )
            .await?;
        Ok(())
    }
}
