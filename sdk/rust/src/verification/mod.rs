//! Verification module for Aethelred SDK.

use crate::core::client::ClientInner;
use crate::core::error::Result;
use crate::core::types::{TEEAttestation, TEEPlatform};
use std::sync::Arc;

const BASE_PATH: &str = "/aethelred/verify/v1";

#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyZKProofRequest {
    pub proof: String,
    pub public_inputs: Vec<String>,
    pub verifying_key_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_system: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VerifyZKProofResponse {
    pub valid: bool,
    pub verification_time_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct VerifyTEEResponse {
    pub valid: bool,
    pub platform: TEEPlatform,
    pub enclave_hash: Option<String>,
    pub error: Option<String>,
}

pub struct VerificationModule {
    client: Arc<ClientInner>,
}

impl VerificationModule {
    pub(crate) fn new(client: Arc<ClientInner>) -> Self {
        Self { client }
    }

    pub async fn verify_zk_proof(
        &self,
        request: VerifyZKProofRequest,
    ) -> Result<VerifyZKProofResponse> {
        self.client
            .post(&format!("{}/zkproofs:verify", BASE_PATH), &request)
            .await
    }

    pub async fn verify_tee_attestation(
        &self,
        attestation: TEEAttestation,
        expected_enclave_hash: Option<&str>,
    ) -> Result<VerifyTEEResponse> {
        #[derive(serde::Serialize)]
        struct Request<'a> {
            attestation: TEEAttestation,
            expected_enclave_hash: Option<&'a str>,
        }
        self.client
            .post(
                &format!("{}/tee/attestation:verify", BASE_PATH),
                &Request {
                    attestation,
                    expected_enclave_hash,
                },
            )
            .await
    }
}
