//! Jobs module for Aethelred SDK.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use crate::core::client::ClientInner;
use crate::core::error::{AethelredError, Result};
use crate::core::types::{ComputeJob, JobStatus, PageRequest, ProofType};

const BASE_PATH: &str = "/aethelred/pouw/v1";

#[derive(Debug, Clone, serde::Serialize)]
pub struct SubmitJobRequest {
    pub model_hash: String,
    pub input_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_type: Option<ProofType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_gas: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_blocks: Option<u32>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub struct SubmitJobResponse {
    pub job_id: String,
    pub tx_hash: String,
    pub estimated_blocks: u32,
}

pub struct JobsModule {
    client: Arc<ClientInner>,
}

impl JobsModule {
    pub(crate) fn new(client: Arc<ClientInner>) -> Self {
        Self { client }
    }

    /// Submit a new compute job.
    ///
    /// Enterprise default: `proof_type` defaults to `ProofTypeHybrid` (TEE + zkML)
    /// for maximum assurance and audit compliance.
    pub async fn submit(&self, mut request: SubmitJobRequest) -> Result<SubmitJobResponse> {
        if request.proof_type.is_none() {
            request.proof_type = Some(ProofType::ProofTypeHybrid);
        }
        self.client
            .post(&format!("{}/jobs", BASE_PATH), &request)
            .await
    }

    /// Get a job by ID.
    pub async fn get(&self, job_id: &str) -> Result<ComputeJob> {
        #[derive(serde::Deserialize)]
        struct Response {
            job: ComputeJob,
        }
        let resp: Response = self
            .client
            .get(&format!("{}/jobs/{}", BASE_PATH, job_id))
            .await?;
        Ok(resp.job)
    }

    /// List jobs.
    pub async fn list(&self, _pagination: Option<PageRequest>) -> Result<Vec<ComputeJob>> {
        #[derive(serde::Deserialize)]
        struct Response {
            jobs: Vec<ComputeJob>,
        }
        let resp: Response = self.client.get(&format!("{}/jobs", BASE_PATH)).await?;
        Ok(resp.jobs)
    }

    /// Cancel a job.
    pub async fn cancel(&self, job_id: &str) -> Result<()> {
        self.client
            .post::<serde_json::Value, _>(&format!("{}/jobs/{}/cancel", BASE_PATH, job_id), &())
            .await?;
        Ok(())
    }

    /// Wait for a job to complete.
    pub async fn wait_for_completion(
        &self,
        job_id: &str,
        poll_interval: Duration,
        timeout: Duration,
    ) -> Result<ComputeJob> {
        let start = std::time::Instant::now();

        loop {
            let job = self.get(job_id).await?;

            match job.status {
                JobStatus::JobStatusCompleted
                | JobStatus::JobStatusFailed
                | JobStatus::JobStatusCancelled => {
                    return Ok(job);
                }
                _ => {}
            }

            if start.elapsed() > timeout {
                return Err(AethelredError::Timeout {
                    timeout_ms: timeout.as_millis() as u64,
                });
            }

            sleep(poll_interval).await;
        }
    }
}
