//! Zero-copy (borrowing) JSON seal parsing helpers.
//!
//! These structures borrow string slices from the source JSON buffer to avoid
//! unnecessary allocations on high-throughput verifier and validator paths.

use serde::Deserialize;

/// Borrowed seal envelope for `/aethelred/seal/v1/seals/{id}` responses.
#[derive(Debug, Deserialize)]
pub struct BorrowedSealEnvelope<'a> {
    #[serde(borrow)]
    pub seal: BorrowedDigitalSeal<'a>,
}

/// Borrowed digital seal payload with commonly used fields.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BorrowedDigitalSeal<'a> {
    pub id: &'a str,
    pub job_id: &'a str,
    pub model_hash: &'a str,
    pub input_commitment: &'a str,
    pub output_commitment: &'a str,
    pub model_commitment: &'a str,
    pub status: &'a str,
    pub requester: &'a str,
    pub created_at: &'a str,
    #[serde(default)]
    pub expires_at: Option<&'a str>,
    #[serde(default, borrow)]
    pub validators: Vec<BorrowedValidatorAttestation<'a>>,
    #[serde(default, borrow)]
    pub tee_attestation: Option<BorrowedTEEAttestation<'a>>,
}

/// Borrowed validator attestation record.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BorrowedValidatorAttestation<'a> {
    pub validator_address: &'a str,
    pub signature: &'a str,
    pub timestamp: &'a str,
    pub voting_power: &'a str,
}

/// Borrowed TEE attestation metadata (quote remains a borrowed string blob).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BorrowedTEEAttestation<'a> {
    pub platform: &'a str,
    pub quote: &'a str,
    pub enclave_hash: &'a str,
    pub timestamp: &'a str,
    #[serde(default)]
    pub nonce: Option<&'a str>,
}

/// Parse a borrowed seal envelope from JSON bytes.
pub fn parse_borrowed_seal_json<'a>(
    payload: &'a [u8],
) -> serde_json::Result<BorrowedSealEnvelope<'a>> {
    serde_json::from_slice(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mock_seal_without_allocating_owned_strings() {
        let raw = br#"{
          "seal": {
            "id": "seal_demo",
            "jobId": "job_local_001",
            "modelHash": "0xaaaabbbb",
            "inputCommitment": "0x1111",
            "outputCommitment": "0x2222",
            "modelCommitment": "0x3333",
            "status": "SEAL_STATUS_ACTIVE",
            "requester": "aethel1developer",
            "createdAt": "2026-02-23T00:00:00Z",
            "expiresAt": "2026-12-31T00:00:00Z",
            "validators": [
              {
                "validatorAddress": "aethelvaloper1abc",
                "signature": "0xsig1",
                "timestamp": "2026-02-23T00:00:01Z",
                "votingPower": "34"
              },
              {
                "validatorAddress": "aethelvaloper1def",
                "signature": "0xsig2",
                "timestamp": "2026-02-23T00:00:02Z",
                "votingPower": "33"
              }
            ],
            "teeAttestation": {
              "platform": "aws_nitro",
              "quote": "base64quote",
              "enclaveHash": "0xeee",
              "timestamp": "2026-02-23T00:00:03Z",
              "nonce": "nonce-1"
            }
          }
        }"#;

        let parsed = parse_borrowed_seal_json(raw).expect("parse borrowed seal");
        assert_eq!(parsed.seal.id, "seal_demo");
        assert_eq!(parsed.seal.job_id, "job_local_001");
        assert_eq!(parsed.seal.validators.len(), 2);
        assert_eq!(
            parsed.seal.validators[0].validator_address,
            "aethelvaloper1abc"
        );
        assert_eq!(
            parsed.seal.tee_attestation.as_ref().unwrap().platform,
            "aws_nitro"
        );
    }
}
