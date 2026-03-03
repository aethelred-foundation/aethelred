//! Shared API helpers for CLI command implementations.

use anyhow::{anyhow, Context, Result};
use reqwest::{Client, Method};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::config::Config;

pub struct ApiClient {
    client: Client,
    api_endpoint: String,
    rpc_endpoint: String,
}

impl ApiClient {
    pub fn new(config: &Config) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .build()
            .context("failed to create HTTP client")?;

        Ok(Self {
            client,
            api_endpoint: trim_trailing_slash(&config.api_endpoint),
            rpc_endpoint: trim_trailing_slash(&config.rpc_endpoint),
        })
    }

    pub async fn get_api<K: AsRef<str>, V: AsRef<str>>(
        &self,
        path: &str,
        query: &[(K, V)],
    ) -> Result<Value> {
        self.request_json(
            Method::GET,
            &format!("{}{}", self.api_endpoint, path),
            query,
            None,
        )
        .await
    }

    pub async fn post_api(&self, path: &str, body: &Value) -> Result<Value> {
        self.request_json(
            Method::POST,
            &format!("{}{}", self.api_endpoint, path),
            &[],
            Some(body),
        )
        .await
    }

    pub async fn put_api(&self, path: &str, body: &Value) -> Result<Value> {
        self.request_json(
            Method::PUT,
            &format!("{}{}", self.api_endpoint, path),
            &[],
            Some(body),
        )
        .await
    }

    pub async fn patch_api(&self, path: &str, body: &Value) -> Result<Value> {
        self.request_json(
            Method::PATCH,
            &format!("{}{}", self.api_endpoint, path),
            &[],
            Some(body),
        )
        .await
    }

    pub async fn get_rpc<K: AsRef<str>, V: AsRef<str>>(
        &self,
        path: &str,
        query: &[(K, V)],
    ) -> Result<Value> {
        self.request_json(
            Method::GET,
            &format!("{}{}", self.rpc_endpoint, path),
            query,
            None,
        )
        .await
    }

    async fn request_json<K: AsRef<str>, V: AsRef<str>>(
        &self,
        method: Method,
        url: &str,
        query: &[(K, V)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let query_pairs: Vec<(&str, &str)> = query
            .iter()
            .map(|(k, v)| (k.as_ref(), v.as_ref()))
            .collect();

        let mut request = self.client.request(method, url).query(&query_pairs);
        if let Some(payload) = body {
            request = request.json(payload);
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("request failed: {url}"))?;

        let status = response.status();
        let text = response
            .text()
            .await
            .context("failed to read response body")?;
        if !status.is_success() {
            return Err(anyhow!("request failed ({status}): {text}"));
        }

        if text.trim().is_empty() {
            return Ok(Value::Object(Map::new()));
        }

        serde_json::from_str(&text).or_else(|_| {
            Ok(Value::Object(Map::from_iter([(
                "raw_response".to_string(),
                Value::String(text),
            )])))
        })
    }
}

pub fn print_value(value: &Value, output_format: &str) -> Result<()> {
    match output_format {
        "json" => println!("{}", serde_json::to_string_pretty(value)?),
        "yaml" => println!("{}", serde_yaml::to_string(value)?),
        _ => println!("{}", serde_json::to_string_pretty(value)?),
    }
    Ok(())
}

pub fn parse_key_value_params(params: &[String]) -> Result<Map<String, Value>> {
    let mut output = Map::new();
    for item in params {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| anyhow!("invalid param '{item}', expected key=value"))?;
        output.insert(key.to_string(), Value::String(value.to_string()));
    }
    Ok(output)
}

pub fn file_sha256_hex(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    let hash = Sha256::digest(data);
    Ok(hex::encode(hash))
}

pub fn read_file_string(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))
}

fn trim_trailing_slash(value: &str) -> String {
    if value.ends_with('/') {
        value.trim_end_matches('/').to_string()
    } else {
        value.to_string()
    }
}
