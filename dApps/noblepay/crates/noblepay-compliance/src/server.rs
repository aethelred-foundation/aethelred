//! Axum HTTP server exposing the compliance engine over a REST API.
//!
//! ## Endpoints
//!
//! | Method | Path                  | Description                          |
//! |--------|-----------------------|--------------------------------------|
//! | POST   | `/v1/screen`          | Screen a single payment              |
//! | POST   | `/v1/screen/batch`    | Screen multiple payments             |
//! | GET    | `/v1/health`          | Health check with list freshness     |
//! | GET    | `/v1/metrics`         | Compliance pipeline metrics          |
//! | POST   | `/v1/sanctions/update`| Trigger sanctions list refresh       |

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use uuid::Uuid;

use crate::engine::ComplianceEngine;
use crate::types::*;

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Shared application state passed to all handlers.
#[derive(Clone)]
pub struct AppState {
    pub engine: ComplianceEngine,
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the Axum router with all compliance API routes.
pub fn build_router(engine: ComplianceEngine) -> Router {
    let state = AppState { engine };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        .route("/v1/screen", post(screen_payment))
        .route("/v1/screen/batch", post(screen_batch))
        .route("/v1/health", get(health_check))
        .route("/v1/metrics", get(get_metrics))
        .route("/v1/sanctions/update", post(update_sanctions))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Start the HTTP server with graceful shutdown.
pub async fn serve(engine: ComplianceEngine, addr: SocketAddr) -> anyhow::Result<()> {
    let app = build_router(engine);

    info!(%addr, "compliance API server starting");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("compliance API server stopped");
    Ok(())
}

/// Wait for SIGINT or SIGTERM for graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("received Ctrl+C, shutting down"),
        _ = terminate => info!("received SIGTERM, shutting down"),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// POST /v1/screen — Screen a single payment.
async fn screen_payment(
    State(state): State<AppState>,
    Json(req): Json<ScreeningRequest>,
) -> impl IntoResponse {
    let request_id = req.payment.id;
    let timeout_ms = req.timeout_ms;

    let mut headers = HeaderMap::new();
    headers.insert("X-Request-Id", request_id.to_string().parse().unwrap());
    headers.insert(
        "X-RateLimit-Limit",
        "1000".parse().unwrap(),
    );

    match state
        .engine
        .screen_payment(&req.payment, req.travel_rule_data.as_ref(), timeout_ms)
        .await
    {
        Ok(result) => {
            let response = ScreeningResponse {
                success: true,
                result: Some(result),
                error: None,
                request_id,
            };
            (StatusCode::OK, headers, Json(response))
        }
        Err(e) => {
            error!(request_id = %request_id, error = %e, "screening failed");
            let status = match &e {
                crate::ComplianceError::Timeout(_) => StatusCode::GATEWAY_TIMEOUT,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            let response = ScreeningResponse {
                success: false,
                result: None,
                error: Some(e.to_string()),
                request_id,
            };
            (status, headers, Json(response))
        }
    }
}

/// POST /v1/screen/batch — Screen multiple payments concurrently.
async fn screen_batch(
    State(state): State<AppState>,
    Json(req): Json<BatchScreeningRequest>,
) -> impl IntoResponse {
    let batch_size = req.payments.len();
    info!(batch_size, "batch screening request received");

    if batch_size > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "batch size exceeds maximum of 100"
            })),
        )
            .into_response();
    }

    let result = state.engine.screen_batch(req.payments).await;
    (StatusCode::OK, Json(result)).into_response()
}

/// GET /v1/health — Health check with sanctions list freshness.
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let freshness = state.engine.sanctions_db().list_freshness().await;
    let total_entries = state.engine.sanctions_db().total_entries().await;

    let lists: std::collections::HashMap<String, String> = freshness
        .iter()
        .map(|(list, ts)| (list.to_string(), ts.to_rfc3339()))
        .collect();

    let response = HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: Utc::now(),
        sanctions_lists: SanctionsListHealth {
            total_entries,
            last_updated: lists,
        },
    };

    (StatusCode::OK, Json(response))
}

/// GET /v1/metrics — Compliance pipeline metrics.
async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = state.engine.metrics();
    (StatusCode::OK, Json(metrics))
}

/// POST /v1/sanctions/update — Trigger sanctions list refresh.
async fn update_sanctions(State(state): State<AppState>) -> impl IntoResponse {
    match state.engine.refresh_sanctions_lists().await {
        Ok(()) => {
            let total = state.engine.sanctions_db().total_entries().await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "success": true,
                    "total_entries": total,
                    "updated_at": Utc::now().to_rfc3339()
                })),
            )
        }
        Err(e) => {
            error!(error = %e, "sanctions list update failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "success": false,
                    "error": e.to_string()
                })),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
    timestamp: chrono::DateTime<Utc>,
    sanctions_lists: SanctionsListHealth,
}

#[derive(Debug, Serialize, Deserialize)]
struct SanctionsListHealth {
    total_entries: usize,
    last_updated: std::collections::HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn test_app() -> Router {
        let engine = ComplianceEngine::new().await;
        build_router(engine)
    }

    #[tokio::test]
    async fn health_endpoint_returns_200() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/v1/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_200() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/v1/metrics")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn screen_endpoint_clean_payment() {
        let app = test_app().await;
        let screening_req = ScreeningRequest {
            payment: Payment::test_payment("clean-alice", "clean-bob", 5_000, "USD"),
            travel_rule_data: None,
            timeout_ms: None,
        };
        let body = serde_json::to_string(&screening_req).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/v1/screen")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn screen_batch_endpoint() {
        let app = test_app().await;
        let batch_req = BatchScreeningRequest {
            payments: vec![
                ScreeningRequest {
                    payment: Payment::test_payment("a", "b", 1000, "USD"),
                    travel_rule_data: None,
                    timeout_ms: None,
                },
                ScreeningRequest {
                    payment: Payment::test_payment("c", "d", 2000, "USD"),
                    travel_rule_data: None,
                    timeout_ms: None,
                },
            ],
        };
        let body = serde_json::to_string(&batch_req).unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/v1/screen/batch")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn sanctions_update_endpoint() {
        let app = test_app().await;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/sanctions/update")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let app = test_app().await;
        let req = Request::builder()
            .uri("/v1/nonexistent")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
