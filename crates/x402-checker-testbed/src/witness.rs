//! A witness backend: the protected resource, replaced by a server that only records that it was called.
//!
//! Point the resource server under test at it as its upstream. Every request is recorded with its headers and
//! body, and answered as the [`WitnessScript`] says, so that a test can assert that the resource executed after
//! verification and before settlement (core spec, section 6.1), or that a failing resource was not settled.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use crate::recorder::{Endpoint, Recorder, header_map};

/// How the witness answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessScript {
    /// HTTP status of the answer.
    pub status: u16,
    /// Delay before answering, to test slow resources.
    pub latency: Duration,
}

impl Default for WitnessScript {
    /// A healthy resource: 200 without delay.
    fn default() -> Self {
        Self {
            status: 200,
            latency: Duration::ZERO,
        }
    }
}

#[derive(Clone)]
struct AppState {
    script: Arc<Mutex<WitnessScript>>,
    recorder: Recorder,
}

/// A running witness backend.
#[derive(Debug)]
pub struct Witness {
    addr: SocketAddr,
    script: Arc<Mutex<WitnessScript>>,
    recorder: Recorder,
    task: JoinHandle<()>,
}

impl Witness {
    /// Binds `listen` (port 0 picks a free port) and serves in a background task until dropped.
    pub async fn spawn(
        listen: SocketAddr,
        script: WitnessScript,
        recorder: Recorder,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(listen).await?;
        let addr = listener.local_addr()?;
        let script = Arc::new(Mutex::new(script));
        let state = AppState {
            script: Arc::clone(&script),
            recorder: recorder.clone(),
        };
        let app = Router::new()
            .route("/", any(handle))
            .route("/{*path}", any(handle))
            .with_state(state);
        let task = tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app).await {
                tracing::error!(%error, "witness backend stopped");
            }
        });
        Ok(Self {
            addr,
            script,
            recorder,
            task,
        })
    }

    /// Where it listens.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Base URL, for a resource server's upstream setting.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Replaces the script for the next scenario.
    pub fn set_script(&self, script: WitnessScript) {
        *self
            .script
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = script;
    }

    /// The shared recorder.
    pub fn recorder(&self) -> &Recorder {
        &self.recorder
    }
}

impl Drop for Witness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn handle(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let seq = state.recorder.start(
        Endpoint::Backend,
        method.as_str(),
        &uri.to_string(),
        header_map(&headers),
        &body,
    );
    let script = state
        .script
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    tokio::time::sleep(script.latency).await;
    let status = StatusCode::from_u16(script.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value =
        json!({ "witness": true, "seq": seq, "method": method.as_str(), "path": uri.to_string() });
    let response = (status, axum::Json(body)).into_response();
    state.recorder.finish(seq, response.status().as_u16());
    response
}
