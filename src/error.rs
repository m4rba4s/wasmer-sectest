use thiserror::Error;

#[derive(Debug, Error)]
pub enum SectestError {
    #[error("async execution worker failed: {0}")]
    AsyncJoin(#[from] tokio::task::JoinError),
    #[error("WASI sandbox setup failed: {0}")]
    WasiSandbox(String),
}
