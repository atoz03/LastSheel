use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    VaultLocked,
    AuthFailed,
    HostkeyChanged,
    HostkeyUnknown,
    SudoRequired,
    DepMissing,
    PermissionDenied,
    NotFound,
    Conflict,
    Unsupported,
    IoError,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDto {
    pub code: ErrorCode,
    pub message: String,
}

impl ErrorDto {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBootstrapDto {
    pub product_name: String,
    pub version: String,
    pub active_milestone: String,
    pub default_download_dir: String,
    pub features: Vec<String>,
}

impl AppBootstrapDto {
    pub fn new(
        version: impl Into<String>,
        default_download_dir: impl Into<String>,
        features: Vec<String>,
    ) -> Self {
        Self {
            product_name: "LastSheel".to_string(),
            version: version.into(),
            active_milestone: "M2-本地终端MVP".to_string(),
            default_download_dir: default_download_dir.into(),
            features,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSessionDto {
    pub terminal_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalOutputEventDto {
    pub terminal_id: String,
    pub chunk_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalState {
    Connecting,
    Ready,
    Closed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalStatusEventDto {
    pub terminal_id: String,
    pub state: TerminalState,
    pub message: Option<String>,
}
