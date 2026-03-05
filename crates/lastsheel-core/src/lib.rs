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
            active_milestone: "M3-Hosts+Vault+Store".to_string(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostItemDto {
    pub host_id: String,
    pub alias: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    pub tags: Vec<String>,
    pub note: String,
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostUpsertInputDto {
    pub host_id: Option<String>,
    pub alias: String,
    pub address: String,
    pub port: u16,
    pub username: String,
    pub tags: Vec<String>,
    pub note: String,
    pub pinned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultStatusDto {
    pub initialized: bool,
    pub unlocked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyImportResultDto {
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadataDto {
    pub key_id: String,
    pub name: String,
    pub has_passphrase: bool,
    pub created_at_ms: i64,
}
