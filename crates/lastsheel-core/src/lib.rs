use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    VaultLocked,
    AuthFailed,
    HostkeyChanged,
    HostkeyUnknown,
    ProxyJumpFailed,
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
            active_milestone: "M7-进程与服务(阶段1)".to_string(),
            default_download_dir: default_download_dir.into(),
            features,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TerminalSessionDto {
    pub terminal_id: String,
    pub connection_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSubscribeInputDto {
    pub connection_id: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSubscribeResultDto {
    pub subscription_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSetPathProbeInputDto {
    pub subscription_id: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorUpdateEventDto {
    pub connection_id: String,
    pub ts_ms: i64,
    pub kind: String,
    pub payload_json: String,
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
    #[serde(default = "default_host_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub proxy_jump: String,
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
    #[serde(default = "default_host_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub proxy_jump: String,
    pub tags: Vec<String>,
    pub note: String,
    pub pinned: bool,
}

fn default_host_auth_mode() -> String {
    "auto".to_string()
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHostItemDto {
    pub host_id: String,
    pub address: String,
    pub port: u16,
    pub algorithm: String,
    pub key_b64: String,
    pub fingerprint_sha256: String,
    pub trusted_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileEntryType {
    File,
    Dir,
    Symlink,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntryDto {
    pub name: String,
    pub path: String,
    pub entry_type: FileEntryType,
    pub size_bytes: u64,
    pub mtime_ms: i64,
    pub mode_octal: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsListResponseDto {
    pub cwd: String,
    pub entries: Vec<FileEntryDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsDeleteInputDto {
    pub host_id: String,
    pub paths: Vec<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsDeleteResultDto {
    pub deleted_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsReadTextInputDto {
    pub host_id: String,
    pub path: String,
    pub max_bytes: Option<usize>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsReadTextResultDto {
    pub path: String,
    pub text: String,
    pub encoding: String,
    pub mtime_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsWriteTextInputDto {
    pub host_id: String,
    pub path: String,
    pub text: String,
    pub encoding: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsWriteTextResultDto {
    pub new_mtime_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessListInputDto {
    pub host_id: String,
    pub password: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessItemDto {
    pub pid: u32,
    pub user: String,
    pub cpu_pct: f64,
    pub mem_pct: f64,
    pub stat: String,
    pub elapsed: String,
    pub command: String,
    pub command_line: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessListResultDto {
    pub sampled_at_ms: i64,
    pub items: Vec<ProcessItemDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSignalInputDto {
    pub host_id: String,
    pub password: Option<String>,
    pub pid: u32,
    pub signal: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessActionResultDto {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceListInputDto {
    pub host_id: String,
    pub password: Option<String>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceItemDto {
    pub unit: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceListResultDto {
    pub supported: bool,
    pub sampled_at_ms: i64,
    pub message: Option<String>,
    pub items: Vec<ServiceItemDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceActionInputDto {
    pub host_id: String,
    pub password: Option<String>,
    pub unit: String,
    pub action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceActionResultDto {
    pub ok: bool,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Queued,
    Running,
    Done,
    Error,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferUpdateEventDto {
    pub transfer_id: String,
    pub state: TransferState,
    pub done_bytes: u64,
    pub total_bytes: Option<u64>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferStartDto {
    pub transfer_id: String,
    pub resolved_local_path: Option<String>,
    pub resolved_remote_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferDownloadInputDto {
    pub host_id: String,
    pub remote_path: String,
    pub local_path: Option<String>,
    pub password: Option<String>,
    pub conflict_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferUploadInputDto {
    pub host_id: String,
    pub local_path: String,
    pub remote_path: String,
    pub password: Option<String>,
    pub conflict_policy: Option<String>,
    pub extract_after_upload: Option<bool>,
    pub extract_destination: Option<String>,
    pub remove_archive_after_extract: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivePackDownloadInputDto {
    pub host_id: String,
    pub paths: Vec<String>,
    pub archive_format: Option<String>,
    pub local_path: Option<String>,
    pub password: Option<String>,
    pub conflict_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferVerifyResultDto {
    pub ok: bool,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferVerifyState {
    Running,
    Done,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferVerifyEventDto {
    pub transfer_id: String,
    pub state: TransferVerifyState,
    pub sha256: Option<String>,
    pub message: Option<String>,
}
