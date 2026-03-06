use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use lastsheel_core::{
    AppBootstrapDto, ArchivePackDownloadInputDto, ErrorCode, ErrorDto, FileEntryDto, FileEntryType,
    FsDeleteInputDto, FsDeleteResultDto, FsListResponseDto, FsReadTextInputDto,
    FsReadTextResultDto, FsWriteTextInputDto, FsWriteTextResultDto, HostItemDto,
    HostUpsertInputDto, KeyImportResultDto, KeyMetadataDto, KnownHostItemDto,
    MonitorSetPathProbeInputDto, MonitorSubscribeInputDto, MonitorSubscribeResultDto,
    MonitorUpdateEventDto, ProcessActionResultDto, ProcessItemDto, ProcessListInputDto,
    ProcessListResultDto, ProcessSignalInputDto, ServiceActionInputDto, ServiceActionResultDto,
    ServiceItemDto, ServiceListInputDto, ServiceListResultDto, TerminalOutputEventDto,
    TerminalSessionDto, TerminalState, TerminalStatusEventDto, TransferDownloadInputDto,
    TransferStartDto, TransferState, TransferUpdateEventDto, TransferUploadInputDto,
    TransferVerifyEventDto, TransferVerifyResultDto, TransferVerifyState, VaultStatusDto,
};
use parking_lot::Mutex;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager, State};
use uuid::Uuid;

struct TerminalSession {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send>,
    cleanup_paths: Vec<PathBuf>,
}

#[derive(Default)]
struct TerminalManager {
    sessions: Mutex<HashMap<String, TerminalSession>>,
}

#[derive(Default)]
struct HostsStoreManager {
    lock: Mutex<()>,
}

#[derive(Default)]
struct KnownHostsStoreManager {
    lock: Mutex<()>,
}

#[derive(Default)]
struct VaultManager {
    runtime: Mutex<VaultRuntime>,
}

struct TransferControl {
    canceled: Arc<AtomicBool>,
}

#[derive(Clone)]
struct TransferRecord {
    transfer_id: String,
    direction: String,
    local_path: Option<PathBuf>,
    state: TransferState,
}

#[derive(Default)]
struct TransferManager {
    items: Mutex<HashMap<String, TransferControl>>,
    records: Mutex<HashMap<String, TransferRecord>>,
}

#[derive(Clone)]
struct SshConnectionContext {
    connection_id: String,
    host: HostItemDto,
    prepared_auth: PreparedSshAuth,
}

#[derive(Default)]
struct SshConnectionManager {
    connections: Mutex<HashMap<String, SshConnectionContext>>,
    terminal_to_connection: Mutex<HashMap<String, String>>,
}

struct MonitorSubscriptionControl {
    connection_id: String,
    profile: String,
    canceled: Arc<AtomicBool>,
    path_probe_paths: Arc<Mutex<Vec<String>>>,
}

#[derive(Default)]
struct MonitorManager {
    items: Mutex<HashMap<String, MonitorSubscriptionControl>>,
}

#[derive(Default)]
struct VaultRuntime {
    initialized: bool,
    unlocked: bool,
    salt: Option<[u8; 16]>,
    key: Option<[u8; 32]>,
    data: VaultDataFile,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HostsStoreFile {
    items: Vec<HostItemDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KnownHostsStoreFile {
    items: Vec<KnownHostItemDto>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct VaultDataFile {
    keys: Vec<StoredPrivateKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredPrivateKey {
    key_id: String,
    name: String,
    pem_text: String,
    passphrase: Option<String>,
    created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct VaultFileEnvelope {
    version: u8,
    salt_b64: String,
    nonce_b64: String,
    cipher_b64: String,
}

const FS_READ_TEXT_DEFAULT_MAX_BYTES: usize = 2_000_000;
const REMOTE_DELETE_MAX_DEPTH: usize = 128;
const MONITOR_PATH_PROBE_MAX_PATHS: usize = 10;

fn emit_terminal_status(
    app: &tauri::AppHandle,
    terminal_id: &str,
    state: TerminalState,
    message: Option<String>,
) {
    let _ = app.emit(
        "terminal.status",
        TerminalStatusEventDto {
            terminal_id: terminal_id.to_string(),
            state,
            message,
        },
    );
}

fn emit_transfer_update(
    app: &tauri::AppHandle,
    transfer_id: &str,
    state: TransferState,
    done_bytes: u64,
    total_bytes: Option<u64>,
    message: Option<String>,
) {
    let _ = app.emit(
        "transfer.update",
        TransferUpdateEventDto {
            transfer_id: transfer_id.to_string(),
            state,
            done_bytes,
            total_bytes,
            message,
        },
    );
}

fn emit_transfer_verify(
    app: &tauri::AppHandle,
    transfer_id: &str,
    state: TransferVerifyState,
    sha256: Option<String>,
    message: Option<String>,
) {
    let _ = app.emit(
        "transfer.verify",
        TransferVerifyEventDto {
            transfer_id: transfer_id.to_string(),
            state,
            sha256,
            message,
        },
    );
}

fn emit_monitor_update(
    app: &tauri::AppHandle,
    connection_id: &str,
    kind: &str,
    payload_json: String,
) {
    let _ = app.emit(
        "monitor.update",
        MonitorUpdateEventDto {
            connection_id: connection_id.to_string(),
            ts_ms: current_time_ms().unwrap_or(0),
            kind: kind.to_string(),
            payload_json,
        },
    );
}

fn app_store_dir(app: &tauri::AppHandle) -> Result<PathBuf, ErrorDto> {
    let base = app
        .path()
        .app_data_dir()
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "无法读取应用数据目录"))?;
    let dir = base.join("store");
    fs::create_dir_all(&dir)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建应用数据目录失败"))?;
    Ok(dir)
}

fn hosts_store_path(app: &tauri::AppHandle) -> Result<PathBuf, ErrorDto> {
    Ok(app_store_dir(app)?.join("hosts.json"))
}

fn known_hosts_store_path(app: &tauri::AppHandle) -> Result<PathBuf, ErrorDto> {
    Ok(app_store_dir(app)?.join("known_hosts.json"))
}

fn known_hosts_ssh_path(app: &tauri::AppHandle) -> Result<PathBuf, ErrorDto> {
    Ok(app_store_dir(app)?.join("known_hosts"))
}

fn vault_store_path(app: &tauri::AppHandle) -> Result<PathBuf, ErrorDto> {
    Ok(app_store_dir(app)?.join("vault.lsv"))
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ErrorDto> {
    let parent = path
        .parent()
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "无效文件路径"))?;
    fs::create_dir_all(parent).map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建目录失败"))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "无效文件名"))?;
    let temp_path = parent.join(format!(".{}.tmp.{}", file_name, Uuid::new_v4()));
    fs::write(&temp_path, bytes)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "写入临时文件失败"))?;

    if path.exists() {
        fs::remove_file(path).map_err(|_| ErrorDto::new(ErrorCode::IoError, "替换目标文件失败"))?;
    }
    fs::rename(&temp_path, path).map_err(|_| ErrorDto::new(ErrorCode::IoError, "提交文件失败"))?;
    Ok(())
}

fn load_hosts_from_disk(app: &tauri::AppHandle) -> Result<HostsStoreFile, ErrorDto> {
    let path = hosts_store_path(app)?;
    if !path.exists() {
        return Ok(HostsStoreFile::default());
    }

    let text = fs::read_to_string(path)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取 Hosts 存储失败"))?;
    serde_json::from_str(&text)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "解析 Hosts 数据失败"))
}

fn save_hosts_to_disk(app: &tauri::AppHandle, store: &HostsStoreFile) -> Result<(), ErrorDto> {
    let path = hosts_store_path(app)?;
    let body = serde_json::to_vec_pretty(store)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "序列化 Hosts 数据失败"))?;
    write_atomic(&path, &body)
}

fn load_known_hosts_from_disk(app: &tauri::AppHandle) -> Result<KnownHostsStoreFile, ErrorDto> {
    let path = known_hosts_store_path(app)?;
    if !path.exists() {
        return Ok(KnownHostsStoreFile::default());
    }

    let text = fs::read_to_string(path)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取 known_hosts 存储失败"))?;
    serde_json::from_str(&text)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "解析 known_hosts 数据失败"))
}

fn save_known_hosts_to_disk(
    app: &tauri::AppHandle,
    store: &KnownHostsStoreFile,
) -> Result<(), ErrorDto> {
    let path = known_hosts_store_path(app)?;
    let body = serde_json::to_vec_pretty(store)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "序列化 known_hosts 数据失败"))?;
    write_atomic(&path, &body)?;

    let ssh_path = known_hosts_ssh_path(app)?;
    let mut lines: Vec<String> = Vec::new();
    for item in &store.items {
        lines.push(format!(
            "[{}]:{} {} {}",
            item.address, item.port, item.algorithm, item.key_b64
        ));
    }
    let body = lines.join("\n");
    write_atomic(&ssh_path, body.as_bytes())?;
    Ok(())
}

fn current_time_ms() -> Result<i64, ErrorDto> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "系统时间异常"))?
        .as_millis() as i64)
}

fn command_exists(command: &str) -> bool {
    ProcessCommand::new(command).arg("-V").output().is_ok()
}

fn ensure_dependency(command: &str, install_hint: &str) -> Result<(), ErrorDto> {
    if command_exists(command) {
        return Ok(());
    }
    Err(ErrorDto::new(
        ErrorCode::DepMissing,
        format!("缺少依赖命令 `{command}`，请先安装（{install_hint}）"),
    ))
}

fn compact_stderr(stderr: &str) -> String {
    let one_line = stderr
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<&str>>()
        .join(" | ");
    if one_line.is_empty() {
        return "无详细输出".to_string();
    }
    if one_line.chars().count() <= 120 {
        return one_line;
    }
    let truncated: String = one_line.chars().take(120).collect();
    format!("{truncated}...")
}

fn quote_posix_shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn classify_management_command_error(stderr: &str, error_prefix: &str) -> ErrorDto {
    let detail = compact_stderr(stderr);
    let lower = detail.to_lowercase();
    if lower.contains("__systemctl_unsupported__") || lower.contains("command not found") {
        return ErrorDto::new(
            ErrorCode::DepMissing,
            format!("{error_prefix}：远端缺少 systemctl，当前主机可能不是 systemd 环境"),
        );
    }
    if lower.contains("authentication is required")
        || lower.contains("interactive authentication required")
        || lower.contains("access denied")
        || lower.contains("polkit")
    {
        return ErrorDto::new(
            ErrorCode::SudoRequired,
            format!("{error_prefix}：当前操作需要 sudo 或 systemd 授权"),
        );
    }
    if lower.contains("operation not permitted") || lower.contains("permission denied") {
        return ErrorDto::new(
            ErrorCode::PermissionDenied,
            format!("{error_prefix}：{detail}"),
        );
    }
    if lower.contains("no such process")
        || lower.contains("not loaded")
        || lower.contains("could not be found")
        || lower.contains("not found")
    {
        return ErrorDto::new(ErrorCode::NotFound, format!("{error_prefix}：{detail}"));
    }
    ErrorDto::new(ErrorCode::IoError, format!("{error_prefix}：{detail}"))
}

fn classify_hostkey_probe_error(
    stderr: &str,
    address: &str,
    port: u16,
    proxy_jump: &str,
) -> ErrorDto {
    let lower = stderr.to_lowercase();
    let has_proxy = !proxy_jump.trim().is_empty();
    let detail = compact_stderr(stderr);
    if has_proxy
        && (lower.contains("proxyjump")
            || lower.contains("jump host")
            || lower.contains("stdio forwarding failed")
            || lower.contains("kex_exchange_identification"))
    {
        return ErrorDto::new(
            ErrorCode::ProxyJumpFailed,
            format!("ProxyJump 链路失败（{proxy_jump}）：{detail}"),
        );
    }
    if lower.contains("could not resolve hostname")
        || lower.contains("name or service not known")
        || lower.contains("temporary failure in name resolution")
    {
        return ErrorDto::new(
            if has_proxy {
                ErrorCode::ProxyJumpFailed
            } else {
                ErrorCode::IoError
            },
            if has_proxy {
                format!("ProxyJump 地址解析失败（{proxy_jump}）：{detail}")
            } else {
                format!("远端地址解析失败（{address}:{port}）：{detail}")
            },
        );
    }
    if lower.contains("connection timed out") || lower.contains("operation timed out") {
        return ErrorDto::new(
            if has_proxy {
                ErrorCode::ProxyJumpFailed
            } else {
                ErrorCode::IoError
            },
            if has_proxy {
                format!("ProxyJump 链路超时（{proxy_jump}）：{detail}")
            } else {
                format!("连接远端主机超时（{address}:{port}）：{detail}")
            },
        );
    }
    if lower.contains("connection refused") {
        return ErrorDto::new(
            if has_proxy {
                ErrorCode::ProxyJumpFailed
            } else {
                ErrorCode::IoError
            },
            if has_proxy {
                format!("ProxyJump 链路被拒绝（{proxy_jump}）：{detail}")
            } else {
                format!("远端 SSH 端口拒绝连接（{address}:{port}）：{detail}")
            },
        );
    }
    if has_proxy {
        return ErrorDto::new(
            ErrorCode::ProxyJumpFailed,
            format!("ProxyJump 链路异常（{proxy_jump}）：{detail}"),
        );
    }
    ErrorDto::new(
        ErrorCode::IoError,
        format!("主机指纹探测失败（{address}:{port}）：{detail}"),
    )
}

fn probe_remote_host_key(
    address: &str,
    port: u16,
    proxy_jump: &str,
) -> Result<(String, String, String), ErrorDto> {
    ensure_dependency("ssh-keyscan", "OpenSSH 客户端套件")?;
    let mut command = ProcessCommand::new("ssh-keyscan");
    command
        .arg("-T")
        .arg("5")
        .arg("-p")
        .arg(port.to_string())
        .arg("-t")
        .arg("rsa,ecdsa,ed25519");
    if !proxy_jump.trim().is_empty() {
        command.arg("-J").arg(proxy_jump.trim());
    }
    command.arg(address);
    let output = command
        .output()
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "执行 ssh-keyscan 失败"))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let line = stdout
        .lines()
        .map(str::trim)
        .find(|value| !value.is_empty() && !value.starts_with('#'))
        .ok_or_else(|| classify_hostkey_probe_error(&stderr, address, port, proxy_jump))?;
    let mut parts = line.split_whitespace();
    let _host = parts.next();
    let algorithm = parts
        .next()
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "ssh-keyscan 返回格式异常"))?
        .to_string();
    let key_b64 = parts
        .next()
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "ssh-keyscan 返回格式异常"))?
        .to_string();

    let host_key = STANDARD
        .decode(&key_b64)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "主机公钥数据格式错误"))?;
    let fingerprint = format!(
        "SHA256:{}",
        STANDARD.encode(Sha256::digest(host_key.as_slice()))
    );
    Ok((algorithm, key_b64, fingerprint))
}

fn normalize_auth_mode(input: &str) -> String {
    match input.trim().to_lowercase().as_str() {
        "key" => "key".to_string(),
        "password" => "password".to_string(),
        "agent" => "agent".to_string(),
        _ => "auto".to_string(),
    }
}

fn normalize_conflict_policy(input: Option<&str>, default_value: &str) -> String {
    match input
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_value)
        .to_lowercase()
        .as_str()
    {
        "overwrite" => "overwrite".to_string(),
        "skip" => "skip".to_string(),
        _ => "rename".to_string(),
    }
}

fn normalize_archive_format(input: Option<&str>, default_value: &str) -> Result<String, ErrorDto> {
    match input
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_value)
        .to_lowercase()
        .as_str()
    {
        "tar_gz" | "tgz" => Ok("tar_gz".to_string()),
        "tar" => Ok("tar".to_string()),
        "tar_bz2" | "tbz2" | "tbz" => Ok("tar_bz2".to_string()),
        "tar_xz" | "txz" => Ok("tar_xz".to_string()),
        "zip" => Ok("zip".to_string()),
        _ => Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "当前仅支持 tar_gz / tar / tar_bz2 / tar_xz / zip 压缩格式",
        )),
    }
}

#[cfg(target_os = "windows")]
fn prepare_one_time_password(
    auth_mode: &str,
    password: Option<String>,
) -> Result<Option<String>, ErrorDto> {
    if auth_mode != "password" {
        return Ok(None);
    }
    if password
        .as_ref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "Windows 暂不支持一次性密码自动注入，请改用手动输入或其他认证方式",
        ));
    }
    Ok(None)
}

#[cfg(not(target_os = "windows"))]
fn prepare_one_time_password(
    auth_mode: &str,
    password: Option<String>,
) -> Result<Option<String>, ErrorDto> {
    if auth_mode != "password" {
        return Ok(None);
    }
    let value = password
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .ok_or_else(|| ErrorDto::new(ErrorCode::AuthFailed, "密码认证需要输入一次性密码"))?;
    Ok(Some(value))
}

fn validate_proxy_jump(proxy_jump: &str) -> Result<String, ErrorDto> {
    let normalized = proxy_jump.trim().to_string();
    if normalized.is_empty() {
        return Ok(String::new());
    }
    let hops: Vec<&str> = normalized.split(',').map(|hop| hop.trim()).collect();
    if hops.len() > 2 {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "ProxyJump 最多支持 2 跳（逗号分隔）",
        ));
    }
    if hops.iter().any(|hop| hop.is_empty()) {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "ProxyJump 格式错误，请使用 host 或 user@host",
        ));
    }
    for hop in &hops {
        if hop.contains(char::is_whitespace) {
            return Err(ErrorDto::new(
                ErrorCode::Unsupported,
                "ProxyJump 不能包含空白字符",
            ));
        }
        let host_part = hop.rsplit_once('@').map(|(_, value)| value).unwrap_or(hop);
        if host_part.is_empty() {
            return Err(ErrorDto::new(
                ErrorCode::Unsupported,
                "ProxyJump 格式错误，请使用 host 或 user@host",
            ));
        }
        if let Some((host, port_text)) = host_part.rsplit_once(':') {
            if host.is_empty() {
                return Err(ErrorDto::new(
                    ErrorCode::Unsupported,
                    "ProxyJump 主机名不能为空",
                ));
            }
            if port_text
                .parse::<u16>()
                .ok()
                .filter(|port| *port > 0)
                .is_none()
            {
                return Err(ErrorDto::new(
                    ErrorCode::Unsupported,
                    "ProxyJump 端口必须是 1-65535 的数字",
                ));
            }
        }
    }
    Ok(hops.join(","))
}

fn create_temp_private_key_file(
    app: &tauri::AppHandle,
    key_id: &str,
    pem_text: &str,
) -> Result<PathBuf, ErrorDto> {
    let dir = app_store_dir(app)?.join("tmp-keys");
    fs::create_dir_all(&dir)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建临时密钥目录失败"))?;
    let path = dir.join(format!("id_{}_{}", key_id, Uuid::new_v4()));
    write_atomic(&path, pem_text.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "设置私钥文件权限失败"))?;
    }
    Ok(path)
}

fn prepare_ssh_identity_file(
    app: &tauri::AppHandle,
    vault_manager: &State<VaultManager>,
    key_id: &str,
) -> Result<PathBuf, ErrorDto> {
    let runtime = vault_manager.runtime.lock();
    if !runtime.unlocked {
        return Err(ErrorDto::new(
            ErrorCode::VaultLocked,
            "使用密钥认证前请先解锁 Vault",
        ));
    }
    let key = runtime
        .data
        .keys
        .iter()
        .find(|item| item.key_id == key_id)
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "找不到指定的密钥"))?;
    create_temp_private_key_file(app, &key.key_id, &key.pem_text)
}

fn decode_fixed<const N: usize>(input: &str) -> Result<[u8; N], ErrorDto> {
    let bytes = STANDARD
        .decode(input)
        .map_err(|_| ErrorDto::new(ErrorCode::AuthFailed, "加密数据格式错误"))?;
    if bytes.len() != N {
        return Err(ErrorDto::new(ErrorCode::AuthFailed, "加密数据长度错误"));
    }

    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn derive_master_key(master_password: &str, salt: &[u8; 16]) -> Result<[u8; 32], ErrorDto> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(master_password.as_bytes(), salt, &mut key)
        .map_err(|_| ErrorDto::new(ErrorCode::AuthFailed, "主密码派生失败"))?;
    Ok(key)
}

fn encrypt_vault_payload(
    salt: &[u8; 16],
    key: &[u8; 32],
    payload: &VaultDataFile,
) -> Result<VaultFileEnvelope, ErrorDto> {
    let plaintext = serde_json::to_vec(payload)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "序列化密钥数据失败"))?;

    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "初始化加密器失败"))?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher_bytes = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_slice())
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "加密密钥库失败"))?;

    Ok(VaultFileEnvelope {
        version: 1,
        salt_b64: STANDARD.encode(salt),
        nonce_b64: STANDARD.encode(nonce),
        cipher_b64: STANDARD.encode(cipher_bytes),
    })
}

fn decrypt_vault_payload(
    key: &[u8; 32],
    envelope: &VaultFileEnvelope,
) -> Result<VaultDataFile, ErrorDto> {
    let nonce = decode_fixed::<12>(&envelope.nonce_b64)?;
    let cipher_bytes = STANDARD
        .decode(&envelope.cipher_b64)
        .map_err(|_| ErrorDto::new(ErrorCode::AuthFailed, "加密数据格式错误"))?;

    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "初始化解密器失败"))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(&nonce), cipher_bytes.as_slice())
        .map_err(|_| ErrorDto::new(ErrorCode::AuthFailed, "主密码错误或数据已损坏"))?;

    serde_json::from_slice(&plain).map_err(|_| ErrorDto::new(ErrorCode::AuthFailed, "密钥数据损坏"))
}

fn load_vault_envelope(app: &tauri::AppHandle) -> Result<Option<VaultFileEnvelope>, ErrorDto> {
    let path = vault_store_path(app)?;
    if !path.exists() {
        return Ok(None);
    }

    let text = fs::read_to_string(path)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取 Vault 文件失败"))?;
    let envelope: VaultFileEnvelope = serde_json::from_str(&text)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "解析 Vault 文件失败"))?;
    Ok(Some(envelope))
}

fn save_vault_envelope(
    app: &tauri::AppHandle,
    envelope: &VaultFileEnvelope,
) -> Result<(), ErrorDto> {
    let path = vault_store_path(app)?;
    let body = serde_json::to_vec_pretty(envelope)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "序列化 Vault 文件失败"))?;
    write_atomic(&path, &body)
}

fn persist_vault(app: &tauri::AppHandle, runtime: &VaultRuntime) -> Result<(), ErrorDto> {
    if !runtime.unlocked {
        return Err(ErrorDto::new(ErrorCode::VaultLocked, "保险箱未解锁"));
    }
    let salt = runtime
        .salt
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "缺少盐值"))?;
    let key = runtime
        .key
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "缺少加密密钥"))?;
    let envelope = encrypt_vault_payload(&salt, &key, &runtime.data)?;
    save_vault_envelope(app, &envelope)
}

#[tauri::command]
fn app_get_bootstrap(app: tauri::AppHandle) -> Result<AppBootstrapDto, ErrorDto> {
    let default_download_dir = app
        .path()
        .download_dir()
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "无法读取系统下载目录"))?
        .join("LastSheel");
    let features = vec![
        "本地终端 PTY（xterm.js + WebGL）".to_string(),
        "Hosts + Vault + Store 基础能力".to_string(),
        "SSH 直连 + known_hosts 严格校验 + 认证与 ProxyJump（阶段3）".to_string(),
        "文件栏与传输增强（批量下载/多格式压缩流/自动解压目录策略/SHA256 + 在线编辑与删除，阶段4-4）".to_string(),
        "监控会话仪表板（概览卡片/趋势图/路径探测/活动连接采样优化，阶段3）".to_string(),
        "进程管理 + systemctl 服务控制（阶段1）".to_string(),
    ];

    Ok(AppBootstrapDto::new(
        app.package_info().version.to_string(),
        default_download_dir.to_string_lossy().to_string(),
        features,
    ))
}

#[tauri::command]
fn store_hosts_list(
    app: tauri::AppHandle,
    manager: State<HostsStoreManager>,
) -> Result<Vec<HostItemDto>, ErrorDto> {
    let _guard = manager.lock.lock();
    let store = load_hosts_from_disk(&app)?;
    Ok(store.items)
}

#[tauri::command]
fn store_hosts_upsert(
    app: tauri::AppHandle,
    manager: State<HostsStoreManager>,
    input: HostUpsertInputDto,
) -> Result<HostItemDto, ErrorDto> {
    let _guard = manager.lock.lock();
    let mut store = load_hosts_from_disk(&app)?;

    let alias = input.alias.trim().to_string();
    let address = input.address.trim().to_string();
    let username = input.username.trim().to_string();
    let auth_mode = normalize_auth_mode(&input.auth_mode);
    let proxy_jump = validate_proxy_jump(&input.proxy_jump)?;
    if alias.is_empty() || address.is_empty() || username.is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "Host 别名、地址和用户名不能为空",
        ));
    }

    let item = HostItemDto {
        host_id: input.host_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        alias,
        address,
        port: if input.port == 0 { 22 } else { input.port },
        username,
        auth_mode,
        key_id: input
            .key_id
            .map(|value| value.trim().to_string())
            .and_then(|value| if value.is_empty() { None } else { Some(value) }),
        proxy_jump,
        tags: input
            .tags
            .into_iter()
            .map(|tag| tag.trim().to_string())
            .filter(|tag| !tag.is_empty())
            .collect(),
        note: input.note.trim().to_string(),
        pinned: input.pinned,
    };

    if let Some(existing) = store
        .items
        .iter_mut()
        .find(|host| host.host_id == item.host_id)
    {
        *existing = item.clone();
    } else {
        store.items.push(item.clone());
    }

    save_hosts_to_disk(&app, &store)?;
    Ok(item)
}

#[tauri::command]
fn store_hosts_delete(
    app: tauri::AppHandle,
    manager: State<HostsStoreManager>,
    host_id: String,
) -> Result<(), ErrorDto> {
    let _guard = manager.lock.lock();
    let mut store = load_hosts_from_disk(&app)?;
    let before = store.items.len();
    store.items.retain(|item| item.host_id != host_id);
    if store.items.len() == before {
        return Err(ErrorDto::new(ErrorCode::NotFound, "Host 不存在"));
    }
    save_hosts_to_disk(&app, &store)?;
    Ok(())
}

#[tauri::command]
fn vault_status(
    app: tauri::AppHandle,
    manager: State<VaultManager>,
) -> Result<VaultStatusDto, ErrorDto> {
    let mut runtime = manager.runtime.lock();
    if !runtime.initialized && load_vault_envelope(&app)?.is_some() {
        runtime.initialized = true;
    }

    Ok(VaultStatusDto {
        initialized: runtime.initialized,
        unlocked: runtime.unlocked,
    })
}

#[tauri::command]
fn vault_unlock(
    app: tauri::AppHandle,
    manager: State<VaultManager>,
    master_password: String,
) -> Result<VaultStatusDto, ErrorDto> {
    if master_password.trim().is_empty() {
        return Err(ErrorDto::new(ErrorCode::AuthFailed, "主密码不能为空"));
    }

    let mut runtime = manager.runtime.lock();
    if let Some(envelope) = load_vault_envelope(&app)? {
        let salt = decode_fixed::<16>(&envelope.salt_b64)?;
        let key = derive_master_key(&master_password, &salt)?;
        let data = decrypt_vault_payload(&key, &envelope)?;
        runtime.initialized = true;
        runtime.unlocked = true;
        runtime.salt = Some(salt);
        runtime.key = Some(key);
        runtime.data = data;
    } else {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let key = derive_master_key(&master_password, &salt)?;
        let data = VaultDataFile::default();
        let envelope = encrypt_vault_payload(&salt, &key, &data)?;
        save_vault_envelope(&app, &envelope)?;
        runtime.initialized = true;
        runtime.unlocked = true;
        runtime.salt = Some(salt);
        runtime.key = Some(key);
        runtime.data = data;
    }

    Ok(VaultStatusDto {
        initialized: runtime.initialized,
        unlocked: runtime.unlocked,
    })
}

#[tauri::command]
fn vault_lock(manager: State<VaultManager>) -> Result<VaultStatusDto, ErrorDto> {
    let mut runtime = manager.runtime.lock();
    let initialized = runtime.initialized;
    runtime.unlocked = false;
    runtime.key = None;
    runtime.data = VaultDataFile::default();
    Ok(VaultStatusDto {
        initialized,
        unlocked: false,
    })
}

#[tauri::command]
fn key_import_private_key(
    app: tauri::AppHandle,
    manager: State<VaultManager>,
    name: String,
    pem_text: String,
    passphrase: Option<String>,
) -> Result<KeyImportResultDto, ErrorDto> {
    let mut runtime = manager.runtime.lock();
    if !runtime.unlocked {
        return Err(ErrorDto::new(ErrorCode::VaultLocked, "保险箱未解锁"));
    }

    let key_name = name.trim().to_string();
    if key_name.is_empty() {
        return Err(ErrorDto::new(ErrorCode::Unsupported, "密钥名称不能为空"));
    }
    if !pem_text.contains("BEGIN") || !pem_text.contains("PRIVATE KEY") {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "私钥内容无效，请粘贴 PEM 格式私钥",
        ));
    }

    let created_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "系统时间异常"))?
        .as_millis() as i64;
    let key_id = Uuid::new_v4().to_string();
    runtime.data.keys.push(StoredPrivateKey {
        key_id: key_id.clone(),
        name: key_name,
        pem_text,
        passphrase: passphrase.map(|value| value.trim().to_string()),
        created_at_ms,
    });
    persist_vault(&app, &runtime)?;

    Ok(KeyImportResultDto { key_id })
}

#[tauri::command]
fn key_list(manager: State<VaultManager>) -> Result<Vec<KeyMetadataDto>, ErrorDto> {
    let runtime = manager.runtime.lock();
    if !runtime.unlocked {
        return Err(ErrorDto::new(ErrorCode::VaultLocked, "保险箱未解锁"));
    }

    Ok(runtime
        .data
        .keys
        .iter()
        .map(|item| KeyMetadataDto {
            key_id: item.key_id.clone(),
            name: item.name.clone(),
            has_passphrase: item
                .passphrase
                .as_ref()
                .map(|value| !value.is_empty())
                .unwrap_or(false),
            created_at_ms: item.created_at_ms,
        })
        .collect())
}

#[tauri::command]
fn known_hosts_list(
    app: tauri::AppHandle,
    manager: State<KnownHostsStoreManager>,
) -> Result<Vec<KnownHostItemDto>, ErrorDto> {
    let _guard = manager.lock.lock();
    let store = load_known_hosts_from_disk(&app)?;
    Ok(store.items)
}

#[tauri::command]
fn known_hosts_trust(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    manager: State<KnownHostsStoreManager>,
    host_id: String,
) -> Result<KnownHostItemDto, ErrorDto> {
    let _hosts_guard = hosts_manager.lock.lock();
    let hosts = load_hosts_from_disk(&app)?;
    let host = hosts
        .items
        .iter()
        .find(|item| item.host_id == host_id)
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "Host 不存在"))?;

    let proxy_jump = validate_proxy_jump(&host.proxy_jump)?;
    let (algorithm, key_b64, fingerprint_sha256) =
        probe_remote_host_key(&host.address, host.port, &proxy_jump)?;
    let trusted_at_ms = current_time_ms()?;
    let known_item = KnownHostItemDto {
        host_id: host.host_id.clone(),
        address: host.address.clone(),
        port: host.port,
        algorithm,
        key_b64,
        fingerprint_sha256,
        trusted_at_ms,
    };

    let _known_guard = manager.lock.lock();
    let mut store = load_known_hosts_from_disk(&app)?;
    if let Some(existing) = store
        .items
        .iter_mut()
        .find(|item| item.address == known_item.address && item.port == known_item.port)
    {
        *existing = known_item.clone();
    } else {
        store.items.push(known_item.clone());
    }
    save_known_hosts_to_disk(&app, &store)?;
    Ok(known_item)
}

fn ensure_known_host_trusted(
    app: &tauri::AppHandle,
    known_hosts_manager: &State<KnownHostsStoreManager>,
    host: &HostItemDto,
) -> Result<(), ErrorDto> {
    let proxy_jump = validate_proxy_jump(&host.proxy_jump)?;
    let (algorithm, key_b64, fingerprint_sha256) =
        probe_remote_host_key(&host.address, host.port, &proxy_jump)?;
    let _known_guard = known_hosts_manager.lock.lock();
    let known_hosts_store = load_known_hosts_from_disk(app)?;
    let known = known_hosts_store
        .items
        .iter()
        .find(|item| item.address == host.address && item.port == host.port);

    match known {
        None => Err(ErrorDto::new(
            ErrorCode::HostkeyUnknown,
            format!(
                "未知主机指纹：{}，请先在 Known Hosts 页面信任该主机",
                fingerprint_sha256
            ),
        )),
        Some(item) => {
            if item.key_b64 != key_b64 || item.algorithm != algorithm {
                return Err(ErrorDto::new(
                    ErrorCode::HostkeyChanged,
                    format!(
                        "主机指纹变化：旧={} 新={}",
                        item.fingerprint_sha256, fingerprint_sha256
                    ),
                ));
            }
            Ok(())
        }
    }
}

fn load_private_key_for_auth(
    vault_manager: &State<VaultManager>,
    key_id: &str,
) -> Result<(String, Option<String>), ErrorDto> {
    let runtime = vault_manager.runtime.lock();
    if !runtime.unlocked {
        return Err(ErrorDto::new(
            ErrorCode::VaultLocked,
            "使用密钥认证前请先解锁 Vault",
        ));
    }
    let key = runtime
        .data
        .keys
        .iter()
        .find(|item| item.key_id == key_id)
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "找不到指定的密钥"))?;
    Ok((key.pem_text.clone(), key.passphrase.clone()))
}

#[derive(Clone, Default)]
struct PreparedSshAuth {
    auth_mode: String,
    key_pem: Option<String>,
    key_passphrase: Option<String>,
    password: Option<String>,
}

fn prepare_sftp_auth(
    host: &HostItemDto,
    auth_mode: &str,
    password: Option<String>,
    vault_manager: &State<VaultManager>,
) -> Result<PreparedSshAuth, ErrorDto> {
    let mut prepared = PreparedSshAuth {
        auth_mode: auth_mode.to_string(),
        key_pem: None,
        key_passphrase: None,
        password,
    };
    if auth_mode == "key" {
        let key_id = host
            .key_id
            .as_ref()
            .ok_or_else(|| ErrorDto::new(ErrorCode::Unsupported, "当前 Host 未配置密钥"))?;
        let (pem_text, passphrase) = load_private_key_for_auth(vault_manager, key_id)?;
        prepared.key_pem = Some(pem_text);
        prepared.key_passphrase = passphrase;
        return Ok(prepared);
    }
    if auth_mode == "auto" {
        if let Some(key_id) = &host.key_id {
            if let Ok((pem_text, passphrase)) = load_private_key_for_auth(vault_manager, key_id) {
                prepared.key_pem = Some(pem_text);
                prepared.key_passphrase = passphrase;
            }
        }
        return Ok(prepared);
    }
    Ok(prepared)
}

fn authenticate_sftp_session(
    session: &mut ssh2::Session,
    username: &str,
    prepared_auth: &PreparedSshAuth,
) -> Result<(), ErrorDto> {
    match prepared_auth.auth_mode.as_str() {
        "key" => {
            let pem_text = prepared_auth
                .key_pem
                .as_deref()
                .ok_or_else(|| ErrorDto::new(ErrorCode::Unsupported, "当前 Host 未配置密钥"))?;
            session
                .userauth_pubkey_memory(
                    username,
                    None,
                    pem_text,
                    prepared_auth.key_passphrase.as_deref(),
                )
                .map_err(|_| ErrorDto::new(ErrorCode::AuthFailed, "密钥认证失败"))?;
        }
        "password" => {
            let plain = prepared_auth.password.as_ref().ok_or_else(|| {
                ErrorDto::new(ErrorCode::AuthFailed, "密码认证需要输入一次性密码")
            })?;
            session
                .userauth_password(username, plain.as_str())
                .map_err(|_| ErrorDto::new(ErrorCode::AuthFailed, "密码认证失败"))?;
        }
        "agent" => {
            session
                .userauth_agent(username)
                .map_err(|_| ErrorDto::new(ErrorCode::AuthFailed, "Agent 认证失败"))?;
        }
        _ => {
            if let Some(pem_text) = prepared_auth.key_pem.as_deref() {
                if session
                    .userauth_pubkey_memory(
                        username,
                        None,
                        pem_text,
                        prepared_auth.key_passphrase.as_deref(),
                    )
                    .is_ok()
                    && session.authenticated()
                {
                    return Ok(());
                }
            }
            if session.userauth_agent(username).is_ok() && session.authenticated() {
                return Ok(());
            }
            if let Some(plain) = prepared_auth.password.as_ref() {
                if session.userauth_password(username, plain.as_str()).is_ok()
                    && session.authenticated()
                {
                    return Ok(());
                }
            }
            return Err(ErrorDto::new(
                ErrorCode::AuthFailed,
                "自动认证失败，请改用明确认证方式",
            ));
        }
    }

    if !session.authenticated() {
        return Err(ErrorDto::new(ErrorCode::AuthFailed, "SSH 认证失败"));
    }
    Ok(())
}

fn open_authenticated_session(
    host: &HostItemDto,
    prepared_auth: &PreparedSshAuth,
) -> Result<ssh2::Session, ErrorDto> {
    let tcp = TcpStream::connect((host.address.as_str(), host.port))
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "连接远端 SSH 端口失败"))?;
    let mut session =
        ssh2::Session::new().map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建 SSH 会话失败"))?;
    session.set_tcp_stream(tcp);
    session
        .handshake()
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "SSH 握手失败"))?;
    authenticate_sftp_session(&mut session, &host.username, prepared_auth)?;
    Ok(session)
}

fn register_ssh_connection(
    manager: &State<SshConnectionManager>,
    terminal_id: &str,
    host: HostItemDto,
    prepared_auth: PreparedSshAuth,
) -> String {
    let connection_id = Uuid::new_v4().to_string();
    manager.connections.lock().insert(
        connection_id.clone(),
        SshConnectionContext {
            connection_id: connection_id.clone(),
            host,
            prepared_auth,
        },
    );
    manager
        .terminal_to_connection
        .lock()
        .insert(terminal_id.to_string(), connection_id.clone());
    connection_id
}

fn get_ssh_connection(
    manager: &State<SshConnectionManager>,
    connection_id: &str,
) -> Result<SshConnectionContext, ErrorDto> {
    manager
        .connections
        .lock()
        .get(connection_id)
        .cloned()
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "SSH 连接上下文不存在或已失效"))
}

fn cancel_monitor_subscriptions_for_connection(
    monitor_manager: &State<MonitorManager>,
    connection_id: &str,
) {
    let mut items = monitor_manager.items.lock();
    let target_ids = items
        .iter()
        .filter_map(|(subscription_id, item)| {
            if item.connection_id == connection_id {
                Some(subscription_id.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for subscription_id in target_ids {
        if let Some(item) = items.remove(&subscription_id) {
            item.canceled.store(true, Ordering::Relaxed);
        }
    }
}

fn cleanup_ssh_connection(
    app: &tauri::AppHandle,
    ssh_connection_manager: &State<SshConnectionManager>,
    monitor_manager: &State<MonitorManager>,
    terminal_id: &str,
) {
    let connection_id = ssh_connection_manager
        .terminal_to_connection
        .lock()
        .remove(terminal_id);
    if let Some(connection_id) = connection_id {
        ssh_connection_manager
            .connections
            .lock()
            .remove(&connection_id);
        cancel_monitor_subscriptions_for_connection(monitor_manager, &connection_id);
        let _ = app.emit("monitor.connection_closed", connection_id);
    }
}

fn run_remote_command_collect(
    host: &HostItemDto,
    prepared_auth: &PreparedSshAuth,
    command: &str,
    error_prefix: &str,
) -> Result<(String, String, i32), ErrorDto> {
    let session = open_authenticated_session(host, prepared_auth)?;
    let mut channel = session.channel_session().map_err(|_| {
        ErrorDto::new(
            ErrorCode::IoError,
            format!("{error_prefix}：创建远端命令通道失败"),
        )
    })?;
    channel.exec(command).map_err(|_| {
        ErrorDto::new(
            ErrorCode::IoError,
            format!("{error_prefix}：启动远端命令失败"),
        )
    })?;
    let mut stdout_text = String::new();
    let mut stderr_text = String::new();
    let _ = channel.read_to_string(&mut stdout_text);
    let _ = channel.stderr().read_to_string(&mut stderr_text);
    channel.wait_close().map_err(|_| {
        ErrorDto::new(
            ErrorCode::IoError,
            format!("{error_prefix}：等待远端命令结束失败"),
        )
    })?;
    let status = channel.exit_status().unwrap_or(1);
    Ok((stdout_text, stderr_text, status))
}

fn run_remote_command_capture(
    host: &HostItemDto,
    prepared_auth: &PreparedSshAuth,
    command: &str,
    error_prefix: &str,
) -> Result<String, ErrorDto> {
    let (stdout_text, stderr_text, status) =
        run_remote_command_collect(host, prepared_auth, command, error_prefix)?;
    if status == 0 {
        return Ok(stdout_text);
    }
    let detail = compact_stderr(&stderr_text);
    Err(ErrorDto::new(
        ErrorCode::IoError,
        format!("{error_prefix}：{detail}"),
    ))
}

fn build_process_list_command(limit: usize) -> String {
    format!(
        "ps -eo pid=,user=,pcpu=,pmem=,stat=,etime=,comm=,args= --sort=-pcpu | awk 'NR<={limit} {{ pid=$1; user=$2; cpu=$3; mem=$4; stat=$5; etime=$6; comm=$7; $1=$2=$3=$4=$5=$6=$7=\"\"; sub(/^ +/, \"\", $0); printf \"%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n\", pid, user, cpu, mem, stat, etime, comm, $0 }}'"
    )
}

fn parse_process_list_payload(raw: &str) -> Vec<ProcessItemDto> {
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let columns = trimmed.splitn(8, '\t').collect::<Vec<_>>();
            if columns.len() != 8 {
                return None;
            }
            Some(ProcessItemDto {
                pid: columns[0].trim().parse::<u32>().ok()?,
                user: columns[1].trim().to_string(),
                cpu_pct: columns[2].trim().parse::<f64>().ok().unwrap_or(0.0),
                mem_pct: columns[3].trim().parse::<f64>().ok().unwrap_or(0.0),
                stat: columns[4].trim().to_string(),
                elapsed: columns[5].trim().to_string(),
                command: columns[6].trim().to_string(),
                command_line: if columns[7].trim().is_empty() {
                    columns[6].trim().to_string()
                } else {
                    columns[7].trim().to_string()
                },
            })
        })
        .collect()
}

fn build_service_list_command(limit: usize) -> String {
    format!(
        "if ! command -v systemctl >/dev/null 2>&1; then printf '__SYSTEMCTL_UNSUPPORTED__'; exit 0; fi; systemctl list-units --type=service --all --no-legend --no-pager --plain --full | awk 'NR<={limit} {{ unit=$1; load=$2; active=$3; sub=$4; $1=$2=$3=$4=\"\"; sub(/^ +/, \"\", $0); printf \"%s\\t%s\\t%s\\t%s\\t%s\\n\", unit, load, active, sub, $0 }}'"
    )
}

fn parse_service_list_payload(raw: &str) -> Result<ServiceListResultDto, ErrorDto> {
    if raw.trim() == "__SYSTEMCTL_UNSUPPORTED__" {
        return Ok(ServiceListResultDto {
            supported: false,
            sampled_at_ms: current_time_ms().unwrap_or(0),
            message: Some("远端未安装 systemctl，或当前主机不是 systemd 环境".to_string()),
            items: Vec::new(),
        });
    }
    let items = raw
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }
            let columns = trimmed.splitn(5, '\t').collect::<Vec<_>>();
            if columns.len() != 5 {
                return None;
            }
            Some(ServiceItemDto {
                unit: columns[0].trim().to_string(),
                load_state: columns[1].trim().to_string(),
                active_state: columns[2].trim().to_string(),
                sub_state: columns[3].trim().to_string(),
                description: columns[4].trim().to_string(),
            })
        })
        .collect::<Vec<_>>();
    Ok(ServiceListResultDto {
        supported: true,
        sampled_at_ms: current_time_ms().unwrap_or(0),
        message: None,
        items,
    })
}

fn normalize_process_signal(signal: &str) -> Result<&'static str, ErrorDto> {
    match signal.trim().to_uppercase().as_str() {
        "TERM" => Ok("TERM"),
        "KILL" => Ok("KILL"),
        "HUP" => Ok("HUP"),
        "INT" => Ok("INT"),
        _ => Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "当前仅支持 TERM / KILL / HUP / INT 信号",
        )),
    }
}

fn validate_systemd_unit_name(unit: &str) -> Result<String, ErrorDto> {
    let trimmed = unit.trim();
    if trimmed.is_empty() {
        return Err(ErrorDto::new(ErrorCode::Unsupported, "服务名不能为空"));
    }
    if trimmed
        .chars()
        .all(|char| char.is_ascii_alphanumeric() || "._-@:".contains(char))
    {
        return Ok(trimmed.to_string());
    }
    Err(ErrorDto::new(
        ErrorCode::Unsupported,
        "服务名格式非法，仅允许字母、数字与 . _ - @ :",
    ))
}

fn normalize_service_action(action: &str) -> Result<&'static str, ErrorDto> {
    match action.trim().to_lowercase().as_str() {
        "start" => Ok("start"),
        "stop" => Ok("stop"),
        "restart" => Ok("restart"),
        "reload" => Ok("reload"),
        _ => Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "当前仅支持 start / stop / restart / reload",
        )),
    }
}

fn monitor_profile_interval(profile: &str) -> Duration {
    match profile {
        "basic" => Duration::from_secs(1),
        _ => Duration::from_secs(5),
    }
}

fn split_monitor_sections(text: &str) -> HashMap<String, String> {
    let mut sections = HashMap::new();
    let mut current_key: Option<String> = None;
    let mut current_lines: Vec<String> = Vec::new();
    for line in text.lines() {
        if let Some(name) = line
            .strip_prefix("__MONITOR_")
            .and_then(|value| value.strip_suffix("__"))
        {
            if let Some(key) = current_key.take() {
                sections.insert(key, current_lines.join("\n"));
                current_lines.clear();
            }
            current_key = Some(name.to_string());
            continue;
        }
        current_lines.push(line.to_string());
    }
    if let Some(key) = current_key {
        sections.insert(key, current_lines.join("\n"));
    }
    sections
}

fn parse_proc_key_values(text: &str) -> HashMap<String, u64> {
    let mut values = HashMap::new();
    for line in text.lines() {
        if let Some((key, raw_value)) = line.split_once(':') {
            let numeric = raw_value
                .split_whitespace()
                .find_map(|item| item.parse::<u64>().ok());
            if let Some(value) = numeric {
                values.insert(key.trim().to_string(), value);
            }
        }
    }
    values
}

fn build_basic_monitor_command() -> String {
    [
        "printf '__MONITOR_STAT__\\n'",
        "cat /proc/stat",
        "printf '__MONITOR_MEM__\\n'",
        "cat /proc/meminfo",
        "printf '__MONITOR_LOAD__\\n'",
        "cat /proc/loadavg",
        "printf '__MONITOR_UPTIME__\\n'",
        "cat /proc/uptime",
        "printf '__MONITOR_NET__\\n'",
        "cat /proc/net/dev",
    ]
    .join("; ")
}

fn build_disk_monitor_command() -> String {
    "df -kPT".to_string()
}

fn build_path_probe_command(paths: &[String]) -> Result<String, ErrorDto> {
    if paths.len() > MONITOR_PATH_PROBE_MAX_PATHS {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            format!("路径探测最多支持 {} 个路径", MONITOR_PATH_PROBE_MAX_PATHS),
        ));
    }
    let mut commands = Vec::new();
    for path in paths {
        let trimmed = path.trim();
        if trimmed.is_empty() {
            continue;
        }
        let escaped = escape_shell_arg(trimmed);
        commands.push(format!(
            "path={escaped}; exists=0; readable=0; writable=0; mount=''; avail=''; total=''; if [ -e \"$path\" ]; then exists=1; fi; if [ -r \"$path\" ]; then readable=1; fi; if [ -w \"$path\" ]; then writable=1; fi; if [ \"$exists\" = \"1\" ]; then set -- $(df -kP \"$path\" 2>/dev/null | tail -n 1); total=$2; avail=$4; mount=$6; fi; printf '__PATH__\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \"$path\" \"$exists\" \"$readable\" \"$writable\" \"$mount\" \"$avail\" \"$total\""
        ));
    }
    if commands.is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "至少需要一个路径探测目标",
        ));
    }
    Ok(commands.join("; "))
}

fn open_authenticated_sftp(
    host: &HostItemDto,
    prepared_auth: &PreparedSshAuth,
) -> Result<ssh2::Sftp, ErrorDto> {
    let session = open_authenticated_session(host, prepared_auth)?;
    session
        .sftp()
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "初始化 SFTP 通道失败"))
}

fn entry_type_from_perm(mode: u32) -> FileEntryType {
    match mode & 0o170000 {
        0o040000 => FileEntryType::Dir,
        0o100000 => FileEntryType::File,
        0o120000 => FileEntryType::Symlink,
        _ => FileEntryType::Unknown,
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn read_remote_dir_entries(
    sftp: &ssh2::Sftp,
    cwd_path: &Path,
) -> Result<Vec<FileEntryDto>, ErrorDto> {
    let raw_entries = sftp
        .readdir(cwd_path)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取远端目录失败"))?;
    let mut entries = Vec::new();
    for (path, stat) in raw_entries {
        let name = match path.file_name().and_then(|item| item.to_str()) {
            Some(value) => value.to_string(),
            None => continue,
        };
        if name == "." || name == ".." {
            continue;
        }
        let mode = stat.perm.unwrap_or(0);
        let entry_path = cwd_path.join(&name);
        entries.push(FileEntryDto {
            name,
            path: path_to_string(&entry_path),
            entry_type: entry_type_from_perm(mode),
            size_bytes: stat.size.unwrap_or(0),
            mtime_ms: stat
                .mtime
                .map(|value| (value as i64).saturating_mul(1000))
                .unwrap_or(0),
            mode_octal: format!("{:04o}", mode & 0o7777),
            uid: stat.uid.unwrap_or(0),
            gid: stat.gid.unwrap_or(0),
        });
    }

    entries.sort_by(|left, right| {
        let left_dir = matches!(left.entry_type, FileEntryType::Dir);
        let right_dir = matches!(right.entry_type, FileEntryType::Dir);
        match right_dir.cmp(&left_dir) {
            std::cmp::Ordering::Equal => left
                .name
                .to_lowercase()
                .cmp(&right.name.to_lowercase())
                .then_with(|| left.name.cmp(&right.name)),
            other => other,
        }
    });
    Ok(entries)
}

fn validate_monitor_profile(input: &str) -> Result<String, ErrorDto> {
    match input.trim().to_lowercase().as_str() {
        "disk" => Ok("disk".to_string()),
        "path_probe" => Ok("path_probe".to_string()),
        "basic" | "" => Ok("basic".to_string()),
        _ => Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "监控 profile 仅支持 basic / disk / path_probe",
        )),
    }
}

fn sample_basic_monitor_payload(
    raw_text: &str,
    prev_cpu: &mut Option<(u64, u64)>,
    prev_net: &mut HashMap<String, (u64, u64)>,
    prev_ts_ms: &mut Option<i64>,
) -> Result<String, ErrorDto> {
    let sections = split_monitor_sections(raw_text);
    let stat_text = sections
        .get("STAT")
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "远端未返回 /proc/stat"))?;
    let mem_text = sections
        .get("MEM")
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "远端未返回 /proc/meminfo"))?;
    let load_text = sections
        .get("LOAD")
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "远端未返回 /proc/loadavg"))?;
    let uptime_text = sections
        .get("UPTIME")
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "远端未返回 /proc/uptime"))?;
    let net_text = sections
        .get("NET")
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "远端未返回 /proc/net/dev"))?;

    let cpu_line = stat_text
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "无法解析 CPU 统计信息"))?;
    let cpu_parts = cpu_line
        .split_whitespace()
        .skip(1)
        .filter_map(|item| item.parse::<u64>().ok())
        .collect::<Vec<_>>();
    if cpu_parts.len() < 4 {
        return Err(ErrorDto::new(ErrorCode::IoError, "CPU 统计字段不足"));
    }
    let total_cpu = cpu_parts.iter().sum::<u64>();
    let idle_cpu = cpu_parts[3].saturating_add(cpu_parts.get(4).copied().unwrap_or(0));
    let cpu_total_pct = if let Some((prev_total_cpu, prev_idle_cpu)) = prev_cpu.take() {
        let total_delta = total_cpu.saturating_sub(prev_total_cpu);
        let idle_delta = idle_cpu.saturating_sub(prev_idle_cpu);
        if total_delta > 0 {
            ((total_delta.saturating_sub(idle_delta)) as f64 / total_delta as f64) * 100.0
        } else {
            0.0
        }
    } else {
        0.0
    };
    *prev_cpu = Some((total_cpu, idle_cpu));

    let proc_values = parse_proc_key_values(mem_text);
    let mem_total_kb = proc_values.get("MemTotal").copied().unwrap_or(0);
    let mem_available_kb = proc_values.get("MemAvailable").copied().unwrap_or(0);
    let mem_cached_kb = proc_values.get("Cached").copied().unwrap_or(0);
    let swap_total_kb = proc_values.get("SwapTotal").copied().unwrap_or(0);
    let swap_free_kb = proc_values.get("SwapFree").copied().unwrap_or(0);
    let mem_used_kb = mem_total_kb.saturating_sub(mem_available_kb);
    let swap_used_kb = swap_total_kb.saturating_sub(swap_free_kb);

    let load_parts = load_text.split_whitespace().collect::<Vec<_>>();
    let load1 = load_parts
        .first()
        .and_then(|item| item.parse::<f64>().ok())
        .unwrap_or(0.0);
    let load5 = load_parts
        .get(1)
        .and_then(|item| item.parse::<f64>().ok())
        .unwrap_or(0.0);
    let load15 = load_parts
        .get(2)
        .and_then(|item| item.parse::<f64>().ok())
        .unwrap_or(0.0);
    let uptime_s = uptime_text
        .split_whitespace()
        .next()
        .and_then(|item| item.parse::<f64>().ok())
        .unwrap_or(0.0);

    let now_ts_ms = current_time_ms()?;
    let elapsed_seconds = prev_ts_ms
        .map(|value| (now_ts_ms.saturating_sub(value) as f64 / 1000.0).max(1.0))
        .unwrap_or(1.0);
    *prev_ts_ms = Some(now_ts_ms);

    let mut net_items = Vec::new();
    for line in net_text.lines().skip(2) {
        let Some((ifname_raw, values_raw)) = line.split_once(':') else {
            continue;
        };
        let ifname = ifname_raw.trim();
        let values = values_raw.split_whitespace().collect::<Vec<_>>();
        if values.len() < 16 {
            continue;
        }
        let rx_total = values[0].parse::<u64>().unwrap_or(0);
        let tx_total = values[8].parse::<u64>().unwrap_or(0);
        let (rx_rate, tx_rate) = if let Some((prev_rx, prev_tx)) = prev_net.get(ifname).copied() {
            (
                rx_total.saturating_sub(prev_rx) as f64 / elapsed_seconds,
                tx_total.saturating_sub(prev_tx) as f64 / elapsed_seconds,
            )
        } else {
            (0.0, 0.0)
        };
        prev_net.insert(ifname.to_string(), (rx_total, tx_total));
        net_items.push(json!({
            "ifname": ifname,
            "rx_bytes_per_s": rx_rate,
            "tx_bytes_per_s": tx_rate,
            "rx_total_bytes": rx_total,
            "tx_total_bytes": tx_total,
        }));
    }

    serde_json::to_string(&json!({
        "cpu_total_pct": cpu_total_pct,
        "load1": load1,
        "load5": load5,
        "load15": load15,
        "mem_total_kb": mem_total_kb,
        "mem_used_kb": mem_used_kb,
        "mem_cached_kb": mem_cached_kb,
        "swap_total_kb": swap_total_kb,
        "swap_used_kb": swap_used_kb,
        "uptime_s": uptime_s,
        "net": net_items,
    }))
    .map_err(|_| ErrorDto::new(ErrorCode::IoError, "序列化基础监控数据失败"))
}

fn sample_disk_monitor_payload(raw_text: &str) -> Result<String, ErrorDto> {
    let mut mounts = Vec::new();
    for line in raw_text.lines().skip(1) {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 7 {
            continue;
        }
        let used_pct = parts[5].trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
        mounts.push(json!({
            "device": parts[0],
            "fstype": parts[1],
            "total_bytes": parts[2].parse::<u64>().unwrap_or(0).saturating_mul(1024),
            "used_bytes": parts[3].parse::<u64>().unwrap_or(0).saturating_mul(1024),
            "avail_bytes": parts[4].parse::<u64>().unwrap_or(0).saturating_mul(1024),
            "used_pct": used_pct,
            "mount": parts[6],
        }));
    }
    serde_json::to_string(&json!({ "mounts": mounts }))
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "序列化磁盘监控数据失败"))
}

fn sample_path_probe_payload(raw_text: &str) -> Result<String, ErrorDto> {
    let mut paths = Vec::new();
    for line in raw_text.lines() {
        let parts = line.split('\t').collect::<Vec<_>>();
        if parts.len() < 8 || parts[0] != "__PATH__" {
            continue;
        }
        paths.push(json!({
            "path": parts[1],
            "exists": parts[2] == "1",
            "readable": parts[3] == "1",
            "writable": parts[4] == "1",
            "mount": if parts[5].is_empty() { serde_json::Value::Null } else { json!(parts[5]) },
            "avail_bytes": parts[6].parse::<u64>().unwrap_or(0).saturating_mul(1024),
            "total_bytes": parts[7].parse::<u64>().unwrap_or(0).saturating_mul(1024),
            "dir_size_bytes": serde_json::Value::Null,
        }));
    }
    serde_json::to_string(&json!({ "paths": paths }))
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "序列化路径探测数据失败"))
}

#[tauri::command]
fn monitor_subscribe(
    app: tauri::AppHandle,
    ssh_connection_manager: State<SshConnectionManager>,
    monitor_manager: State<MonitorManager>,
    input: MonitorSubscribeInputDto,
) -> Result<MonitorSubscribeResultDto, ErrorDto> {
    let profile = validate_monitor_profile(&input.profile)?;
    let connection = get_ssh_connection(&ssh_connection_manager, &input.connection_id)?;
    if !connection.host.proxy_jump.trim().is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "监控当前仅支持直连主机，暂不支持 ProxyJump",
        ));
    }
    let subscription_id = Uuid::new_v4().to_string();
    let canceled = Arc::new(AtomicBool::new(false));
    let path_probe_paths = Arc::new(Mutex::new(vec![
        ".".to_string(),
        "/var/log".to_string(),
        "/tmp".to_string(),
    ]));
    monitor_manager.items.lock().insert(
        subscription_id.clone(),
        MonitorSubscriptionControl {
            connection_id: connection.connection_id.clone(),
            profile: profile.clone(),
            canceled: canceled.clone(),
            path_probe_paths: path_probe_paths.clone(),
        },
    );

    let app_handle = app.clone();
    let connection_id = connection.connection_id.clone();
    thread::spawn(move || {
        let mut prev_cpu: Option<(u64, u64)> = None;
        let mut prev_net: HashMap<String, (u64, u64)> = HashMap::new();
        let mut prev_ts_ms: Option<i64> = None;
        loop {
            if canceled.load(Ordering::Relaxed) {
                break;
            }
            let sample_result = match profile.as_str() {
                "disk" => run_remote_command_capture(
                    &connection.host,
                    &connection.prepared_auth,
                    &build_disk_monitor_command(),
                    "采集磁盘监控",
                )
                .and_then(|raw| sample_disk_monitor_payload(&raw)),
                "path_probe" => {
                    let paths = path_probe_paths.lock().clone();
                    build_path_probe_command(&paths).and_then(|command| {
                        run_remote_command_capture(
                            &connection.host,
                            &connection.prepared_auth,
                            &command,
                            "采集路径探测监控",
                        )
                        .and_then(|raw| sample_path_probe_payload(&raw))
                    })
                }
                _ => run_remote_command_capture(
                    &connection.host,
                    &connection.prepared_auth,
                    &build_basic_monitor_command(),
                    "采集基础监控",
                )
                .and_then(|raw| {
                    sample_basic_monitor_payload(
                        &raw,
                        &mut prev_cpu,
                        &mut prev_net,
                        &mut prev_ts_ms,
                    )
                }),
            };
            match sample_result {
                Ok(payload_json) => {
                    emit_monitor_update(&app_handle, &connection_id, &profile, payload_json)
                }
                Err(error) => emit_monitor_update(
                    &app_handle,
                    &connection_id,
                    &profile,
                    json!({ "error": error.message }).to_string(),
                ),
            }
            thread::sleep(monitor_profile_interval(&profile));
        }
    });

    Ok(MonitorSubscribeResultDto { subscription_id })
}

#[tauri::command]
fn monitor_unsubscribe(
    monitor_manager: State<MonitorManager>,
    subscription_id: String,
) -> Result<(), ErrorDto> {
    let item = monitor_manager.items.lock().remove(&subscription_id);
    if let Some(item) = item {
        item.canceled.store(true, Ordering::Relaxed);
        return Ok(());
    }
    Err(ErrorDto::new(ErrorCode::NotFound, "监控订阅不存在"))
}

#[tauri::command]
fn monitor_set_path_probe(
    monitor_manager: State<MonitorManager>,
    input: MonitorSetPathProbeInputDto,
) -> Result<(), ErrorDto> {
    let items = monitor_manager.items.lock();
    let item = items
        .get(&input.subscription_id)
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "监控订阅不存在"))?;
    if item.profile != "path_probe" {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "当前订阅不是路径探测 profile",
        ));
    }
    let next_paths = input
        .paths
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if next_paths.is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "至少需要一个路径探测目标",
        ));
    }
    if next_paths.len() > MONITOR_PATH_PROBE_MAX_PATHS {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            format!("路径探测最多支持 {} 个路径", MONITOR_PATH_PROBE_MAX_PATHS),
        ));
    }
    *item.path_probe_paths.lock() = next_paths;
    Ok(())
}

#[tauri::command]
fn fs_list_remote(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    host_id: String,
    path: Option<String>,
    password: Option<String>,
) -> Result<FsListResponseDto, ErrorDto> {
    let _hosts_guard = hosts_manager.lock.lock();
    let hosts = load_hosts_from_disk(&app)?;
    let host = hosts
        .items
        .iter()
        .find(|item| item.host_id == host_id)
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "Host 不存在"))?
        .clone();
    if !host.proxy_jump.trim().is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "文件栏当前仅支持直连主机，暂不支持 ProxyJump",
        ));
    }

    let auth_mode = normalize_auth_mode(&host.auth_mode);
    let one_time_password = prepare_one_time_password(&auth_mode, password)?;
    let prepared_auth = prepare_sftp_auth(&host, &auth_mode, one_time_password, &vault_manager)?;
    ensure_known_host_trusted(&app, &known_hosts_manager, &host)?;
    let sftp = open_authenticated_sftp(&host, &prepared_auth)?;
    let requested_path = path
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| ".".to_string());
    let cwd_path = sftp
        .realpath(Path::new(&requested_path))
        .map_err(|_| ErrorDto::new(ErrorCode::NotFound, "目标路径不存在或不可访问"))?;
    let entries = read_remote_dir_entries(&sftp, &cwd_path)?;
    Ok(FsListResponseDto {
        cwd: path_to_string(&cwd_path),
        entries,
    })
}

#[tauri::command]
fn fs_delete_remote(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    input: FsDeleteInputDto,
) -> Result<FsDeleteResultDto, ErrorDto> {
    let host = load_host_for_remote_operation(&app, &hosts_manager, &input.host_id)?;
    if !host.proxy_jump.trim().is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "文件操作当前仅支持直连主机，暂不支持 ProxyJump",
        ));
    }
    let mut normalized_paths = Vec::new();
    let mut dedup = HashSet::new();
    for path in input.paths {
        let trimmed = path.trim().to_string();
        validate_remote_target_path(&trimmed)?;
        if dedup.insert(trimmed.clone()) {
            normalized_paths.push(trimmed);
        }
    }
    if normalized_paths.is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "至少需要一个远端路径",
        ));
    }

    let auth_mode = normalize_auth_mode(&host.auth_mode);
    let one_time_password = prepare_one_time_password(&auth_mode, input.password)?;
    let prepared_auth = prepare_sftp_auth(&host, &auth_mode, one_time_password, &vault_manager)?;
    ensure_known_host_trusted(&app, &known_hosts_manager, &host)?;
    let sftp = open_authenticated_sftp(&host, &prepared_auth)?;

    for path in &normalized_paths {
        remove_remote_path_recursive(&sftp, Path::new(path), 0)?;
    }

    Ok(FsDeleteResultDto {
        deleted_count: normalized_paths.len(),
    })
}

#[tauri::command]
fn fs_read_text(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    input: FsReadTextInputDto,
) -> Result<FsReadTextResultDto, ErrorDto> {
    let remote_path = input.path.trim().to_string();
    validate_remote_target_path(&remote_path)?;
    let max_bytes = input.max_bytes.unwrap_or(FS_READ_TEXT_DEFAULT_MAX_BYTES);
    if max_bytes == 0 || max_bytes > 20_000_000 {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "max_bytes 取值范围为 1 到 20000000",
        ));
    }

    let host = load_host_for_remote_operation(&app, &hosts_manager, &input.host_id)?;
    if !host.proxy_jump.trim().is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "文件操作当前仅支持直连主机，暂不支持 ProxyJump",
        ));
    }
    let auth_mode = normalize_auth_mode(&host.auth_mode);
    let one_time_password = prepare_one_time_password(&auth_mode, input.password)?;
    let prepared_auth = prepare_sftp_auth(&host, &auth_mode, one_time_password, &vault_manager)?;
    ensure_known_host_trusted(&app, &known_hosts_manager, &host)?;
    let sftp = open_authenticated_sftp(&host, &prepared_auth)?;
    let target_path = Path::new(&remote_path);
    let stat = sftp
        .stat(target_path)
        .map_err(|_| ErrorDto::new(ErrorCode::NotFound, "远端文件不存在"))?;
    let mode = stat.perm.unwrap_or(0);
    if matches!(entry_type_from_perm(mode), FileEntryType::Dir) {
        return Err(ErrorDto::new(ErrorCode::Unsupported, "目录不支持文本编辑"));
    }
    if stat.size.unwrap_or(0) > max_bytes as u64 {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            format!("文件大小超过限制（>{max_bytes} 字节）"),
        ));
    }

    let mut remote_file = sftp
        .open(target_path)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取远端文件失败"))?;
    let mut content = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read_size = remote_file
            .read(&mut buffer)
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取远端文件失败"))?;
        if read_size == 0 {
            break;
        }
        if content.len().saturating_add(read_size) > max_bytes {
            return Err(ErrorDto::new(
                ErrorCode::Unsupported,
                format!("文件大小超过限制（>{max_bytes} 字节）"),
            ));
        }
        content.extend_from_slice(&buffer[..read_size]);
    }
    let text = String::from_utf8(content)
        .map_err(|_| ErrorDto::new(ErrorCode::Unsupported, "仅支持 UTF-8 文本文件"))?;

    Ok(FsReadTextResultDto {
        path: remote_path,
        text,
        encoding: "utf-8".to_string(),
        mtime_ms: stat
            .mtime
            .map(|value| (value as i64).saturating_mul(1000))
            .unwrap_or(0),
    })
}

#[tauri::command]
fn fs_write_text_atomic(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    input: FsWriteTextInputDto,
) -> Result<FsWriteTextResultDto, ErrorDto> {
    let remote_path = input.path.trim().to_string();
    validate_remote_target_path(&remote_path)?;
    let encoding = input
        .encoding
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("utf-8")
        .to_lowercase();
    if encoding != "utf-8" && encoding != "utf8" {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "当前仅支持 utf-8 编码写入",
        ));
    }

    let host = load_host_for_remote_operation(&app, &hosts_manager, &input.host_id)?;
    if !host.proxy_jump.trim().is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "文件操作当前仅支持直连主机，暂不支持 ProxyJump",
        ));
    }
    let auth_mode = normalize_auth_mode(&host.auth_mode);
    let one_time_password = prepare_one_time_password(&auth_mode, input.password)?;
    let prepared_auth = prepare_sftp_auth(&host, &auth_mode, one_time_password, &vault_manager)?;
    ensure_known_host_trusted(&app, &known_hosts_manager, &host)?;
    let sftp = open_authenticated_sftp(&host, &prepared_auth)?;

    let target_path = Path::new(&remote_path);
    let existing_stat = sftp
        .stat(target_path)
        .map_err(|_| ErrorDto::new(ErrorCode::NotFound, "远端文件不存在"))?;
    if matches!(
        entry_type_from_perm(existing_stat.perm.unwrap_or(0)),
        FileEntryType::Dir
    ) {
        return Err(ErrorDto::new(ErrorCode::Unsupported, "目录不支持文本编辑"));
    }
    let target_name = target_path
        .file_name()
        .and_then(|item| item.to_str())
        .ok_or_else(|| ErrorDto::new(ErrorCode::Unsupported, "目标路径格式无效"))?;
    let parent_dir = target_path.parent().unwrap_or_else(|| Path::new("."));
    let temp_path = parent_dir.join(format!(".{target_name}.tmp.{}", Uuid::new_v4().simple()));
    let bytes = input.text.into_bytes();

    let write_result = (|| -> Result<(), ErrorDto> {
        let mut temp_file = sftp
            .create(&temp_path)
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建远端临时文件失败"))?;
        temp_file
            .write_all(&bytes)
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "写入远端临时文件失败"))?;
        let _ = temp_file.flush();
        drop(temp_file);
        sftp.rename(&temp_path, target_path, Some(ssh2::RenameFlags::OVERWRITE))
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "原子替换远端文件失败"))?;
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = sftp.unlink(&temp_path);
        return Err(error);
    }

    let stat = sftp
        .stat(target_path)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取写入结果失败"))?;
    Ok(FsWriteTextResultDto {
        new_mtime_ms: stat
            .mtime
            .map(|value| (value as i64).saturating_mul(1000))
            .unwrap_or(0),
    })
}

#[tauri::command]
fn process_list_remote(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    input: ProcessListInputDto,
) -> Result<ProcessListResultDto, ErrorDto> {
    let (host, prepared_auth) = prepare_remote_command_context(
        &app,
        &hosts_manager,
        &known_hosts_manager,
        &vault_manager,
        &input.host_id,
        input.password,
        "进程管理",
    )?;
    let limit = input.limit.unwrap_or(60).clamp(1, 200);
    let raw = run_remote_command_capture(
        &host,
        &prepared_auth,
        &build_process_list_command(limit),
        "拉取进程列表",
    )?;
    Ok(ProcessListResultDto {
        sampled_at_ms: current_time_ms().unwrap_or(0),
        items: parse_process_list_payload(&raw),
    })
}

#[tauri::command]
fn process_signal_remote(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    input: ProcessSignalInputDto,
) -> Result<ProcessActionResultDto, ErrorDto> {
    if input.pid == 0 {
        return Err(ErrorDto::new(ErrorCode::Unsupported, "PID 必须大于 0"));
    }
    let signal = normalize_process_signal(&input.signal)?;
    let (host, prepared_auth) = prepare_remote_command_context(
        &app,
        &hosts_manager,
        &known_hosts_manager,
        &vault_manager,
        &input.host_id,
        input.password,
        "进程管理",
    )?;
    let (_, stderr_text, status) = run_remote_command_collect(
        &host,
        &prepared_auth,
        &format!("kill -s {signal} {}", input.pid),
        "执行进程信号",
    )?;
    if status != 0 {
        return Err(classify_management_command_error(
            &stderr_text,
            "执行进程信号",
        ));
    }
    Ok(ProcessActionResultDto {
        ok: true,
        message: format!("已向进程 {} 发送 {signal} 信号", input.pid),
    })
}

#[tauri::command]
fn service_list_remote(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    input: ServiceListInputDto,
) -> Result<ServiceListResultDto, ErrorDto> {
    let (host, prepared_auth) = prepare_remote_command_context(
        &app,
        &hosts_manager,
        &known_hosts_manager,
        &vault_manager,
        &input.host_id,
        input.password,
        "服务管理",
    )?;
    let limit = input.limit.unwrap_or(80).clamp(1, 200);
    let raw = run_remote_command_capture(
        &host,
        &prepared_auth,
        &build_service_list_command(limit),
        "拉取 systemctl 服务列表",
    )?;
    parse_service_list_payload(&raw)
}

#[tauri::command]
fn service_action_remote(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    input: ServiceActionInputDto,
) -> Result<ServiceActionResultDto, ErrorDto> {
    let action = normalize_service_action(&input.action)?;
    let unit = validate_systemd_unit_name(&input.unit)?;
    let (host, prepared_auth) = prepare_remote_command_context(
        &app,
        &hosts_manager,
        &known_hosts_manager,
        &vault_manager,
        &input.host_id,
        input.password,
        "服务管理",
    )?;
    let command = format!(
        "command -v systemctl >/dev/null 2>&1 || {{ printf '__SYSTEMCTL_UNSUPPORTED__' >&2; exit 127; }}; systemctl {action} {}",
        quote_posix_shell_arg(&unit),
    );
    let (_, stderr_text, status) =
        run_remote_command_collect(&host, &prepared_auth, &command, "执行服务动作")?;
    if status != 0 {
        return Err(classify_management_command_error(
            &stderr_text,
            "执行服务动作",
        ));
    }
    Ok(ServiceActionResultDto {
        ok: true,
        message: format!("已执行 {action}：{unit}"),
    })
}

fn load_host_for_remote_operation(
    app: &tauri::AppHandle,
    hosts_manager: &State<HostsStoreManager>,
    host_id: &str,
) -> Result<HostItemDto, ErrorDto> {
    let _hosts_guard = hosts_manager.lock.lock();
    let hosts = load_hosts_from_disk(app)?;
    hosts
        .items
        .iter()
        .find(|item| item.host_id == host_id)
        .cloned()
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "Host 不存在"))
}

fn prepare_remote_command_context(
    app: &tauri::AppHandle,
    hosts_manager: &State<HostsStoreManager>,
    known_hosts_manager: &State<KnownHostsStoreManager>,
    vault_manager: &State<VaultManager>,
    host_id: &str,
    password: Option<String>,
    operation_name: &str,
) -> Result<(HostItemDto, PreparedSshAuth), ErrorDto> {
    let host = load_host_for_remote_operation(app, hosts_manager, host_id)?;
    if !host.proxy_jump.trim().is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            format!("{operation_name}当前仅支持直连主机，暂不支持 ProxyJump"),
        ));
    }
    let auth_mode = normalize_auth_mode(&host.auth_mode);
    let one_time_password = prepare_one_time_password(&auth_mode, password)?;
    let prepared_auth = prepare_sftp_auth(&host, &auth_mode, one_time_password, vault_manager)?;
    ensure_known_host_trusted(app, known_hosts_manager, &host)?;
    Ok((host, prepared_auth))
}

fn validate_remote_target_path(path: &str) -> Result<(), ErrorDto> {
    let value = path.trim();
    if value.is_empty() {
        return Err(ErrorDto::new(ErrorCode::Unsupported, "远端路径不能为空"));
    }
    if value == "/" || value == "." || value == ".." {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "禁止对根目录或当前目录执行此操作",
        ));
    }
    Ok(())
}

fn remove_remote_path_recursive(
    sftp: &ssh2::Sftp,
    target_path: &Path,
    depth: usize,
) -> Result<(), ErrorDto> {
    if depth > REMOTE_DELETE_MAX_DEPTH {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "目录层级过深，已停止删除以避免误操作",
        ));
    }
    let stat = sftp
        .lstat(target_path)
        .map_err(|_| ErrorDto::new(ErrorCode::NotFound, "远端文件或目录不存在"))?;
    let mode = stat.perm.unwrap_or(0);
    if matches!(entry_type_from_perm(mode), FileEntryType::Dir) {
        let children = sftp
            .readdir(target_path)
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取远端目录失败"))?;
        for (child_path, _) in children {
            let name = match child_path.file_name().and_then(|item| item.to_str()) {
                Some(value) => value,
                None => continue,
            };
            if name == "." || name == ".." {
                continue;
            }
            remove_remote_path_recursive(sftp, &target_path.join(name), depth + 1)?;
        }
        sftp.rmdir(target_path)
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "删除远端目录失败"))?;
        return Ok(());
    }
    sftp.unlink(target_path)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "删除远端文件失败"))
}

fn sanitize_path_segment(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .map(|ch| {
            if ch.is_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_');
    if trimmed.is_empty() {
        "host".to_string()
    } else {
        trimmed.to_string()
    }
}

fn resolve_conflict_path(path: PathBuf) -> PathBuf {
    if !path.exists() {
        return path;
    }
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let stem = path
        .file_stem()
        .and_then(|item| item.to_str())
        .unwrap_or("download")
        .to_string();
    let ext = path
        .extension()
        .and_then(|item| item.to_str())
        .unwrap_or("");
    for index in 1..10000 {
        let file_name = if ext.is_empty() {
            format!("{stem} ({index})")
        } else {
            format!("{stem} ({index}).{ext}")
        };
        let candidate = parent.join(file_name);
        if !candidate.exists() {
            return candidate;
        }
    }
    parent.join(format!("{stem}-{}", Uuid::new_v4()))
}

fn resolve_download_target_path(
    app: &tauri::AppHandle,
    host: &HostItemDto,
    remote_path: &str,
    local_path: Option<String>,
    conflict_policy: &str,
) -> Result<PathBuf, ErrorDto> {
    let candidate = local_path
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let base = app.path().download_dir().unwrap_or_else(|_| {
                app.path()
                    .app_data_dir()
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
            let file_name = Path::new(remote_path)
                .file_name()
                .and_then(|item| item.to_str())
                .filter(|item| !item.is_empty())
                .unwrap_or("download.bin")
                .to_string();
            base.join("LastSheel")
                .join(sanitize_path_segment(&host.alias))
                .join(file_name)
        });
    let parent = candidate
        .parent()
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "无效的下载路径"))?;
    fs::create_dir_all(parent)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建下载目录失败"))?;
    if !candidate.exists() {
        return Ok(candidate);
    }
    match conflict_policy {
        "overwrite" => Ok(candidate),
        "skip" => Err(ErrorDto::new(
            ErrorCode::Conflict,
            format!("目标文件已存在：{}", path_to_string(&candidate)),
        )),
        _ => Ok(resolve_conflict_path(candidate)),
    }
}

fn resolve_archive_download_target_path(
    app: &tauri::AppHandle,
    host: &HostItemDto,
    local_path: Option<String>,
    default_file_name: &str,
    conflict_policy: &str,
) -> Result<PathBuf, ErrorDto> {
    let candidate = local_path
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            app.path()
                .download_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join("LastSheel")
                .join(sanitize_path_segment(&host.alias))
                .join(default_file_name)
        });
    let mut candidate = if candidate.is_absolute() {
        candidate
    } else {
        std::env::current_dir()
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取当前目录失败"))?
            .join(candidate)
    };
    if candidate.exists() && candidate.is_dir() {
        candidate = candidate.join(default_file_name);
    }
    let parent = candidate
        .parent()
        .ok_or_else(|| ErrorDto::new(ErrorCode::IoError, "无效的下载路径"))?;
    fs::create_dir_all(parent)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建下载目录失败"))?;
    if !candidate.exists() {
        return Ok(candidate);
    }
    match conflict_policy {
        "overwrite" => Ok(candidate),
        "skip" => Err(ErrorDto::new(
            ErrorCode::Conflict,
            format!("目标文件已存在：{}", path_to_string(&candidate)),
        )),
        _ => Ok(resolve_conflict_path(candidate)),
    }
}

fn escape_shell_arg(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn archive_extension(archive_format: &str) -> &'static str {
    match archive_format {
        "tar" => "tar",
        "tar_bz2" => "tar.bz2",
        "tar_xz" => "tar.xz",
        "zip" => "zip",
        _ => "tar.gz",
    }
}

fn archive_dependency_command(archive_format: &str) -> &'static str {
    match archive_format {
        "zip" => "zip",
        _ => "tar",
    }
}

fn extract_dependency_command(archive_format: &str) -> &'static str {
    match archive_format {
        "zip" => "unzip",
        _ => "tar",
    }
}

fn detect_archive_format_from_path(path: &str) -> Option<&'static str> {
    let normalized = path.trim().to_lowercase();
    if normalized.ends_with(".tar.gz") || normalized.ends_with(".tgz") {
        return Some("tar_gz");
    }
    if normalized.ends_with(".tar.bz2")
        || normalized.ends_with(".tbz2")
        || normalized.ends_with(".tbz")
    {
        return Some("tar_bz2");
    }
    if normalized.ends_with(".tar.xz") || normalized.ends_with(".txz") {
        return Some("tar_xz");
    }
    if normalized.ends_with(".tar") {
        return Some("tar");
    }
    if normalized.ends_with(".zip") {
        return Some("zip");
    }
    None
}

fn strip_archive_extension(file_name: &str) -> String {
    let normalized = file_name.trim().to_lowercase();
    for suffix in [
        ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tbz", ".tar.xz", ".txz", ".tar", ".zip",
    ] {
        if normalized.ends_with(suffix) {
            return file_name[..file_name.len().saturating_sub(suffix.len())].to_string();
        }
    }
    file_name.to_string()
}

fn default_extract_destination(remote_archive_path: &str) -> String {
    let remote_path = Path::new(remote_archive_path);
    let parent = remote_path
        .parent()
        .map(path_to_string)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| ".".to_string());
    let file_name = remote_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("archive");
    let directory_name = strip_archive_extension(file_name);
    if directory_name.trim().is_empty() {
        return parent;
    }
    if parent == "." {
        directory_name
    } else {
        format!("{parent}/{directory_name}")
    }
}

fn build_remote_archive_command(paths: &[String], archive_format: &str) -> String {
    let escaped_paths = paths
        .iter()
        .map(|path| escape_shell_arg(path))
        .collect::<Vec<_>>()
        .join(" ");
    match archive_format {
        "tar" => format!("tar -cf - -- {escaped_paths}"),
        "tar_bz2" => format!("tar -cjf - -- {escaped_paths}"),
        "tar_xz" => format!("tar -cJf - -- {escaped_paths}"),
        "zip" => format!("zip -qry - -- {escaped_paths}"),
        _ => format!("tar -czf - -- {escaped_paths}"),
    }
}

fn build_remote_extract_command(
    archive_format: &str,
    remote_archive_path: &str,
    extract_destination: &str,
    remove_archive_after_extract: bool,
) -> String {
    let archive = escape_shell_arg(remote_archive_path);
    let destination = escape_shell_arg(extract_destination);
    let extract_command = match archive_format {
        "tar" => format!("mkdir -p {destination} && tar -xf {archive} -C {destination}"),
        "tar_bz2" => format!("mkdir -p {destination} && tar -xjf {archive} -C {destination}"),
        "tar_xz" => format!("mkdir -p {destination} && tar -xJf {archive} -C {destination}"),
        "zip" => format!("unzip -oq {archive} -d {destination}"),
        _ => format!("mkdir -p {destination} && tar -xzf {archive} -C {destination}"),
    };
    if remove_archive_after_extract {
        format!("{extract_command} && rm -f {archive}")
    } else {
        extract_command
    }
}

fn run_remote_command_checked(
    host: &HostItemDto,
    prepared_auth: &PreparedSshAuth,
    command: &str,
    error_prefix: &str,
) -> Result<(), ErrorDto> {
    let session = open_authenticated_session(host, prepared_auth)?;
    let mut channel = session.channel_session().map_err(|_| {
        ErrorDto::new(
            ErrorCode::IoError,
            format!("{error_prefix}：创建远端命令通道失败"),
        )
    })?;
    channel.exec(command).map_err(|_| {
        ErrorDto::new(
            ErrorCode::IoError,
            format!("{error_prefix}：启动远端命令失败"),
        )
    })?;
    channel.wait_close().map_err(|_| {
        ErrorDto::new(
            ErrorCode::IoError,
            format!("{error_prefix}：等待远端命令结束失败"),
        )
    })?;
    let status = channel.exit_status().unwrap_or(1);
    if status == 0 {
        return Ok(());
    }
    let mut stderr_text = String::new();
    let _ = channel.stderr().read_to_string(&mut stderr_text);
    let message = if stderr_text.trim().is_empty() {
        format!("{error_prefix}：远端命令执行失败")
    } else {
        format!("{error_prefix}：{}", stderr_text.trim())
    };
    Err(ErrorDto::new(ErrorCode::IoError, message))
}

fn resolve_remote_conflict_path(
    sftp: &ssh2::Sftp,
    remote_path: &str,
    conflict_policy: &str,
) -> Result<String, ErrorDto> {
    let original = Path::new(remote_path);
    let exists = sftp.stat(original).is_ok();
    if !exists {
        return Ok(remote_path.to_string());
    }
    match conflict_policy {
        "overwrite" => Ok(remote_path.to_string()),
        "skip" => Err(ErrorDto::new(
            ErrorCode::Conflict,
            format!("远端文件已存在：{remote_path}"),
        )),
        _ => {
            let parent = original.parent().unwrap_or_else(|| Path::new(""));
            let stem = original
                .file_stem()
                .and_then(|item| item.to_str())
                .unwrap_or("upload")
                .to_string();
            let ext = original
                .extension()
                .and_then(|item| item.to_str())
                .unwrap_or("")
                .to_string();
            for index in 1..10000 {
                let file_name = if ext.is_empty() {
                    format!("{stem} ({index})")
                } else {
                    format!("{stem} ({index}).{ext}")
                };
                let candidate = parent.join(file_name);
                if sftp.stat(&candidate).is_err() {
                    return Ok(path_to_string(&candidate));
                }
            }
            Ok(path_to_string(
                &parent.join(format!("{stem}-{}", Uuid::new_v4())),
            ))
        }
    }
}

fn insert_transfer_control(
    transfer_manager: &State<TransferManager>,
    transfer_id: &str,
) -> Arc<AtomicBool> {
    let canceled = Arc::new(AtomicBool::new(false));
    transfer_manager.items.lock().insert(
        transfer_id.to_string(),
        TransferControl {
            canceled: canceled.clone(),
        },
    );
    canceled
}

fn upsert_transfer_record(transfer_manager: &State<TransferManager>, record: TransferRecord) {
    transfer_manager
        .records
        .lock()
        .insert(record.transfer_id.clone(), record);
}

fn update_transfer_record_state(
    transfer_manager: &State<TransferManager>,
    transfer_id: &str,
    state: TransferState,
) {
    if let Some(record) = transfer_manager.records.lock().get_mut(transfer_id) {
        record.state = state;
    }
}

fn remove_transfer_control(app: &tauri::AppHandle, transfer_id: &str) {
    let transfer_manager = app.state::<TransferManager>();
    transfer_manager.items.lock().remove(transfer_id);
}

fn sha256_file_hex(path: &Path) -> Result<String, ErrorDto> {
    let mut file =
        fs::File::open(path).map_err(|_| ErrorDto::new(ErrorCode::NotFound, "本地文件不存在"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let size = file
            .read(&mut buffer)
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取本地文件失败"))?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }
    let digest = hasher.finalize();
    Ok(format!("{digest:x}"))
}

#[tauri::command]
fn transfer_download(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    transfer_manager: State<TransferManager>,
    input: TransferDownloadInputDto,
) -> Result<TransferStartDto, ErrorDto> {
    let remote_path = input.remote_path.trim().to_string();
    let conflict_policy = normalize_conflict_policy(input.conflict_policy.as_deref(), "rename");
    if remote_path.is_empty() {
        return Err(ErrorDto::new(ErrorCode::Unsupported, "远端路径不能为空"));
    }
    let host = load_host_for_remote_operation(&app, &hosts_manager, &input.host_id)?;
    if !host.proxy_jump.trim().is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "传输当前仅支持直连主机，暂不支持 ProxyJump",
        ));
    }
    let auth_mode = normalize_auth_mode(&host.auth_mode);
    let one_time_password = prepare_one_time_password(&auth_mode, input.password)?;
    let prepared_auth = prepare_sftp_auth(&host, &auth_mode, one_time_password, &vault_manager)?;
    ensure_known_host_trusted(&app, &known_hosts_manager, &host)?;
    let resolved_local_path = resolve_download_target_path(
        &app,
        &host,
        &remote_path,
        input.local_path,
        &conflict_policy,
    )?;

    let transfer_id = Uuid::new_v4().to_string();
    let canceled = insert_transfer_control(&transfer_manager, &transfer_id);
    upsert_transfer_record(
        &transfer_manager,
        TransferRecord {
            transfer_id: transfer_id.clone(),
            direction: "download".to_string(),
            local_path: Some(resolved_local_path.clone()),
            state: TransferState::Queued,
        },
    );
    emit_transfer_update(
        &app,
        &transfer_id,
        TransferState::Queued,
        0,
        None,
        Some("下载任务已入队".to_string()),
    );

    let app_handle = app.clone();
    let transfer_id_for_thread = transfer_id.clone();
    let resolved_local_path_for_thread = resolved_local_path.clone();
    thread::spawn(move || {
        let manager = app_handle.state::<TransferManager>();
        update_transfer_record_state(&manager, &transfer_id_for_thread, TransferState::Running);
        emit_transfer_update(
            &app_handle,
            &transfer_id_for_thread,
            TransferState::Running,
            0,
            None,
            Some("开始下载".to_string()),
        );
        let run_result = (|| -> Result<(u64, Option<u64>), ErrorDto> {
            let sftp = open_authenticated_sftp(&host, &prepared_auth)?;
            let mut remote_file = sftp
                .open(Path::new(&remote_path))
                .map_err(|_| ErrorDto::new(ErrorCode::NotFound, "远端文件不存在或不可读"))?;
            let total_bytes = sftp
                .stat(Path::new(&remote_path))
                .ok()
                .and_then(|stat| stat.size);
            let mut local_file = fs::File::create(&resolved_local_path_for_thread)
                .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建本地文件失败"))?;
            let mut buffer = vec![0_u8; 64 * 1024];
            let mut done_bytes = 0_u64;
            loop {
                if canceled.load(Ordering::Relaxed) {
                    let _ = fs::remove_file(&resolved_local_path_for_thread);
                    return Err(ErrorDto::new(ErrorCode::Canceled, "下载已取消"));
                }
                let read_size = remote_file
                    .read(&mut buffer)
                    .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取远端文件失败"))?;
                if read_size == 0 {
                    break;
                }
                local_file
                    .write_all(&buffer[..read_size])
                    .map_err(|_| ErrorDto::new(ErrorCode::IoError, "写入本地文件失败"))?;
                done_bytes = done_bytes.saturating_add(read_size as u64);
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    TransferState::Running,
                    done_bytes,
                    total_bytes,
                    None,
                );
            }
            Ok((done_bytes, total_bytes))
        })();

        match run_result {
            Ok((done_bytes, total_bytes)) => {
                let manager = app_handle.state::<TransferManager>();
                update_transfer_record_state(
                    &manager,
                    &transfer_id_for_thread,
                    TransferState::Done,
                );
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    TransferState::Done,
                    done_bytes,
                    total_bytes,
                    Some(format!(
                        "下载完成：{}",
                        path_to_string(&resolved_local_path_for_thread)
                    )),
                )
            }
            Err(error) => {
                let state = if matches!(error.code, ErrorCode::Canceled) {
                    TransferState::Canceled
                } else {
                    TransferState::Error
                };
                let manager = app_handle.state::<TransferManager>();
                update_transfer_record_state(&manager, &transfer_id_for_thread, state.clone());
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    state,
                    0,
                    None,
                    Some(error.message),
                );
            }
        }
        remove_transfer_control(&app_handle, &transfer_id_for_thread);
    });

    Ok(TransferStartDto {
        transfer_id,
        resolved_local_path: Some(path_to_string(&resolved_local_path)),
        resolved_remote_path: None,
    })
}

#[tauri::command]
fn archive_pack_stream_download(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    transfer_manager: State<TransferManager>,
    input: ArchivePackDownloadInputDto,
) -> Result<TransferStartDto, ErrorDto> {
    let archive_format = normalize_archive_format(input.archive_format.as_deref(), "tar_gz")?;
    let host = load_host_for_remote_operation(&app, &hosts_manager, &input.host_id)?;
    if !host.proxy_jump.trim().is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "传输当前仅支持直连主机，暂不支持 ProxyJump",
        ));
    }
    let mut selected_paths = Vec::new();
    let mut dedup = HashSet::new();
    for path in input.paths {
        let trimmed = path.trim().to_string();
        validate_remote_target_path(&trimmed)?;
        if dedup.insert(trimmed.clone()) {
            selected_paths.push(trimmed);
        }
    }
    if selected_paths.is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "至少需要一个远端路径",
        ));
    }

    let conflict_policy = normalize_conflict_policy(input.conflict_policy.as_deref(), "rename");
    let default_file_name = format!(
        "{}-bundle-{}.{}",
        sanitize_path_segment(&host.alias),
        current_time_ms()?,
        archive_extension(&archive_format)
    );
    let resolved_local_path = resolve_archive_download_target_path(
        &app,
        &host,
        input.local_path,
        &default_file_name,
        &conflict_policy,
    )?;

    let auth_mode = normalize_auth_mode(&host.auth_mode);
    let one_time_password = prepare_one_time_password(&auth_mode, input.password)?;
    let prepared_auth = prepare_sftp_auth(&host, &auth_mode, one_time_password, &vault_manager)?;
    ensure_known_host_trusted(&app, &known_hosts_manager, &host)?;

    let transfer_id = Uuid::new_v4().to_string();
    let canceled = insert_transfer_control(&transfer_manager, &transfer_id);
    upsert_transfer_record(
        &transfer_manager,
        TransferRecord {
            transfer_id: transfer_id.clone(),
            direction: "download".to_string(),
            local_path: Some(resolved_local_path.clone()),
            state: TransferState::Queued,
        },
    );
    emit_transfer_update(
        &app,
        &transfer_id,
        TransferState::Queued,
        0,
        None,
        Some("压缩下载任务已入队".to_string()),
    );

    let app_handle = app.clone();
    let transfer_id_for_thread = transfer_id.clone();
    let resolved_local_path_for_thread = resolved_local_path.clone();
    thread::spawn(move || {
        let manager = app_handle.state::<TransferManager>();
        update_transfer_record_state(&manager, &transfer_id_for_thread, TransferState::Running);
        emit_transfer_update(
            &app_handle,
            &transfer_id_for_thread,
            TransferState::Running,
            0,
            None,
            Some("开始远端打包下载".to_string()),
        );
        let run_result = (|| -> Result<(u64, Option<u64>), ErrorDto> {
            let session = open_authenticated_session(&host, &prepared_auth)?;
            let mut probe_channel = session
                .channel_session()
                .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建远端命令通道失败"))?;
            let dependency_command = archive_dependency_command(&archive_format);
            probe_channel
                .exec(&format!("command -v {dependency_command} >/dev/null 2>&1"))
                .map_err(|_| {
                    ErrorDto::new(
                        ErrorCode::IoError,
                        format!("检测远端 {dependency_command} 失败"),
                    )
                })?;
            probe_channel.wait_close().map_err(|_| {
                ErrorDto::new(
                    ErrorCode::IoError,
                    format!("检测远端 {dependency_command} 失败"),
                )
            })?;
            if probe_channel.exit_status().unwrap_or(1) != 0 {
                return Err(ErrorDto::new(
                    ErrorCode::DepMissing,
                    format!("远端缺少 {dependency_command} 命令，无法执行压缩下载"),
                ));
            }

            let command = build_remote_archive_command(&selected_paths, &archive_format);
            let mut channel = session
                .channel_session()
                .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建远端命令通道失败"))?;
            channel
                .exec(&command)
                .map_err(|_| ErrorDto::new(ErrorCode::IoError, "启动远端压缩命令失败"))?;
            let mut local_file = fs::File::create(&resolved_local_path_for_thread)
                .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建本地压缩包失败"))?;

            let mut buffer = vec![0_u8; 64 * 1024];
            let mut done_bytes = 0_u64;
            loop {
                if canceled.load(Ordering::Relaxed) {
                    let _ = channel.close();
                    let _ = fs::remove_file(&resolved_local_path_for_thread);
                    return Err(ErrorDto::new(ErrorCode::Canceled, "压缩下载已取消"));
                }
                let read_size = channel
                    .read(&mut buffer)
                    .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取远端压缩流失败"))?;
                if read_size == 0 {
                    break;
                }
                local_file
                    .write_all(&buffer[..read_size])
                    .map_err(|_| ErrorDto::new(ErrorCode::IoError, "写入本地压缩包失败"))?;
                done_bytes = done_bytes.saturating_add(read_size as u64);
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    TransferState::Running,
                    done_bytes,
                    None,
                    None,
                );
            }
            local_file
                .flush()
                .map_err(|_| ErrorDto::new(ErrorCode::IoError, "写入本地压缩包失败"))?;
            channel
                .wait_close()
                .map_err(|_| ErrorDto::new(ErrorCode::IoError, "结束远端压缩命令失败"))?;
            let status = channel.exit_status().unwrap_or(1);
            if status != 0 {
                let mut stderr_text = String::new();
                let _ = channel.stderr().read_to_string(&mut stderr_text);
                let message = if stderr_text.trim().is_empty() {
                    "远端压缩命令执行失败".to_string()
                } else {
                    format!("远端压缩失败：{}", stderr_text.trim())
                };
                let _ = fs::remove_file(&resolved_local_path_for_thread);
                return Err(ErrorDto::new(ErrorCode::IoError, message));
            }
            Ok((done_bytes, None))
        })();

        match run_result {
            Ok((done_bytes, total_bytes)) => {
                let manager = app_handle.state::<TransferManager>();
                update_transfer_record_state(
                    &manager,
                    &transfer_id_for_thread,
                    TransferState::Done,
                );
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    TransferState::Done,
                    done_bytes,
                    total_bytes,
                    Some(format!(
                        "压缩下载完成：{}",
                        path_to_string(&resolved_local_path_for_thread)
                    )),
                )
            }
            Err(error) => {
                let state = if matches!(error.code, ErrorCode::Canceled) {
                    TransferState::Canceled
                } else {
                    TransferState::Error
                };
                let manager = app_handle.state::<TransferManager>();
                update_transfer_record_state(&manager, &transfer_id_for_thread, state.clone());
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    state,
                    0,
                    None,
                    Some(error.message),
                );
            }
        }
        remove_transfer_control(&app_handle, &transfer_id_for_thread);
    });

    Ok(TransferStartDto {
        transfer_id,
        resolved_local_path: Some(path_to_string(&resolved_local_path)),
        resolved_remote_path: None,
    })
}

#[tauri::command]
fn transfer_upload(
    app: tauri::AppHandle,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    transfer_manager: State<TransferManager>,
    input: TransferUploadInputDto,
) -> Result<TransferStartDto, ErrorDto> {
    let local_path = input.local_path.trim().to_string();
    let remote_path_input = input.remote_path.trim().to_string();
    let conflict_policy = normalize_conflict_policy(input.conflict_policy.as_deref(), "rename");
    let extract_after_upload = input.extract_after_upload.unwrap_or(false);
    let remove_archive_after_extract = input.remove_archive_after_extract.unwrap_or(false);
    if local_path.is_empty() || remote_path_input.is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "本地路径和远端路径不能为空",
        ));
    }
    let local_path_buf = PathBuf::from(local_path.clone());
    if !local_path_buf.exists() {
        return Err(ErrorDto::new(ErrorCode::NotFound, "本地文件不存在"));
    }
    let upload_archive_format = detect_archive_format_from_path(&local_path);
    if extract_after_upload && upload_archive_format.is_none() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "仅支持对 .tar.gz/.tgz/.tar/.tar.bz2/.tbz2/.tbz/.tar.xz/.txz/.zip 文件执行上传后解压",
        ));
    }

    let host = load_host_for_remote_operation(&app, &hosts_manager, &input.host_id)?;
    if !host.proxy_jump.trim().is_empty() {
        return Err(ErrorDto::new(
            ErrorCode::Unsupported,
            "传输当前仅支持直连主机，暂不支持 ProxyJump",
        ));
    }
    let auth_mode = normalize_auth_mode(&host.auth_mode);
    let one_time_password = prepare_one_time_password(&auth_mode, input.password)?;
    let prepared_auth = prepare_sftp_auth(&host, &auth_mode, one_time_password, &vault_manager)?;
    ensure_known_host_trusted(&app, &known_hosts_manager, &host)?;
    let preview_sftp = open_authenticated_sftp(&host, &prepared_auth)?;
    let remote_path =
        resolve_remote_conflict_path(&preview_sftp, &remote_path_input, &conflict_policy)?;
    let extract_destination = input
        .extract_destination
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default_extract_destination(&remote_path));

    let transfer_id = Uuid::new_v4().to_string();
    let canceled = insert_transfer_control(&transfer_manager, &transfer_id);
    upsert_transfer_record(
        &transfer_manager,
        TransferRecord {
            transfer_id: transfer_id.clone(),
            direction: "upload".to_string(),
            local_path: Some(local_path_buf.clone()),
            state: TransferState::Queued,
        },
    );
    emit_transfer_update(
        &app,
        &transfer_id,
        TransferState::Queued,
        0,
        None,
        Some("上传任务已入队".to_string()),
    );

    let app_handle = app.clone();
    let transfer_id_for_thread = transfer_id.clone();
    let remote_path_for_thread = remote_path.clone();
    thread::spawn(move || {
        let manager = app_handle.state::<TransferManager>();
        update_transfer_record_state(&manager, &transfer_id_for_thread, TransferState::Running);
        emit_transfer_update(
            &app_handle,
            &transfer_id_for_thread,
            TransferState::Running,
            0,
            None,
            Some("开始上传".to_string()),
        );
        let run_result = (|| -> Result<(u64, Option<u64>), ErrorDto> {
            let sftp = open_authenticated_sftp(&host, &prepared_auth)?;
            let mut local_file = fs::File::open(&local_path_buf)
                .map_err(|_| ErrorDto::new(ErrorCode::NotFound, "读取本地文件失败"))?;
            let total_bytes = local_file.metadata().ok().map(|meta| meta.len());
            let mut remote_file = sftp
                .create(Path::new(&remote_path_for_thread))
                .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建远端文件失败"))?;
            let mut buffer = vec![0_u8; 64 * 1024];
            let mut done_bytes = 0_u64;
            loop {
                if canceled.load(Ordering::Relaxed) {
                    let _ = sftp.unlink(Path::new(&remote_path_for_thread));
                    return Err(ErrorDto::new(ErrorCode::Canceled, "上传已取消"));
                }
                let read_size = local_file
                    .read(&mut buffer)
                    .map_err(|_| ErrorDto::new(ErrorCode::IoError, "读取本地文件失败"))?;
                if read_size == 0 {
                    break;
                }
                remote_file
                    .write_all(&buffer[..read_size])
                    .map_err(|_| ErrorDto::new(ErrorCode::IoError, "写入远端文件失败"))?;
                done_bytes = done_bytes.saturating_add(read_size as u64);
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    TransferState::Running,
                    done_bytes,
                    total_bytes,
                    None,
                );
            }
            if extract_after_upload {
                if canceled.load(Ordering::Relaxed) {
                    return Err(ErrorDto::new(ErrorCode::Canceled, "上传已取消"));
                }
                let archive_format = upload_archive_format.ok_or_else(|| {
                    ErrorDto::new(ErrorCode::Unsupported, "当前文件格式不支持远端自动解压")
                })?;
                let dependency_command = extract_dependency_command(archive_format);
                run_remote_command_checked(
                    &host,
                    &prepared_auth,
                    &format!("command -v {dependency_command} >/dev/null 2>&1"),
                    &format!("检测远端 {dependency_command}"),
                )
                .map_err(|error| {
                    if matches!(error.code, ErrorCode::IoError) {
                        ErrorDto::new(
                            ErrorCode::DepMissing,
                            format!("远端缺少 {dependency_command} 命令，无法自动解压"),
                        )
                    } else {
                        error
                    }
                })?;
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    TransferState::Running,
                    done_bytes,
                    total_bytes,
                    Some(format!("上传完成，开始解压到 {extract_destination}")),
                );
                let extract_command = build_remote_extract_command(
                    archive_format,
                    &remote_path_for_thread,
                    &extract_destination,
                    remove_archive_after_extract,
                );
                run_remote_command_checked(
                    &host,
                    &prepared_auth,
                    &extract_command,
                    "远端自动解压",
                )?;
            }
            Ok((done_bytes, total_bytes))
        })();

        match run_result {
            Ok((done_bytes, total_bytes)) => {
                let manager = app_handle.state::<TransferManager>();
                update_transfer_record_state(
                    &manager,
                    &transfer_id_for_thread,
                    TransferState::Done,
                );
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    TransferState::Done,
                    done_bytes,
                    total_bytes,
                    Some(if extract_after_upload {
                        format!("上传并解压完成：{extract_destination}")
                    } else {
                        "上传完成".to_string()
                    }),
                )
            }
            Err(error) => {
                let state = if matches!(error.code, ErrorCode::Canceled) {
                    TransferState::Canceled
                } else {
                    TransferState::Error
                };
                let manager = app_handle.state::<TransferManager>();
                update_transfer_record_state(&manager, &transfer_id_for_thread, state.clone());
                emit_transfer_update(
                    &app_handle,
                    &transfer_id_for_thread,
                    state,
                    0,
                    None,
                    Some(error.message),
                );
            }
        }
        remove_transfer_control(&app_handle, &transfer_id_for_thread);
    });

    Ok(TransferStartDto {
        transfer_id,
        resolved_local_path: None,
        resolved_remote_path: Some(remote_path),
    })
}

#[tauri::command]
fn transfer_cancel(
    transfer_manager: State<TransferManager>,
    transfer_id: String,
) -> Result<(), ErrorDto> {
    let items = transfer_manager.items.lock();
    let control = items
        .get(&transfer_id)
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "传输任务不存在"))?;
    control.canceled.store(true, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
fn transfer_verify_sha256(
    app: tauri::AppHandle,
    transfer_manager: State<TransferManager>,
    transfer_id: String,
) -> Result<TransferVerifyResultDto, ErrorDto> {
    emit_transfer_verify(
        &app,
        &transfer_id,
        TransferVerifyState::Running,
        None,
        Some("开始计算 SHA256".to_string()),
    );
    let verify_result = (|| -> Result<(String, PathBuf), ErrorDto> {
        let record = transfer_manager
            .records
            .lock()
            .get(&transfer_id)
            .cloned()
            .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "传输任务不存在"))?;
        if record.direction != "download" {
            return Err(ErrorDto::new(
                ErrorCode::Unsupported,
                "仅下载任务支持 SHA256 校验",
            ));
        }
        if !matches!(record.state, TransferState::Done) {
            return Err(ErrorDto::new(
                ErrorCode::Unsupported,
                "仅已完成的下载任务可执行 SHA256 校验",
            ));
        }
        let local_path = record
            .local_path
            .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "本地文件路径不存在"))?;
        let sha256 = sha256_file_hex(&local_path)?;
        Ok((sha256, local_path))
    })();

    match verify_result {
        Ok((sha256, local_path)) => {
            emit_transfer_verify(
                &app,
                &transfer_id,
                TransferVerifyState::Done,
                Some(sha256.clone()),
                Some(format!("SHA256 校验完成：{}", path_to_string(&local_path))),
            );
            Ok(TransferVerifyResultDto {
                ok: true,
                sha256: Some(sha256),
            })
        }
        Err(error) => {
            emit_transfer_verify(
                &app,
                &transfer_id,
                TransferVerifyState::Error,
                None,
                Some(error.message.clone()),
            );
            Err(error)
        }
    }
}

fn spawn_terminal_with_command(
    app: &tauri::AppHandle,
    manager: &State<TerminalManager>,
    mut command: CommandBuilder,
    cleanup_paths: Vec<PathBuf>,
) -> Result<TerminalSessionDto, ErrorDto> {
    let terminal_id = Uuid::new_v4().to_string();
    emit_terminal_status(app, &terminal_id, TerminalState::Connecting, None);

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 28,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建终端会话失败"))?;

    command.env("TERM", "xterm-256color");
    let child = pair
        .slave
        .spawn_command(command)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "启动终端进程失败"))?;
    drop(pair.slave);

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建终端读通道失败"))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建终端写通道失败"))?;

    manager.sessions.lock().insert(
        terminal_id.clone(),
        TerminalSession {
            master: pair.master,
            writer,
            child,
            cleanup_paths,
        },
    );

    let app_handle = app.clone();
    let terminal_id_for_thread = terminal_id.clone();
    thread::spawn(move || {
        let mut buf = [0_u8; 16 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => {
                    emit_terminal_status(
                        &app_handle,
                        &terminal_id_for_thread,
                        TerminalState::Closed,
                        Some("终端会话已结束".to_string()),
                    );
                    break;
                }
                Ok(n) => {
                    let chunk_b64 = STANDARD.encode(&buf[..n]);
                    let _ = app_handle.emit(
                        "terminal.output",
                        TerminalOutputEventDto {
                            terminal_id: terminal_id_for_thread.clone(),
                            chunk_b64,
                        },
                    );
                }
                Err(_) => {
                    emit_terminal_status(
                        &app_handle,
                        &terminal_id_for_thread,
                        TerminalState::Error,
                        Some("读取终端输出失败".to_string()),
                    );
                    break;
                }
            }
        }
        if let Some(current) = app_handle
            .state::<TerminalManager>()
            .sessions
            .lock()
            .remove(&terminal_id_for_thread)
        {
            for path in current.cleanup_paths {
                let _ = fs::remove_file(path);
            }
        }
        cleanup_ssh_connection(
            &app_handle,
            &app_handle.state::<SshConnectionManager>(),
            &app_handle.state::<MonitorManager>(),
            &terminal_id_for_thread,
        );
    });

    emit_terminal_status(app, &terminal_id, TerminalState::Ready, None);
    Ok(TerminalSessionDto {
        terminal_id,
        connection_id: None,
    })
}

fn detect_shell(shell_profile: Option<String>) -> String {
    if let Some(profile) = shell_profile {
        if !profile.trim().is_empty() {
            return profile;
        }
    }

    #[cfg(target_os = "windows")]
    {
        "powershell.exe".to_string()
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string())
    }
}

#[tauri::command]
fn terminal_spawn_local(
    app: tauri::AppHandle,
    manager: State<TerminalManager>,
    shell_profile: Option<String>,
) -> Result<TerminalSessionDto, ErrorDto> {
    let shell = detect_shell(shell_profile);
    let cmd = CommandBuilder::new(shell);
    spawn_terminal_with_command(&app, &manager, cmd, Vec::new())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn terminal_connect_ssh(
    app: tauri::AppHandle,
    terminal_manager: State<TerminalManager>,
    ssh_connection_manager: State<SshConnectionManager>,
    hosts_manager: State<HostsStoreManager>,
    known_hosts_manager: State<KnownHostsStoreManager>,
    vault_manager: State<VaultManager>,
    host_id: String,
    password: Option<String>,
) -> Result<TerminalSessionDto, ErrorDto> {
    let _hosts_guard = hosts_manager.lock.lock();
    let hosts = load_hosts_from_disk(&app)?;
    let host = hosts
        .items
        .iter()
        .find(|item| item.host_id == host_id)
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "Host 不存在"))?;

    let host = host.clone();
    let auth_mode = normalize_auth_mode(&host.auth_mode);
    let proxy_jump = validate_proxy_jump(&host.proxy_jump)?;
    let one_time_password = prepare_one_time_password(&auth_mode, password)?;
    let prepared_auth =
        prepare_sftp_auth(&host, &auth_mode, one_time_password.clone(), &vault_manager)?;
    ensure_known_host_trusted(&app, &known_hosts_manager, &host)?;

    let known_hosts_path = known_hosts_ssh_path(&app)?;
    let null_known_hosts = if cfg!(target_os = "windows") {
        "NUL"
    } else {
        "/dev/null"
    };
    ensure_dependency("ssh", "OpenSSH 客户端")?;
    let mut cleanup_paths = Vec::new();
    let mut cmd = if auth_mode == "password" {
        #[cfg(not(target_os = "windows"))]
        {
            ensure_dependency("sshpass", "brew/apt/yum 安装 sshpass")?;
            let mut value = CommandBuilder::new("sshpass");
            value.arg("-e");
            value.arg("ssh");
            value.env("SSHPASS", one_time_password.unwrap_or_default());
            value
        }
        #[cfg(target_os = "windows")]
        {
            CommandBuilder::new("ssh")
        }
    } else {
        CommandBuilder::new("ssh")
    };
    cmd.arg("-p");
    cmd.arg(host.port.to_string());
    cmd.arg("-o");
    cmd.arg("StrictHostKeyChecking=yes");
    cmd.arg("-o");
    cmd.arg(format!("GlobalKnownHostsFile={null_known_hosts}"));
    cmd.arg("-o");
    cmd.arg(format!(
        "UserKnownHostsFile={}",
        known_hosts_path.to_string_lossy()
    ));
    if !proxy_jump.trim().is_empty() {
        cmd.arg("-J");
        cmd.arg(proxy_jump);
    }
    match auth_mode.as_str() {
        "key" => {
            let key_id = host
                .key_id
                .as_ref()
                .ok_or_else(|| ErrorDto::new(ErrorCode::Unsupported, "当前 Host 未配置密钥"))?;
            let identity_path = prepare_ssh_identity_file(&app, &vault_manager, key_id)?;
            cmd.arg("-i");
            cmd.arg(identity_path.to_string_lossy().to_string());
            cmd.arg("-o");
            cmd.arg("IdentitiesOnly=yes");
            cleanup_paths.push(identity_path);
        }
        "agent" => {
            cmd.arg("-o");
            cmd.arg("IdentitiesOnly=no");
        }
        "password" => {
            cmd.arg("-o");
            cmd.arg("PreferredAuthentications=password,keyboard-interactive");
            cmd.arg("-o");
            cmd.arg("PubkeyAuthentication=no");
            cmd.arg("-o");
            cmd.arg("NumberOfPasswordPrompts=1");
        }
        "auto" => {}
        _ => {}
    }
    cmd.arg(format!("{}@{}", host.username, host.address));

    let mut response = spawn_terminal_with_command(&app, &terminal_manager, cmd, cleanup_paths)?;
    let connection_id = register_ssh_connection(
        &ssh_connection_manager,
        &response.terminal_id,
        host,
        prepared_auth,
    );
    response.connection_id = Some(connection_id);
    Ok(response)
}

#[tauri::command]
fn terminal_write(
    manager: State<TerminalManager>,
    terminal_id: String,
    data_b64: String,
) -> Result<(), ErrorDto> {
    let data = STANDARD
        .decode(data_b64)
        .map_err(|_| ErrorDto::new(ErrorCode::Unsupported, "终端输入格式错误"))?;

    let mut sessions = manager.sessions.lock();
    let session = sessions
        .get_mut(&terminal_id)
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "终端会话不存在"))?;

    session
        .writer
        .write_all(&data)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "写入终端失败"))?;
    session
        .writer
        .flush()
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "刷新终端缓冲失败"))?;
    Ok(())
}

#[tauri::command]
fn terminal_resize(
    manager: State<TerminalManager>,
    terminal_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), ErrorDto> {
    let mut sessions = manager.sessions.lock();
    let session = sessions
        .get_mut(&terminal_id)
        .ok_or_else(|| ErrorDto::new(ErrorCode::NotFound, "终端会话不存在"))?;

    let size = PtySize {
        cols: cols.max(1),
        rows: rows.max(1),
        pixel_width: 0,
        pixel_height: 0,
    };
    session
        .master
        .resize(size)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "调整终端尺寸失败"))?;
    Ok(())
}

#[tauri::command]
fn terminal_close(
    app: tauri::AppHandle,
    manager: State<TerminalManager>,
    ssh_connection_manager: State<SshConnectionManager>,
    monitor_manager: State<MonitorManager>,
    terminal_id: String,
) -> Result<(), ErrorDto> {
    let session = manager.sessions.lock().remove(&terminal_id);
    if let Some(mut current) = session {
        current
            .child
            .kill()
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "关闭终端进程失败"))?;
        for path in current.cleanup_paths {
            let _ = fs::remove_file(path);
        }
        emit_terminal_status(
            &app,
            &terminal_id,
            TerminalState::Closed,
            Some("终端会话已手动关闭".to_string()),
        );
        cleanup_ssh_connection(
            &app,
            &ssh_connection_manager,
            &monitor_manager,
            &terminal_id,
        );
        return Ok(());
    }

    Err(ErrorDto::new(ErrorCode::NotFound, "终端会话不存在"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(TerminalManager::default())
        .manage(SshConnectionManager::default())
        .manage(MonitorManager::default())
        .manage(HostsStoreManager::default())
        .manage(KnownHostsStoreManager::default())
        .manage(VaultManager::default())
        .manage(TransferManager::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            app_get_bootstrap,
            store_hosts_list,
            store_hosts_upsert,
            store_hosts_delete,
            known_hosts_list,
            known_hosts_trust,
            vault_status,
            vault_unlock,
            vault_lock,
            key_import_private_key,
            key_list,
            monitor_subscribe,
            monitor_unsubscribe,
            monitor_set_path_probe,
            fs_list_remote,
            fs_delete_remote,
            fs_read_text,
            fs_write_text_atomic,
            process_list_remote,
            process_signal_remote,
            service_list_remote,
            service_action_remote,
            transfer_download,
            archive_pack_stream_download,
            transfer_upload,
            transfer_cancel,
            transfer_verify_sha256,
            terminal_spawn_local,
            terminal_connect_ssh,
            terminal_write,
            terminal_resize,
            terminal_close
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
