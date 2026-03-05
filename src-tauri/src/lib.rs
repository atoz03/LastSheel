use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use argon2::Argon2;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use lastsheel_core::{
    AppBootstrapDto, ErrorCode, ErrorDto, HostItemDto, HostUpsertInputDto, KeyImportResultDto,
    KeyMetadataDto, TerminalOutputEventDto, TerminalSessionDto, TerminalState,
    TerminalStatusEventDto, VaultStatusDto,
};
use parking_lot::Mutex;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{Emitter, Manager, State};
use uuid::Uuid;

struct TerminalSession {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn Child + Send>,
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
struct VaultManager {
    runtime: Mutex<VaultRuntime>,
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
        "pnpm + Rust CI 工作流".to_string(),
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
    let terminal_id = Uuid::new_v4().to_string();
    emit_terminal_status(&app, &terminal_id, TerminalState::Connecting, None);

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 28,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "创建本地终端失败"))?;

    let shell = detect_shell(shell_profile);
    let cmd = CommandBuilder::new(shell);
    let child = pair
        .slave
        .spawn_command(cmd)
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "启动本地 shell 失败"))?;
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
    });

    emit_terminal_status(&app, &terminal_id, TerminalState::Ready, None);
    Ok(TerminalSessionDto { terminal_id })
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
    terminal_id: String,
) -> Result<(), ErrorDto> {
    let session = manager.sessions.lock().remove(&terminal_id);
    if let Some(mut current) = session {
        current
            .child
            .kill()
            .map_err(|_| ErrorDto::new(ErrorCode::IoError, "关闭终端进程失败"))?;
        emit_terminal_status(
            &app,
            &terminal_id,
            TerminalState::Closed,
            Some("终端会话已手动关闭".to_string()),
        );
        return Ok(());
    }

    Err(ErrorDto::new(ErrorCode::NotFound, "终端会话不存在"))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(TerminalManager::default())
        .manage(HostsStoreManager::default())
        .manage(VaultManager::default())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            app_get_bootstrap,
            store_hosts_list,
            store_hosts_upsert,
            store_hosts_delete,
            vault_status,
            vault_unlock,
            vault_lock,
            key_import_private_key,
            key_list,
            terminal_spawn_local,
            terminal_write,
            terminal_resize,
            terminal_close
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
