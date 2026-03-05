use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use lastsheel_core::{
    AppBootstrapDto, ErrorCode, ErrorDto, TerminalOutputEventDto, TerminalSessionDto,
    TerminalState, TerminalStatusEventDto,
};
use parking_lot::Mutex;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::thread;
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

#[tauri::command]
fn app_get_bootstrap(app: tauri::AppHandle) -> Result<AppBootstrapDto, ErrorDto> {
    let default_download_dir = app
        .path()
        .download_dir()
        .map_err(|_| ErrorDto::new(ErrorCode::IoError, "无法读取系统下载目录"))?
        .join("LastSheel");
    let features = vec![
        "本地终端 PTY（xterm.js + WebGL）".to_string(),
        "标签与分屏基础布局".to_string(),
        "Rust Workspace + CI".to_string(),
    ];

    Ok(AppBootstrapDto::new(
        app.package_info().version.to_string(),
        default_download_dir.to_string_lossy().to_string(),
        features,
    ))
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
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            app_get_bootstrap,
            terminal_spawn_local,
            terminal_write,
            terminal_resize,
            terminal_close
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
