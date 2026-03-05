# LastSheel V1 总开发计划（落到接口与交互细节）

## 摘要

V1 用 Rust + Tauri + React/TS 从零实现跨平台桌面 SSH 终端工具，必须实现三块：

1. FinalShell 风格：会话界面左侧常驻 系统监控（CPU/内存/负载/网速/磁盘挂载/路径探测），并配套 进程管理 + systemctl 服务管理。
2. Termius 风格：本地化的 Hosts/Keychain/Port Forwarding/Snippets/Known Hosts/Logs 管理页（无云同步），支持加密备份导入导出。
3. WindTerm 风格：会话内 快速发送（片段）+ 历史命令（默认不落盘），右侧可停靠面板快速检索与一键发送。

关键 UI 决策已锁定：

- 文件管理器 底部常驻文件栏（随当前 SSH 会话显示），下载默认保存到 可配置下载目录。
- 远端系统 V1 仅 Linux；默认无 sudo、无 agent；可选一次性 user-level agent（不常驻、无安装、无 sudo）。
- 终端渲染 V1 使用 xterm.js + WebGL Addon，并实现背压/流控策略，确保大输出不锁死 UI。
- known_hosts 默认严格校验：首次必须确认指纹；指纹变化必须阻断并提示；信任记录只写应用内（不改用户 ~/.ssh/known_hosts）。
- 端口转发默认安全策略：-L/-D 默认仅监听 127.0.0.1；需要 0.0.0.0 时显式选择并强提示风险。
- SSH Agent Forwarding 支持但默认关闭（会话级开关，开启时强提示风险）。
- SSH config 策略：一次性导入（不持续同步，不自动改写用户 ~/.ssh/config）。
- 硬件钥匙（FIDO2/Touch ID）V1 不做。

## 执行记录（2026-03-05）

- ✅ 已完成里程碑 1：脚手架与 CI
  - Tauri + React/TS 工程初始化完成
  - Rust Workspace 拆分为 `src-tauri` + `crates/lastsheel-core`
  - 全局导航与 7 个管理页路由骨架完成
  - 错误码 DTO 与启动配置命令（`app_get_bootstrap`）已接通
  - GitHub Actions（lint/typecheck/build/fmt/clippy）已配置
- ✅ 已完成里程碑 2：本地终端 MVP
  - Rust 端接入本地 PTY 生命周期：spawn/write/resize/close
  - 前端接入 xterm.js + WebGL，支持终端输出事件订阅
  - Hosts 会话区支持标签与双栏分屏、快捷键（Ctrl+Shift+T / Ctrl+\ / Ctrl+Shift+W）
  - 右侧接入 QuickSend 与 History 检索/一键发送
  - 包管理切换为 pnpm（含 CI/tauri before*Command）
- ✅ 已完成里程碑 3：Hosts + Vault + Store
  - Hosts 本地 Store：新增、更新、删除、列表读取
  - Vault 本地加密：主密码初始化/解锁/锁定（Argon2 + AES-GCM-SIV）
  - Keychain：支持导入 PEM 私钥并展示元数据列表（V1 不生成）
  - 前端 Hosts/Keychain 页面接入真实 Tauri Commands
- 🚧 里程碑 4（阶段1）已开始：SSH 直连 + known_hosts 严格校验
  - 新增 `terminal_connect_ssh(host_id)`，基于已信任 Host 发起 SSH 会话
  - 新增 `known_hosts_trust/list`，信任记录仅保存在应用内并供前端展示
  - 连接前执行主机指纹校验：未知返回 `HOSTKEY_UNKNOWN`，变更返回 `HOSTKEY_CHANGED`
  - Hosts 页支持“SSH连接 / 信任指纹”，Known Hosts 页支持查看记录
- ✅ 里程碑 4（阶段2）已完成：认证能力补齐与代理跳转
  - Host 新增认证模式字段：auto/password/key/agent
  - key 模式支持从 Vault 选择密钥，连接时临时落盘私钥并以 `-i` 启动 ssh
  - 支持 ProxyJump（逗号分隔，最多2跳）并在后端严格校验格式
  - Hosts 页新增认证方式、密钥选择与 ProxyJump 输入
- ✅ 里程碑 4（阶段3）已完成：密码认证优化与代理链路可观测性
  - password 模式支持一次性密码输入（前端 prompt，不落盘）并通过 `sshpass` 注入
  - 主机指纹探测切换为 `ssh-keyscan`，支持 `ProxyJump` 探测链路
  - 新增 `PROXY_JUMP_FAILED` 错误码并映射常见异常（解析失败/超时/拒绝连接）
  - Hosts 页连接失败提示按错误码给出可执行指引
- ✅ 里程碑 5（阶段1）已完成：底部文件栏远端目录列表
  - 新增 `fs_list_remote(host_id, path, password?)`，通过 SFTP 返回目录项元数据
  - Hosts 会话底部文件栏接入路径输入、刷新、双击目录进入
  - password 模式复用一次性密码（仅内存缓存，不落盘）
  - 当前限制：文件栏仅支持直连主机，含 ProxyJump 的 Host 暂不支持
- ✅ 里程碑 5（阶段2）已完成：传输队列 upload/download + 取消
  - 新增 `transfer_download/transfer_upload/transfer_cancel` 命令与 `transfer.update` 事件
  - 下载默认落盘到系统下载目录 `LastSheel/<host_alias>/`，同名自动追加后缀
  - Hosts 文件栏接入上传/下载入口、进度展示与任务取消
  - 当前限制：传输链路与文件列表一致，仅支持直连主机
- ✅ 里程碑 5（阶段3）已完成：传输校验、冲突策略与批量操作
  - `transfer_download/transfer_upload` 新增冲突策略（`rename/overwrite/skip`）
  - 新增 `transfer_verify_sha256` 命令与 `transfer.verify` 事件，支持下载完成后校验
  - 文件栏新增多选与批量下载入口，传输队列新增 SHA256 校验按钮与结果展示
  - 当前限制：传输链路与文件列表一致，仅支持直连主机
- 🚧 里程碑 5（阶段4）进行中：高级文件操作与在线编辑
  - 新增 `fs_delete_remote`，支持远端文件/目录递归删除（含批量路径）
  - 新增 `fs_read_text/fs_write_text_atomic`，支持 UTF-8 小文件在线编辑与原子写回
  - Hosts 文件栏新增批量删除入口与在线编辑弹窗（保存前 Diff 预览）
  - 当前限制：仅支持 UTF-8 文本；远端压缩下载/上传后解压待下一步
- ▶ 下一执行目标：里程碑 5（阶段4-2：远端压缩下载与上传后解压）

———

## 目标与验收标准（可量化）

1. 三平台（Win/macOS/Linux）安装包可运行，能自动更新。
2. SSH 会话：密钥 + agent + 密码 + keyboard-interactive；ProxyJump 1-2 跳；known_hosts 严格校验。
3. 端口转发：-L/-R/-D 可创建/查看/停止；断线自动清理；错误可定位到原因。
4. 左侧监控：1 秒级刷新 CPU/网速曲线，10 秒级刷新挂载与磁盘；缺失权限/命令时局部降级而不影响终端。
5. 文件栏：表格列齐全（名/大小/类型/修改时间/权限/用户组），上传下载队列可靠；支持远端压缩流式下载、上传后解压；在线编辑小文件并保存前展示 diff。
6. 进程 + systemctl：进程列表与 kill 可用；systemctl 存在时提供服务列表与 start/stop/restart/status；无权限时提示明确。
7. 快速发送与历史：片段支持参数模板；历史命令可搜索与一键发送；默认不落盘，可收藏到片段。
8. Keychain：支持导入私钥/口令/密码；支持生成 Ed25519；支持一键部署公钥到 authorized_keys。
9. 备份：支持导入/导出加密备份包（包含私钥），默认使用主密码加密；备份格式为单文件自定义格式（例如 .lsbak）。

———

## UI 信息架构与布局（对标你 3 张图的组合）

### 1) 全局导航（Termius 风格）

左侧最外层是导航栏（图标 + 文本）：

- Hosts
- Keychain
- Port Forwarding
- Snippets
- Known Hosts
- Logs
- Settings

### 2) Hosts 页（会话树）

- 树节点：分组（可嵌套）/Host
- Host 元数据（V1）：分组、标签（tags）、备注（note）、收藏（pin）
- 快捷动作：连接（新标签）、在分屏中连接、复制地址、编辑

### 3) 会话工作区（WindTerm + FinalShell 融合）

当打开 SSH 标签时，进入“会话视图”，布局固定为：

- 左侧：上半区 Hosts 树，下半区 监控面板（常驻，可折叠）
- 中央：终端（xterm.js），支持标签与分屏
- 右侧：可折叠停靠栏（默认隐藏）
  - QuickSend（片段）
  - History（历史命令）
- 底部：文件栏（仅 SSH 会话显示）
  - Files：远程文件表格
  - Transfers：传输队列
    -（可选）Logs：仅该连接的操作日志

———

## 前后端接口（字段级，保证实现时不再做产品决策）

所有接口通过 Tauri commands/events；Rust 端对外暴露稳定 DTO（JSON）。

### A. 连接与终端

Commands

- terminal.connect_ssh(host_id) -> { terminal_id, connection_id }
- terminal.spawn_local(shell_profile) -> { terminal_id }
- terminal.write(terminal_id, data_b64)
- terminal.resize(terminal_id, cols, rows)
- terminal.close(terminal_id)

Events

- terminal.output { terminal_id, chunk_b64 }
- terminal.status { terminal_id, state: connecting|ready|closed|error, message? }

### B. 监控订阅

Commands

- monitor.subscribe(connection_id, profile) -> { subscription_id }
  - profile 固定枚举：basic（CPU/内存/负载/网速/uptime），disk（挂载/df/可用），path_probe（指定路径探测）
- monitor.unsubscribe(subscription_id)
- monitor.set_path_probe(subscription_id, paths: string[])（最多 10 个路径，超出拒绝）

Events

- monitor.update { connection_id, ts_ms, kind, payload }
  - kind=basic payload：
    - cpu_total_pct
    - load1, load5, load15
    - mem_total_kb, mem_used_kb, mem_cached_kb, swap_total_kb, swap_used_kb
    - net: [{ ifname, rx_bytes_per_s, tx_bytes_per_s, rx_total_bytes, tx_total_bytes }]
    - uptime_s
  - kind=disk payload：
    - mounts: [{ mount, fstype?, device?, total_bytes, used_bytes, avail_bytes, used_pct }]
  - kind=path_probe payload：
    - paths: [{ path, exists, readable, writable, mount, avail_bytes, total_bytes, dir_size_bytes? }]
    - dir_size_bytes 默认不采集，只有用户点“计算目录大小”才触发（避免卡顿）

### C. 文件管理与传输

Commands

- fs.list(connection_id, path, sort) -> { entries: FileEntry[], cwd, caps }
  - FileEntry：
    - name
    - path（规范化绝对路径）
    - type: file|dir|symlink|char|block|socket|fifo|unknown
    - size_bytes
    - mtime_ms
    - mode_octal（如 0755）
    - uid, gid
    - user_name?, group_name?（可用则填；不可用就空）
- fs.mkdir/fs.rename/fs.delete/fs.chmod/fs.chown（chown 若无权限返回明确错误码）
- 在线编辑
  - fs.read_text(connection_id, path, max_bytes=2_000_000) -> { text, encoding }
  - fs.write_text_atomic(connection_id, path, text, encoding) -> { new_mtime_ms }
  - 原子策略固定：写入同目录临时文件 .<name>.tmp.<rand> -> fsync -> rename 覆盖（失败则不改动原文件）
- 传输
  - transfer.upload(connection_id, local_path, remote_path) -> { transfer_id }
  - transfer.download(connection_id, remote_path, local_path?) -> { transfer_id, resolved_local_path }
  - transfer.cancel(transfer_id)
  - transfer.verify_sha256(transfer_id) -> { ok, sha256? }（下载完成后可选校验）
- 远端压缩下载（核心）
  - archive.pack_stream_download(connection_id, paths[], format: tar_gz|zip, local_path?) -> { transfer_id }
  - 后端选择命令优先级：tar 优先，其次 zip；都没有则报错
- 上传后解压
  - archive.upload_and_unpack(connection_id, local_archive_path, remote_dest, format) -> { transfer_id }
  - 流程固定：上传到 remote_dest/.lastsheeel_upload_<rand> -> 解压 -> 清理临时文件
  - 清理失败要提示但不阻断（用户可手动删除）

Events

- transfer.update { transfer_id, state: queued|running|done|error|canceled, done_bytes, total_bytes?, message? }

下载目录策略（已锁定）

- Settings：download_dir 默认取系统 Downloads
- 冲突：自动追加 (1) (2) 后缀
- 每次下载默认直接落到 download_dir/LastSheel/<host_alias>/（host_alias 可配置，默认 host 名）
- 传输并发默认：下载 4 并发、上传 4 并发（可在设置里调整）
- 下载断点续传：支持对同一远端文件进行 resume（服务器不支持时降级为重新下载并提示）
- 隐藏文件显示：默认显示以 . 开头的文件（可在设置切换隐藏）
- 文件默认排序：目录优先 + 名称升序；支持按名称/时间/大小升降序排序

### D. 进程与服务

Commands

- process.list(connection_id, filter) -> { items: ProcessItem[] }
  - ProcessItem：pid,user,pcpu,pmem,stat,start_ts_ms?,cmdline
- process.signal(connection_id, pid, signal: TERM|KILL|INT|HUP|USR1|USR2)
- service.list(connection_id, scope: system|user) -> { items: ServiceItem[], supported: boolean }
  - ServiceItem：name, load_state, active_state, sub_state, description?
- service.action(connection_id, scope, name, action: start|stop|restart|status) -> { ok, message }
  - 需要 sudo 时：返回错误码 SUDO_REQUIRED，前端弹出密码输入；输入后调用 service.action_with_sudo(password)（仅内存，不落盘）

### E. Keychain（密钥库）与备份

Commands

- key.import_private_key(name, pem_text, passphrase?) -> { key_id }
- key.generate_ed25519(name, comment?) -> { key_id, public_key_text }
- key.set_ssh_password(host_id, password) -> { ok }
- key.deploy_public_key(connection_id, public_key_text, ensure_perms: true) -> { ok, message? }
- backup.export(path, password?) -> { ok }（默认使用主密码；可选覆盖为独立导出密码）
- backup.import(path, password?) -> { ok, message? }

约束

- 备份格式：单文件自定义格式（例如 .lsbak），包含版本号、KDF 参数、加密 payload 与完整性校验。
- 备份默认包含私钥与口令/密码等敏感信息，必须加密；导入前展示包含内容摘要。
- SSH 密码默认按 Host 绑定，不做跨 Host 复用。

———

## 远端采集与命令执行（安全与兼容策略）

### 1) 默认“无 agent、无 sudo”

优先 SFTP 读取：

- /proc/stat, /proc/meminfo, /proc/loadavg, /proc/uptime, /proc/net/dev, /proc/mounts

必须 exec 的命令（白名单、无用户拼接）

- 磁盘：df -kP（稳定易解析）
- 分区（可选增强）：lsblk -b -J（存在则用，否则跳过）
- 进程：优先 ps -eo pid,user,pcpu,pmem,stat,lstart,args --sort=-pcpu；不支持则 fallback 扫 /proc/<pid>/stat/status,cmdline
- systemctl：先 command -v systemctl 探测；不存在则 supported=false

监控补充规则

- 网速默认接口：自动选择最近流量最大的非 lo 接口；用户可下拉切换。
- 路径探测默认路径：/、/home、/var，并自动补充 /mnt 下的每个目录；允许每 Host 覆盖配置。
- 左侧监控包含 Top 进程：CPU Top5 + MEM Top5，点击可跳转进程管理页并带过滤。

### 2) 参数安全

- 任何含路径参数的 exec 都必须走 sh_quote() 单引号转义策略（固定实现，不允许临时拼接）。
- 禁止把用户输入直接拼到 shell 命令中；只能作为“参数”传入并被 quote。

### 3) 可选一次性 agent（user-level）

- 不依赖 sudo，不写 systemd
- 仅在用户手动开启“增强监控”时启用
- 上传到 ~/.cache/lastsheeel-agent/ 并直接运行，退出即删除（删除失败也只提示）

———

## 文件栏与终端目录“联动”设计（避免脆弱解析）

V1 不解析 shell prompt 来猜 cwd，采用显式联动按钮：

- 文件栏顶部提供
  - “同步到终端目录”：后端在该连接 exec pwd，将文件栏切换到该路径
  - “在终端 cd 到此目录”：在终端发送 cd '<path>' 并回车（可关闭自动回车）
- 这样既有顺手体验，又避免不同 shell/提示符导致的不稳定。

———

## 快速发送与历史命令（细则已锁定）

### 片段（Snippets）

- 范围：全局/会话（host）级
- 模板：${VAR} 占位符
- 内置变量：${HOST} ${USER} ${PORT} ${SESSION_NAME}
- 发送：可选“发送后自动回车”
- 记录：片段触发会写入会话日志（便于审计自己操作）

### 历史命令（默认不落盘）

- 捕获规则：记录“用户在输入框按 Enter 发送的整行文本”
- 存储：只在内存 ring buffer（默认 500 条，可配置）
- 操作：搜索、双击发送、收藏到片段
- 脱敏（V1 默认启用简单规则）：匹配 password=, token=, AKIA 等常见模式时提示用户是否保存到历史（默认不保存）

———

## 文件操作默认策略（V1）

- 删除：永久删除（二次确认，不做回收站逻辑）。
- 符号链接：标记为链接，默认双击跟随进入目标（解析失败则提示并允许复制链接目标）。
- 批量操作：支持多选复制/移动/删除。
- 同名冲突：弹窗选择覆盖/跳过/重命名，并支持“应用到全部”。

———

## 事件与错误码约定（V1）

统一规则

- 所有 command 返回统一错误结构：{ code, message, detail? }（Tauri 侧映射为前端可消费的 Error DTO）。
- 禁止把敏感信息写入 message/detail（例如私钥内容、密码、完整命令行含密钥路径等）。
- 前端根据 code 决定交互（弹窗、重试、提示安装依赖等），避免字符串匹配。

核心错误码（可扩展）

- VAULT_LOCKED：保险箱未解锁
- AUTH_FAILED：认证失败
- HOSTKEY_CHANGED：主机指纹变化（必须阻断）
- HOSTKEY_UNKNOWN：未知主机指纹（需要用户确认）
- SUDO_REQUIRED：需要 sudo 才能执行
- DEP_MISSING：远端缺少依赖命令（例如 tar/zip/lsblk）
- PERMISSION_DENIED：权限不足
- NOT_FOUND：文件/路径不存在
- CONFLICT：同名冲突（未指定策略时）
- UNSUPPORTED：服务器或协议不支持（例如不支持 resume）
- IO_ERROR：I/O 错误（网络/磁盘/通道）
- CANCELED：操作被取消

新增 Events（补齐 Keychain/备份/转发/校验）

- forward.update { forward_id, state: starting|running|stopped|error, message? }
- keychain.changed { reason: imported|generated|deleted|password_updated }
- backup.progress { state: running|done|error, message?, done_bytes?, total_bytes? }
- transfer.verify { transfer_id, state: running|done|error, sha256?, message? }

转发与传输的安全交互

- 当用户把 -L/-D bind 改为 0.0.0.0 时，前端必须弹确认，并在 UI 持久标记“对外监听”状态。

———

## 数据库存储（本地-only）

- hosts/groups/tags/notes
- keys（密钥内容放 vault 加密表）
- known_hosts
- snippets
- forwards（配置与最近状态）
- settings/layouts
- logs（操作日志与错误，便于诊断）
- 历史命令默认不入库（符合你的选择）
  - 历史命令如需落盘，后续版本再设计加密索引与检索性能

———

## 里程碑与交付物（每一步都有可运行验收）

1. 脚手架与 CI：Tauri + React/TS + Rust workspace；fmt/clippy/eslint/typecheck；基础窗口与路由
2. 终端 MVP：本地 PTY + xterm.js + WebGL；标签与分屏；基础快捷键
3. Hosts + Vault + Store：会话树、标签/备注；主密码解锁/锁定；密钥导入（不生成）
4. SSH 直连：russh + 认证 + known_hosts；终端 I/O 稳定
5. 底部文件栏：SFTP 列表列齐全；上传下载队列；默认下载目录策略
6. 监控（无 agent）：/proc + df；左侧常驻面板 UI（曲线+挂载条形图+路径探测）
7. 进程 + systemctl：列表/动作；权限与缺失命令降级
8. 端口转发：-L/-R/-D + UI 管理 + 生命周期清理
9. 在线编辑 + diff：小文件读取/编辑/保存前 diff/原子替换；失败回滚
10. 快速发送 + 历史：右侧停靠栏；命令面板（Ctrl+P）聚合动作
11. 性能与稳定：高吞吐压测；背压参数固化；错误码与提示统一
12. 打包与自动更新：三平台产物；签名；release 流水线

———

## 明确非目标（V1 不做）

- FIDO2/Touch ID
- 终端图像协议
- 云同步/团队协作
- 插件系统
