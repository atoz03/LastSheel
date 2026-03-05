# LastSheel

LastSheel 是一个面向 Linux 远端主机的桌面 SSH 运维工具，当前仓库已完成
V1 里程碑 M1~M5（阶段3）基础能力：

- Tauri v2 + React + TypeScript 项目骨架
- Rust Workspace（`src-tauri` + `crates/lastsheel-core`）
- Hosts 会话工作区（标签 + 分屏 + QuickSend + 历史检索）
- Hosts 本地持久化（新增/列表/删除）
- Vault 主密码初始化/解锁/锁定 + 私钥导入（本地加密存储）
- Rust 本地 PTY 会话管理（spawn/write/resize/close）
- SSH 直连基础能力（Host 信任校验后发起连接）
- known_hosts 严格策略（未知阻断、变更阻断、应用内信任）
- SSH 认证与跳板基础能力（auto/password/key/agent + ProxyJump 最多2跳）
- 密码认证优化（一次性密码输入 + `sshpass` 自动注入，不落盘）
- 代理链路可观测性（`PROXY_JUMP_FAILED` + 跳板链路原因提示）
- 文件栏首期能力（SSH 会话下远端目录 SFTP 列表、路径切换与双击进入目录）
- 传输队列增强（上传/下载冲突策略、批量下载、SHA256 校验）
- 统一错误码与启动配置 DTO（Rust -> 前端 Event/Command）
- GitHub Actions 持续集成（TypeScript + Rust）

## 本地开发

```bash
pnpm install
pnpm tauri dev
```

## 质量检查

```bash
pnpm lint
pnpm typecheck
pnpm build
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## 目录结构

- `src/`：React 前端（导航、页面骨架）
- `src-tauri/`：Tauri 桌面入口与命令注册
- `crates/lastsheel-core/`：共享 DTO 与错误码定义
- `plan.md`：V1 总计划（产品与接口约束）

## 当前状态

- 已完成：里程碑 1（脚手架、基础窗口路由、CI）
- 已完成：里程碑 2（本地终端 MVP：xterm.js + WebGL + 标签 + 分屏）
- 已完成：里程碑 3（Hosts + Vault + Store）
- 已完成：里程碑 4 阶段3（SSH 认证补齐 + ProxyJump 可观测性）
- 已完成：里程碑 5 阶段3（传输校验 + 冲突策略 + 批量操作）
