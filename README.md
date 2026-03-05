# LastSheel

LastSheel 是一个面向 Linux 远端主机的桌面 SSH 运维工具，当前仓库已完成
V1 里程碑 M1 与 M2（本地终端 MVP）基础能力：

- Tauri v2 + React + TypeScript 项目骨架
- Rust Workspace（`src-tauri` + `crates/lastsheel-core`）
- Hosts 会话工作区（标签 + 分屏 + QuickSend + 历史检索）
- Rust 本地 PTY 会话管理（spawn/write/resize/close）
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
- 下一步：里程碑 3（Hosts + Vault + Store）
