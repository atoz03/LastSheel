import type { FormEvent } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { decodeBase64ToUtf8, encodeUtf8ToBase64 } from "./encoding";
import { TerminalPane } from "./TerminalPane";
import type {
  RemoteFileEntry,
  RemoteFileListResponse,
  TerminalOutputPayload,
  TerminalPaneModel,
  TerminalSessionResponse,
  TerminalStatusPayload,
  TerminalTabModel,
  TransferStartResponse,
  TransferState,
  TransferUpdatePayload,
} from "./types";
import "./hosts-workspace.css";

const SNIPPETS = [
  "uname -a",
  "whoami && id",
  "df -h",
  "free -m",
  "ps -eo pid,user,pcpu,pmem,comm --sort=-pcpu | head",
];

const HISTORY_LIMIT = 500;
const DEFAULT_PORT = 22;

type HostItem = {
  host_id: string;
  alias: string;
  address: string;
  port: number;
  username: string;
  auth_mode: string;
  key_id?: string | null;
  proxy_jump: string;
  tags: string[];
  note: string;
  pinned: boolean;
};

type KeyOption = {
  key_id: string;
  name: string;
  created_at_ms?: number;
};

type HostForm = {
  alias: string;
  address: string;
  port: string;
  username: string;
  authMode: "auto" | "password" | "key" | "agent";
  keyId: string;
  proxyJump: string;
  tags: string;
  note: string;
  pinned: boolean;
};

type InvokeErrorDto = {
  code?: string;
  message?: string;
};

type TransferItem = {
  transfer_id: string;
  direction: "download" | "upload";
  host_alias: string;
  target_path: string;
  state: TransferState;
  done_bytes: number;
  total_bytes?: number | null;
  message?: string;
};

function getInvokeError(error: unknown): { code?: string; message: string } {
  if (typeof error === "string") {
    return { message: error };
  }
  if (error && typeof error === "object") {
    const payload = error as InvokeErrorDto;
    if (typeof payload.message === "string") {
      return {
        code: typeof payload.code === "string" ? payload.code : undefined,
        message: payload.message,
      };
    }
    try {
      return { message: JSON.stringify(error) };
    } catch {
      return { message: "未知错误" };
    }
  }
  return { message: String(error) };
}

function formatInvokeError(error: unknown): string {
  const payload = getInvokeError(error);
  if (!payload.code) {
    return payload.message;
  }
  return `[${payload.code}] ${payload.message}`;
}

function formatSshConnectError(error: unknown): string {
  const payload = getInvokeError(error);
  switch (payload.code) {
    case "HOSTKEY_UNKNOWN":
      return `${payload.message}（请先点击“信任指纹”）`;
    case "HOSTKEY_CHANGED":
      return `${payload.message}（请确认后重新信任）`;
    case "VAULT_LOCKED":
      return `${payload.message}（请先在 Keychain 解锁 Vault）`;
    case "PROXY_JUMP_FAILED":
      return `${payload.message}（请检查跳板机地址、端口与网络）`;
    case "DEP_MISSING":
      return `${payload.message}（请安装缺失依赖后重试）`;
    default:
      return payload.code ? `[${payload.code}] ${payload.message}` : payload.message;
  }
}

function formatFileSize(sizeBytes: number): string {
  if (sizeBytes >= 1024 * 1024 * 1024) {
    return `${(sizeBytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  }
  if (sizeBytes >= 1024 * 1024) {
    return `${(sizeBytes / (1024 * 1024)).toFixed(1)} MB`;
  }
  if (sizeBytes >= 1024) {
    return `${(sizeBytes / 1024).toFixed(1)} KB`;
  }
  return `${sizeBytes} B`;
}

function formatMtime(timestampMs: number): string {
  if (timestampMs <= 0) {
    return "-";
  }
  return new Date(timestampMs).toLocaleString();
}

function formatTransferProgress(doneBytes: number, totalBytes?: number | null): string {
  if (totalBytes && totalBytes > 0) {
    const pct = Math.min(100, (doneBytes / totalBytes) * 100);
    return `${formatFileSize(doneBytes)} / ${formatFileSize(totalBytes)} (${pct.toFixed(1)}%)`;
  }
  return formatFileSize(doneBytes);
}

function createTab(
  title: string,
  pane: TerminalPaneModel,
  options: { tabKind: "local" | "ssh"; hostId?: string; hostAlias?: string },
): TerminalTabModel {
  const tabId = crypto.randomUUID();
  return {
    tab_id: tabId,
    title,
    panes: [pane],
    active_pane_id: pane.pane_id,
    tab_kind: options.tabKind,
    host_id: options.hostId,
    host_alias: options.hostAlias,
  };
}

export function HostsWorkspace() {
  const [tabs, setTabs] = useState<TerminalTabModel[]>([]);
  const [activeTabId, setActiveTabId] = useState<string | null>(null);
  const [chunksByTerminal, setChunksByTerminal] = useState<Record<string, string[]>>({});
  const [history, setHistory] = useState<string[]>([]);
  const [historyKeyword, setHistoryKeyword] = useState("");
  const [notice, setNotice] = useState("按 Ctrl+Shift+T 新建标签，Ctrl+\\ 进行分屏。");
  const [hosts, setHosts] = useState<HostItem[]>([]);
  const [hostForm, setHostForm] = useState<HostForm>({
    alias: "",
    address: "",
    port: "22",
    username: "root",
    authMode: "auto",
    keyId: "",
    proxyJump: "",
    tags: "",
    note: "",
    pinned: false,
  });
  const [keyOptions, setKeyOptions] = useState<KeyOption[]>([]);
  const [remoteEntriesByTab, setRemoteEntriesByTab] = useState<Record<string, RemoteFileEntry[]>>({});
  const [remoteCwdByTab, setRemoteCwdByTab] = useState<Record<string, string>>({});
  const [remotePathInputByTab, setRemotePathInputByTab] = useState<Record<string, string>>({});
  const [remoteLoadingTabId, setRemoteLoadingTabId] = useState<string | null>(null);
  const [selectedRemotePathByTab, setSelectedRemotePathByTab] = useState<Record<string, string>>({});
  const [transferItems, setTransferItems] = useState<TransferItem[]>([]);
  const [transferBusy, setTransferBusy] = useState(false);
  const inputBufferRef = useRef<Record<string, string>>({});
  const tabsRef = useRef<TerminalTabModel[]>([]);
  const passwordCacheRef = useRef<Record<string, string>>({});

  const activeTab = useMemo(
    () => tabs.find((tab) => tab.tab_id === activeTabId) ?? null,
    [activeTabId, tabs],
  );
  const hostById = useMemo(
    () => new Map(hosts.map((host) => [host.host_id, host])),
    [hosts],
  );
  const activeSshHost = useMemo(() => {
    if (!activeTab || activeTab.tab_kind !== "ssh" || !activeTab.host_id) {
      return null;
    }
    return hostById.get(activeTab.host_id) ?? null;
  }, [activeTab, hostById]);

  useEffect(() => {
    tabsRef.current = tabs;
  }, [tabs]);

  const updatePaneStatus = useCallback(
    (terminalId: string, state: TerminalPaneModel["status"], message?: string) => {
      setTabs((prev) =>
        prev.map((tab) => ({
          ...tab,
          panes: tab.panes.map((pane) =>
            pane.terminal_id === terminalId ? { ...pane, status: state, message } : pane,
          ),
        })),
      );
    },
    [],
  );

  const pushHistory = useCallback((line: string) => {
    const value = line.trim();
    if (!value) {
      return;
    }
    setHistory((prev) => {
      const next = [value, ...prev.filter((item) => item !== value)];
      return next.slice(0, HISTORY_LIMIT);
    });
  }, []);

  const loadHosts = useCallback(async () => {
    try {
      const response = await invoke<HostItem[]>("store_hosts_list");
      setHosts(response);
    } catch {
      setNotice("Hosts 存储暂不可用，请通过 `pnpm tauri dev` 启动。");
    }
  }, []);

  const loadKeyOptions = useCallback(async () => {
    try {
      const response = await invoke<KeyOption[]>("key_list");
      setKeyOptions(response);
    } catch {
      setKeyOptions([]);
    }
  }, []);

  const saveHost = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      const tags = hostForm.tags
        .split(",")
        .map((tag) => tag.trim())
        .filter((tag) => tag.length > 0);
      const port = Number(hostForm.port);

      try {
        await invoke("store_hosts_upsert", {
          input: {
            alias: hostForm.alias,
            address: hostForm.address,
            port: Number.isNaN(port) ? DEFAULT_PORT : port,
            username: hostForm.username,
            authMode: hostForm.authMode,
            keyId: hostForm.keyId || null,
            proxyJump: hostForm.proxyJump,
            tags,
            note: hostForm.note,
            pinned: hostForm.pinned,
          },
        });
        await loadHosts();
        setHostForm((prev) => ({
          ...prev,
          alias: "",
          address: "",
          keyId: "",
          proxyJump: "",
          tags: "",
          note: "",
          pinned: false,
        }));
        setNotice("Host 已保存。");
      } catch (error: unknown) {
        setNotice(`保存 Host 失败：${formatInvokeError(error)}`);
      }
    },
    [hostForm, loadHosts],
  );

  const removeHost = useCallback(
    async (hostId: string) => {
      try {
        await invoke("store_hosts_delete", { hostId });
        await loadHosts();
        setNotice("Host 已删除。");
      } catch (error: unknown) {
        setNotice(`删除 Host 失败：${formatInvokeError(error)}`);
      }
    },
    [loadHosts],
  );

  const trustHost = useCallback(async (hostId: string) => {
    try {
      const result = await invoke<{ fingerprint_sha256: string }>("known_hosts_trust", { hostId });
      setNotice(`已信任主机指纹：${result.fingerprint_sha256}`);
    } catch (error: unknown) {
      setNotice(`信任主机失败：${formatInvokeError(error)}`);
    }
  }, []);

  const writeTerminal = useCallback(
    async (terminalId: string, data: string) => {
      const current = inputBufferRef.current[terminalId] ?? "";
      let nextBuffer = current;
      for (const char of data) {
        if (char === "\r") {
          pushHistory(nextBuffer);
          nextBuffer = "";
          continue;
        }
        if (char === "\u007F") {
          nextBuffer = nextBuffer.slice(0, -1);
          continue;
        }
        if (char >= " ") {
          nextBuffer += char;
        }
      }
      inputBufferRef.current[terminalId] = nextBuffer;

      try {
        await invoke("terminal_write", {
          terminalId,
          dataB64: encodeUtf8ToBase64(data),
        });
      } catch {
        setNotice("终端写入失败，请检查会话状态。");
      }
    },
    [pushHistory],
  );

  const resizeTerminal = useCallback(async (terminalId: string, cols: number, rows: number) => {
    try {
      await invoke("terminal_resize", {
        terminalId,
        cols,
        rows,
      });
    } catch {
      setNotice("终端尺寸同步失败，已保持当前显示。");
    }
  }, []);

  const closeTerminal = useCallback(async (terminalId: string) => {
    try {
      await invoke("terminal_close", { terminalId });
    } catch {
      // 会话可能已自然退出，忽略关闭错误
    }
    delete inputBufferRef.current[terminalId];
    setChunksByTerminal((prev) => {
      const next = { ...prev };
      delete next[terminalId];
      return next;
    });
  }, []);

  const createTerminalPane = useCallback(async (): Promise<TerminalPaneModel | null> => {
    try {
      const response = await invoke<TerminalSessionResponse>("terminal_spawn_local");
      return {
        pane_id: crypto.randomUUID(),
        terminal_id: response.terminal_id,
        status: "connecting",
      };
    } catch {
      setNotice("无法启动本地终端，请确认通过 `pnpm tauri dev` 运行。");
      return null;
    }
  }, []);

  const createNewTab = useCallback(async () => {
    const pane = await createTerminalPane();
    if (!pane) {
      return;
    }
    setTabs((prev) => {
      const title = `本地会话 ${prev.length + 1}`;
      const tab = createTab(title, pane, { tabKind: "local" });
      setActiveTabId(tab.tab_id);
      return [...prev, tab];
    });
    setNotice("已创建本地终端标签。");
  }, [createTerminalPane]);

  const connectSshHost = useCallback(async (host: HostItem) => {
    let oneTimePassword: string | null = null;
    if (host.auth_mode === "password") {
      oneTimePassword = window.prompt(`请输入 ${host.alias} 的一次性 SSH 密码（不会落盘）`, "");
      if (oneTimePassword === null) {
        setNotice("已取消 SSH 连接。");
        return;
      }
      if (!oneTimePassword.trim()) {
        setNotice("密码不能为空。");
        return;
      }
      passwordCacheRef.current[host.host_id] = oneTimePassword;
    }
    try {
      const response = await invoke<TerminalSessionResponse>("terminal_connect_ssh", {
        hostId: host.host_id,
        password: oneTimePassword,
      });
      const pane: TerminalPaneModel = {
        pane_id: crypto.randomUUID(),
        terminal_id: response.terminal_id,
        status: "connecting",
      };
      setTabs((prev) => {
        const tab = createTab(`SSH:${host.alias}`, pane, {
          tabKind: "ssh",
          hostId: host.host_id,
          hostAlias: host.alias,
        });
        setActiveTabId(tab.tab_id);
        return [...prev, tab];
      });
      setNotice(`SSH 会话已创建：${host.alias}`);
    } catch (error: unknown) {
      setNotice(`SSH 连接失败：${formatSshConnectError(error)}`);
    }
  }, []);

  const splitActiveTab = useCallback(async () => {
    if (!activeTab || activeTab.panes.length >= 2) {
      return;
    }
    const pane = await createTerminalPane();
    if (!pane) {
      return;
    }
    setTabs((prev) =>
      prev.map((tab) =>
        tab.tab_id === activeTab.tab_id
          ? {
              ...tab,
              panes: [...tab.panes, pane],
              active_pane_id: pane.pane_id,
            }
          : tab,
      ),
    );
    setNotice("分屏已创建。");
  }, [activeTab, createTerminalPane]);

  const closeActivePane = useCallback(async () => {
    if (!activeTab) {
      return;
    }
    const targetPane = activeTab.panes.find((pane) => pane.pane_id === activeTab.active_pane_id);
    if (!targetPane) {
      return;
    }
    await closeTerminal(targetPane.terminal_id);
    setTabs((prev) =>
      prev
        .map((tab) => {
          if (tab.tab_id !== activeTab.tab_id) {
            return tab;
          }
          const remaining = tab.panes.filter((pane) => pane.pane_id !== targetPane.pane_id);
          if (remaining.length === 0) {
            return null;
          }
          return {
            ...tab,
            panes: remaining,
            active_pane_id: remaining[0].pane_id,
          };
        })
        .filter((tab): tab is TerminalTabModel => tab !== null),
    );
    setNotice("当前终端已关闭。");
  }, [activeTab, closeTerminal]);

  const sendLineToActivePane = useCallback(
    async (line: string) => {
      const pane = activeTab?.panes.find((item) => item.pane_id === activeTab.active_pane_id);
      if (!pane) {
        return;
      }
      await writeTerminal(pane.terminal_id, `${line}\r`);
    },
    [activeTab, writeTerminal],
  );

  const requestPasswordForHost = useCallback((host: HostItem, forcePrompt: boolean): string | null => {
    if (host.auth_mode !== "password") {
      return null;
    }
    if (!forcePrompt) {
      const cached = passwordCacheRef.current[host.host_id];
      if (cached) {
        return cached;
      }
    }
    const value = window.prompt(`请输入 ${host.alias} 的一次性 SSH 密码（不会落盘）`, "");
    if (value === null) {
      return null;
    }
    if (!value.trim()) {
      setNotice("密码不能为空。");
      return null;
    }
    passwordCacheRef.current[host.host_id] = value;
    return value;
  }, []);

  const loadRemoteFilesForTab = useCallback(
    async (tab: TerminalTabModel, targetPath?: string, forcePasswordPrompt = false) => {
      if (tab.tab_kind !== "ssh" || !tab.host_id) {
        return;
      }
      const host = hostById.get(tab.host_id);
      if (!host) {
        setNotice("无法读取远端文件：Host 已不存在。");
        return;
      }
      if (host.proxy_jump.trim()) {
        setRemoteEntriesByTab((prev) => ({ ...prev, [tab.tab_id]: [] }));
        setRemoteCwdByTab((prev) => ({ ...prev, [tab.tab_id]: "-" }));
        return;
      }

      const password =
        host.auth_mode === "password" ? requestPasswordForHost(host, forcePasswordPrompt) : null;
      if (host.auth_mode === "password" && password === null) {
        setRemoteEntriesByTab((prev) =>
          Object.prototype.hasOwnProperty.call(prev, tab.tab_id) ? prev : { ...prev, [tab.tab_id]: [] },
        );
        return;
      }

      setRemoteLoadingTabId(tab.tab_id);
      try {
        const response = await invoke<RemoteFileListResponse>("fs_list_remote", {
          hostId: host.host_id,
          path: targetPath?.trim() ? targetPath.trim() : null,
          password,
        });
        setRemoteEntriesByTab((prev) => ({ ...prev, [tab.tab_id]: response.entries }));
        setRemoteCwdByTab((prev) => ({ ...prev, [tab.tab_id]: response.cwd }));
        setRemotePathInputByTab((prev) => ({ ...prev, [tab.tab_id]: response.cwd }));
        setSelectedRemotePathByTab((prev) => {
          const selected = prev[tab.tab_id];
          if (selected && response.entries.some((entry) => entry.path === selected)) {
            return prev;
          }
          return { ...prev, [tab.tab_id]: "" };
        });
      } catch (error: unknown) {
        const payload = getInvokeError(error);
        if (payload.code === "AUTH_FAILED") {
          delete passwordCacheRef.current[host.host_id];
        }
        setNotice(`文件列表加载失败：${formatInvokeError(error)}`);
      } finally {
        setRemoteLoadingTabId((prev) => (prev === tab.tab_id ? null : prev));
      }
    },
    [hostById, requestPasswordForHost],
  );

  const refreshActiveRemoteFiles = useCallback(async () => {
    if (!activeTab || activeTab.tab_kind !== "ssh") {
      return;
    }
    const preferredPath = remotePathInputByTab[activeTab.tab_id] ?? remoteCwdByTab[activeTab.tab_id] ?? ".";
    await loadRemoteFilesForTab(activeTab, preferredPath);
  }, [activeTab, loadRemoteFilesForTab, remoteCwdByTab, remotePathInputByTab]);

  const openRemoteDirectory = useCallback(
    async (entry: RemoteFileEntry) => {
      if (!activeTab || activeTab.tab_kind !== "ssh") {
        return;
      }
      await loadRemoteFilesForTab(activeTab, entry.path);
    },
    [activeTab, loadRemoteFilesForTab],
  );

  const upsertTransferItem = useCallback((nextItem: { transfer_id: string } & Partial<TransferItem>) => {
    setTransferItems((prev) => {
      const existingIndex = prev.findIndex((item) => item.transfer_id === nextItem.transfer_id);
      if (existingIndex < 0) {
        const created: TransferItem = {
          transfer_id: nextItem.transfer_id,
          direction: nextItem.direction ?? "download",
          host_alias: nextItem.host_alias ?? "-",
          target_path: nextItem.target_path ?? "-",
          state: nextItem.state ?? "queued",
          done_bytes: nextItem.done_bytes ?? 0,
          total_bytes: nextItem.total_bytes ?? null,
          message: nextItem.message,
        };
        return [created, ...prev].slice(0, 20);
      }
      const next = [...prev];
      next[existingIndex] = { ...next[existingIndex], ...nextItem };
      return next;
    });
  }, []);

  const startDownload = useCallback(async () => {
    if (!activeTab || activeTab.tab_kind !== "ssh" || !activeTab.host_id) {
      return;
    }
    const host = hostById.get(activeTab.host_id);
    if (!host) {
      setNotice("无法发起下载：Host 不存在。");
      return;
    }
    const remotePath = selectedRemotePathByTab[activeTab.tab_id];
    if (!remotePath) {
      setNotice("请先在文件列表中选中要下载的文件。");
      return;
    }
    const entriesForTab = remoteEntriesByTab[activeTab.tab_id] ?? [];
    const remoteEntry = entriesForTab.find((item) => item.path === remotePath);
    if (!remoteEntry || remoteEntry.entry_type === "dir") {
      setNotice("目录不支持直接下载，请选择文件。");
      return;
    }
    const customLocalPath = window.prompt("可选：输入本地保存路径（留空则使用默认下载目录）", "");
    if (customLocalPath === null) {
      setNotice("已取消下载。");
      return;
    }
    const password = host.auth_mode === "password" ? requestPasswordForHost(host, false) : null;
    if (host.auth_mode === "password" && password === null) {
      return;
    }
    setTransferBusy(true);
    try {
      const response = await invoke<TransferStartResponse>("transfer_download", {
        input: {
          hostId: host.host_id,
          remotePath: remoteEntry.path,
          localPath: customLocalPath.trim() ? customLocalPath.trim() : null,
          password,
        },
      });
      upsertTransferItem({
        transfer_id: response.transfer_id,
        direction: "download",
        host_alias: host.alias,
        target_path: remoteEntry.path,
        state: "queued",
        done_bytes: 0,
        total_bytes: null,
        message: response.resolved_local_path ?? "下载任务已创建",
      });
      setNotice("下载任务已创建。");
    } catch (error: unknown) {
      const payload = getInvokeError(error);
      if (payload.code === "AUTH_FAILED") {
        delete passwordCacheRef.current[host.host_id];
      }
      setNotice(`下载失败：${formatInvokeError(error)}`);
    } finally {
      setTransferBusy(false);
    }
  }, [activeTab, hostById, remoteEntriesByTab, requestPasswordForHost, selectedRemotePathByTab, upsertTransferItem]);

  const startUpload = useCallback(async () => {
    if (!activeTab || activeTab.tab_kind !== "ssh" || !activeTab.host_id) {
      return;
    }
    const host = hostById.get(activeTab.host_id);
    if (!host) {
      setNotice("无法发起上传：Host 不存在。");
      return;
    }
    const localPath = window.prompt("请输入本地文件绝对路径", "");
    if (localPath === null) {
      setNotice("已取消上传。");
      return;
    }
    if (!localPath.trim()) {
      setNotice("本地路径不能为空。");
      return;
    }
    const currentCwd = remoteCwdByTab[activeTab.tab_id] ?? "-";
    const defaultRemote = currentCwd !== "-" ? `${currentCwd}/` : "";
    const remotePath = window.prompt("请输入远端目标文件路径", defaultRemote);
    if (remotePath === null) {
      setNotice("已取消上传。");
      return;
    }
    if (!remotePath.trim()) {
      setNotice("远端路径不能为空。");
      return;
    }
    const password = host.auth_mode === "password" ? requestPasswordForHost(host, false) : null;
    if (host.auth_mode === "password" && password === null) {
      return;
    }
    setTransferBusy(true);
    try {
      const response = await invoke<TransferStartResponse>("transfer_upload", {
        input: {
          hostId: host.host_id,
          localPath: localPath.trim(),
          remotePath: remotePath.trim(),
          password,
        },
      });
      upsertTransferItem({
        transfer_id: response.transfer_id,
        direction: "upload",
        host_alias: host.alias,
        target_path: remotePath.trim(),
        state: "queued",
        done_bytes: 0,
        total_bytes: null,
      });
      setNotice("上传任务已创建。");
    } catch (error: unknown) {
      const payload = getInvokeError(error);
      if (payload.code === "AUTH_FAILED") {
        delete passwordCacheRef.current[host.host_id];
      }
      setNotice(`上传失败：${formatInvokeError(error)}`);
    } finally {
      setTransferBusy(false);
    }
  }, [activeTab, hostById, remoteCwdByTab, requestPasswordForHost, upsertTransferItem]);

  const cancelTransfer = useCallback(async (transferId: string) => {
    try {
      await invoke("transfer_cancel", { transferId });
      setNotice("已发送取消请求。");
    } catch (error: unknown) {
      setNotice(`取消失败：${formatInvokeError(error)}`);
    }
  }, []);

  useEffect(() => {
    if (tabs.length === 0) {
      void createNewTab();
    }
  }, [createNewTab, tabs.length]);

  useEffect(() => {
    void loadHosts();
  }, [loadHosts]);

  useEffect(() => {
    void loadKeyOptions();
  }, [loadKeyOptions]);

  useEffect(() => {
    let unlistenOutput: (() => void) | undefined;
    let unlistenStatus: (() => void) | undefined;
    let unlistenTransfer: (() => void) | undefined;

    const bind = async () => {
      try {
        unlistenOutput = await listen<TerminalOutputPayload>("terminal.output", (event) => {
          const payload = event.payload;
          const chunk = decodeBase64ToUtf8(payload.chunk_b64);
          setChunksByTerminal((prev) => {
            const existing = prev[payload.terminal_id] ?? [];
            const next = [...existing, chunk].slice(-3000);
            return { ...prev, [payload.terminal_id]: next };
          });
        });

        unlistenStatus = await listen<TerminalStatusPayload>("terminal.status", (event) => {
          const payload = event.payload;
          updatePaneStatus(payload.terminal_id, payload.state, payload.message ?? undefined);
          if (payload.message) {
            setNotice(payload.message);
          }
        });
        unlistenTransfer = await listen<TransferUpdatePayload>("transfer.update", (event) => {
          const payload = event.payload;
          upsertTransferItem({
            transfer_id: payload.transfer_id,
            state: payload.state,
            done_bytes: payload.done_bytes,
            total_bytes: payload.total_bytes,
            message: payload.message ?? undefined,
          });
          if (payload.message && (payload.state === "done" || payload.state === "error")) {
            setNotice(payload.message);
          }
          if (payload.state === "done" || payload.state === "error" || payload.state === "canceled") {
            void refreshActiveRemoteFiles();
          }
        });
      } catch {
        setNotice("当前不是 Tauri 运行时，终端命令不可用。");
      }
    };

    void bind();
    return () => {
      if (unlistenOutput) {
        unlistenOutput();
      }
      if (unlistenStatus) {
        unlistenStatus();
      }
      if (unlistenTransfer) {
        unlistenTransfer();
      }
    };
  }, [refreshActiveRemoteFiles, updatePaneStatus, upsertTransferItem]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (!event.ctrlKey || !event.shiftKey) {
        return;
      }
      if (event.key.toLowerCase() === "t") {
        event.preventDefault();
        void createNewTab();
      }
      if (event.key === "\\") {
        event.preventDefault();
        void splitActiveTab();
      }
      if (event.key.toLowerCase() === "w") {
        event.preventDefault();
        void closeActivePane();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [closeActivePane, createNewTab, splitActiveTab]);

  useEffect(() => {
    return () => {
      const terminalIds = tabsRef.current.flatMap((tab) =>
        tab.panes.map((pane) => pane.terminal_id),
      );
      terminalIds.forEach((terminalId) => {
        void closeTerminal(terminalId);
      });
    };
  }, [closeTerminal]);

  useEffect(() => {
    if (!activeTab || activeTab.tab_kind !== "ssh") {
      return;
    }
    if (Object.prototype.hasOwnProperty.call(remoteEntriesByTab, activeTab.tab_id)) {
      return;
    }
    void loadRemoteFilesForTab(activeTab);
  }, [activeTab, loadRemoteFilesForTab, remoteEntriesByTab]);

  useEffect(() => {
    const validTabIds = new Set(tabs.map((tab) => tab.tab_id));
    setRemoteEntriesByTab((prev) => {
      const next = Object.fromEntries(
        Object.entries(prev).filter(([tabId]) => validTabIds.has(tabId)),
      );
      return Object.keys(next).length === Object.keys(prev).length ? prev : next;
    });
    setRemoteCwdByTab((prev) => {
      const next = Object.fromEntries(
        Object.entries(prev).filter(([tabId]) => validTabIds.has(tabId)),
      );
      return Object.keys(next).length === Object.keys(prev).length ? prev : next;
    });
    setRemotePathInputByTab((prev) => {
      const next = Object.fromEntries(
        Object.entries(prev).filter(([tabId]) => validTabIds.has(tabId)),
      );
      return Object.keys(next).length === Object.keys(prev).length ? prev : next;
    });
    setSelectedRemotePathByTab((prev) => {
      const next = Object.fromEntries(
        Object.entries(prev).filter(([tabId]) => validTabIds.has(tabId)),
      );
      return Object.keys(next).length === Object.keys(prev).length ? prev : next;
    });
  }, [tabs]);

  const filteredHistory = useMemo(() => {
    const keyword = historyKeyword.trim().toLowerCase();
    if (!keyword) {
      return history;
    }
    return history.filter((line) => line.toLowerCase().includes(keyword));
  }, [history, historyKeyword]);
  const activeRemoteEntries = activeTab ? remoteEntriesByTab[activeTab.tab_id] ?? [] : [];
  const activeRemoteCwd = activeTab ? remoteCwdByTab[activeTab.tab_id] ?? "-" : "-";
  const activeRemotePathInput = activeTab ? remotePathInputByTab[activeTab.tab_id] ?? "" : "";
  const activeSelectedRemotePath = activeTab ? selectedRemotePathByTab[activeTab.tab_id] ?? "" : "";

  return (
    <section className="hosts-workspace">
      <div className="workspace-toolbar">
        <div className="toolbar-actions">
          <button type="button" onClick={() => void createNewTab()}>
            新建标签
          </button>
          <button type="button" onClick={() => void splitActiveTab()}>
            垂直分屏
          </button>
          <button type="button" onClick={() => void closeActivePane()}>
            关闭当前
          </button>
        </div>
        <p>{notice}</p>
      </div>

      <div className="workspace-main">
        <aside className="workspace-left">
          <h3>Hosts</h3>
          <ul>
            {hosts.map((host) => (
              <li key={host.host_id}>
                <div className="host-item-top">
                  <span>{host.alias}</span>
                  <div className="host-item-actions">
                    <button type="button" onClick={() => void connectSshHost(host)}>
                      SSH连接
                    </button>
                    <button type="button" onClick={() => void trustHost(host.host_id)}>
                      信任指纹
                    </button>
                    <button type="button" onClick={() => void removeHost(host.host_id)}>
                      删除
                    </button>
                  </div>
                </div>
                <div className="host-item-meta">
                  {host.username}@{host.address}:{host.port}
                </div>
                <div className="host-item-meta">
                  认证：{host.auth_mode}
                  {host.proxy_jump ? ` · ProxyJump: ${host.proxy_jump}` : ""}
                  {host.key_id ? ` · Key: ${host.key_id.slice(0, 8)}` : ""}
                </div>
              </li>
            ))}
            {hosts.length === 0 ? <li>暂无 Host，请先添加。</li> : null}
          </ul>

          <form className="host-form" onSubmit={(event) => void saveHost(event)}>
            <input
              value={hostForm.alias}
              onChange={(event) =>
                setHostForm((prev) => ({ ...prev, alias: event.currentTarget.value }))
              }
              placeholder="别名，例如 prod-api"
              required
            />
            <input
              value={hostForm.address}
              onChange={(event) =>
                setHostForm((prev) => ({ ...prev, address: event.currentTarget.value }))
              }
              placeholder="地址，例如 10.10.1.8"
              required
            />
            <div className="host-form-inline-wide">
              <input
                value={hostForm.username}
                onChange={(event) =>
                  setHostForm((prev) => ({ ...prev, username: event.currentTarget.value }))
                }
                placeholder="用户名"
                required
              />
              <input
                value={hostForm.port}
                onChange={(event) =>
                  setHostForm((prev) => ({ ...prev, port: event.currentTarget.value }))
                }
                placeholder="端口"
              />
            </div>
            <div className="host-form-inline">
              <select
                value={hostForm.authMode}
                onChange={(event) =>
                  setHostForm((prev) => ({
                    ...prev,
                    authMode: event.currentTarget.value as HostForm["authMode"],
                  }))
                }
              >
                <option value="auto">自动</option>
                <option value="password">密码</option>
                <option value="key">密钥</option>
                <option value="agent">Agent</option>
              </select>
              <input
                value={hostForm.proxyJump}
                onChange={(event) =>
                  setHostForm((prev) => ({ ...prev, proxyJump: event.currentTarget.value }))
                }
                placeholder="ProxyJump，例如 bastion 或 u1@h1,u2@h2"
              />
            </div>
            <select
              value={hostForm.keyId}
              onChange={(event) =>
                setHostForm((prev) => ({ ...prev, keyId: event.currentTarget.value }))
              }
              disabled={hostForm.authMode !== "key"}
            >
              <option value="">选择密钥（仅密钥认证）</option>
              {keyOptions.map((item) => (
                <option key={item.key_id} value={item.key_id}>
                  {item.name} / {item.key_id.slice(0, 8)}
                  {item.created_at_ms ? ` / ${new Date(item.created_at_ms).toLocaleDateString()}` : ""}
                </option>
              ))}
            </select>
            <input
              value={hostForm.tags}
              onChange={(event) =>
                setHostForm((prev) => ({ ...prev, tags: event.currentTarget.value }))
              }
              placeholder="标签，逗号分隔"
            />
            <textarea
              value={hostForm.note}
              onChange={(event) =>
                setHostForm((prev) => ({ ...prev, note: event.currentTarget.value }))
              }
              placeholder="备注"
            />
            <label className="host-form-pin">
              <input
                type="checkbox"
                checked={hostForm.pinned}
                onChange={(event) =>
                  setHostForm((prev) => ({ ...prev, pinned: event.currentTarget.checked }))
                }
              />
              置顶
            </label>
            <button type="submit">保存 Host</button>
          </form>

          <h3>监控</h3>
          <p>CPU 24% · MEM 43% · Load 1.02</p>
          <p>网速 Rx 1.1MB/s · Tx 320KB/s</p>
        </aside>

        <div className="workspace-center">
          <div className="terminal-tabs">
            {tabs.map((tab) => (
              <button
                key={tab.tab_id}
                type="button"
                className={tab.tab_id === activeTabId ? "terminal-tab active" : "terminal-tab"}
                onClick={() => setActiveTabId(tab.tab_id)}
              >
                {tab.title}
              </button>
            ))}
          </div>

          <div className={activeTab?.panes.length === 2 ? "terminal-grid split" : "terminal-grid"}>
            {activeTab?.panes.map((pane) => (
              <div
                key={pane.pane_id}
                className={pane.pane_id === activeTab.active_pane_id ? "pane-frame active" : "pane-frame"}
                onClick={() =>
                  setTabs((prev) =>
                    prev.map((tab) =>
                      tab.tab_id === activeTab.tab_id ? { ...tab, active_pane_id: pane.pane_id } : tab,
                    ),
                  )
                }
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    setTabs((prev) =>
                      prev.map((tab) =>
                        tab.tab_id === activeTab.tab_id
                          ? { ...tab, active_pane_id: pane.pane_id }
                          : tab,
                      ),
                    );
                  }
                }}
                role="button"
                tabIndex={0}
              >
                <div className="pane-header">
                  <span>{pane.terminal_id.slice(0, 8)}</span>
                  <span>{pane.status}</span>
                </div>
                <TerminalPane
                  terminalId={pane.terminal_id}
                  chunks={chunksByTerminal[pane.terminal_id] ?? []}
                  onInput={(terminalId, data) => {
                    void writeTerminal(terminalId, data);
                  }}
                  onResize={(terminalId, cols, rows) => {
                    void resizeTerminal(terminalId, cols, rows);
                  }}
                />
              </div>
            ))}
          </div>

          <div className="workspace-bottom">
            <div className="filebar-header">
              <h4>文件栏</h4>
              {activeTab?.tab_kind === "ssh" ? (
                <div className="filebar-actions">
                  <input
                    value={activeRemotePathInput}
                    onChange={(event) =>
                      setRemotePathInputByTab((prev) => ({
                        ...prev,
                        [activeTab.tab_id]: event.currentTarget.value,
                      }))
                    }
                    placeholder="输入远端路径，例如 /var/log"
                  />
                  <button type="button" onClick={() => void refreshActiveRemoteFiles()}>
                    {remoteLoadingTabId === activeTab.tab_id ? "加载中..." : "刷新"}
                  </button>
                  <button
                    type="button"
                    onClick={() => void startUpload()}
                    disabled={transferBusy || remoteLoadingTabId === activeTab.tab_id}
                  >
                    上传
                  </button>
                  <button
                    type="button"
                    onClick={() => void startDownload()}
                    disabled={
                      transferBusy ||
                      remoteLoadingTabId === activeTab.tab_id ||
                      !activeSelectedRemotePath ||
                      activeRemoteEntries.find((item) => item.path === activeSelectedRemotePath)?.entry_type ===
                        "dir"
                    }
                  >
                    下载
                  </button>
                </div>
              ) : null}
            </div>
            {activeTab?.tab_kind !== "ssh" ? (
              <p>当前为本地会话，文件栏仅在 SSH 会话中可用。</p>
            ) : activeSshHost?.proxy_jump ? (
              <p>当前主机使用 ProxyJump，文件栏暂仅支持直连主机。</p>
            ) : (
              <>
                <p>
                  Host：{activeSshHost?.alias ?? activeTab.host_alias ?? "-"} · 当前目录：{activeRemoteCwd}
                </p>
                <div className="filebar-table-wrap">
                  <table className="filebar-table">
                    <thead>
                      <tr>
                        <th>名称</th>
                        <th>类型</th>
                        <th>大小</th>
                        <th>权限</th>
                        <th>UID/GID</th>
                        <th>修改时间</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeRemoteEntries.map((entry) => (
                        <tr
                          key={entry.path}
                          className={[
                            entry.entry_type === "dir" ? "file-row-dir" : "",
                            activeSelectedRemotePath === entry.path ? "file-row-selected" : "",
                          ]
                            .filter(Boolean)
                            .join(" ")}
                          onClick={() =>
                            activeTab
                              ? setSelectedRemotePathByTab((prev) => ({
                                  ...prev,
                                  [activeTab.tab_id]: entry.path,
                                }))
                              : undefined
                          }
                          onDoubleClick={() =>
                            entry.entry_type === "dir" ? void openRemoteDirectory(entry) : undefined
                          }
                        >
                          <td>{entry.name}</td>
                          <td>{entry.entry_type}</td>
                          <td>{entry.entry_type === "dir" ? "-" : formatFileSize(entry.size_bytes)}</td>
                          <td>{entry.mode_octal}</td>
                          <td>
                            {entry.uid}/{entry.gid}
                          </td>
                          <td>{formatMtime(entry.mtime_ms)}</td>
                        </tr>
                      ))}
                      {activeRemoteEntries.length === 0 && remoteLoadingTabId !== activeTab.tab_id ? (
                        <tr>
                          <td colSpan={6} className="filebar-empty">
                            暂无文件或目录
                          </td>
                        </tr>
                      ) : null}
                    </tbody>
                  </table>
                </div>
                <div className="transfer-panel">
                  <h5>传输队列</h5>
                  <ul className="transfer-list">
                    {transferItems.map((item) => (
                      <li key={item.transfer_id}>
                        <div>
                          <strong>{item.direction === "download" ? "下载" : "上传"}</strong>
                          <span>
                            {item.host_alias} · {item.state}
                          </span>
                        </div>
                        <div>
                          <span>{item.target_path}</span>
                          <span>{formatTransferProgress(item.done_bytes, item.total_bytes)}</span>
                          {item.message ? <span>{item.message}</span> : null}
                        </div>
                        {(item.state === "queued" || item.state === "running") && (
                          <button type="button" onClick={() => void cancelTransfer(item.transfer_id)}>
                            取消
                          </button>
                        )}
                      </li>
                    ))}
                    {transferItems.length === 0 ? <li className="transfer-empty">暂无传输任务</li> : null}
                  </ul>
                </div>
              </>
            )}
          </div>
        </div>

        <aside className="workspace-right">
          <h3>QuickSend</h3>
          <div className="quicksend-list">
            {SNIPPETS.map((snippet) => (
              <button key={snippet} type="button" onClick={() => void sendLineToActivePane(snippet)}>
                {snippet}
              </button>
            ))}
          </div>
          <h3>History</h3>
          <input
            value={historyKeyword}
            onChange={(event) => setHistoryKeyword(event.currentTarget.value)}
            placeholder="检索历史命令"
          />
          <div className="history-list">
            {filteredHistory.map((line) => (
              <button key={line} type="button" onClick={() => void sendLineToActivePane(line)}>
                {line}
              </button>
            ))}
          </div>
        </aside>
      </div>
    </section>
  );
}
