import type { FormEvent } from "react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { decodeBase64ToUtf8, encodeUtf8ToBase64 } from "./encoding";
import { TerminalPane } from "./TerminalPane";
import type {
  TerminalOutputPayload,
  TerminalPaneModel,
  TerminalSessionResponse,
  TerminalStatusPayload,
  TerminalTabModel,
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

function formatInvokeError(error: unknown): string {
  if (typeof error === "string") {
    return error;
  }
  if (error && typeof error === "object") {
    const message = (error as { message?: unknown }).message;
    if (typeof message === "string") {
      return message;
    }
    try {
      return JSON.stringify(error);
    } catch {
      return "未知错误";
    }
  }
  return String(error);
}

function createTab(title: string, pane: TerminalPaneModel): TerminalTabModel {
  const tabId = crypto.randomUUID();
  return {
    tab_id: tabId,
    title,
    panes: [pane],
    active_pane_id: pane.pane_id,
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
  const inputBufferRef = useRef<Record<string, string>>({});
  const tabsRef = useRef<TerminalTabModel[]>([]);

  const activeTab = useMemo(
    () => tabs.find((tab) => tab.tab_id === activeTabId) ?? null,
    [activeTabId, tabs],
  );

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
        setNotice(`保存 Host 失败：${String(error)}`);
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
        setNotice(`删除 Host 失败：${String(error)}`);
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
      const tab = createTab(title, pane);
      setActiveTabId(tab.tab_id);
      return [...prev, tab];
    });
    setNotice("已创建本地终端标签。");
  }, [createTerminalPane]);

  const connectSshHost = useCallback(async (host: HostItem) => {
    try {
      const response = await invoke<TerminalSessionResponse>("terminal_connect_ssh", {
        hostId: host.host_id,
      });
      const pane: TerminalPaneModel = {
        pane_id: crypto.randomUUID(),
        terminal_id: response.terminal_id,
        status: "connecting",
      };
      setTabs((prev) => {
        const tab = createTab(`SSH:${host.alias}`, pane);
        setActiveTabId(tab.tab_id);
        return [...prev, tab];
      });
      setNotice(`SSH 会话已创建：${host.alias}`);
    } catch (error: unknown) {
      setNotice(`SSH 连接失败：${formatInvokeError(error)}`);
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
    };
  }, [updatePaneStatus]);

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

  const filteredHistory = useMemo(() => {
    const keyword = historyKeyword.trim().toLowerCase();
    if (!keyword) {
      return history;
    }
    return history.filter((line) => line.toLowerCase().includes(keyword));
  }, [history, historyKeyword]);

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
            <h4>文件栏（M3 占位）</h4>
            <p>将于 M5 接入 SFTP 列表、传输队列与在线编辑。</p>
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
