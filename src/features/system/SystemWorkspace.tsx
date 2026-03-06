import {useCallback, useEffect, useMemo, useRef, useState} from "react";
import {invoke} from "@tauri-apps/api/core";
import "./system-workspace.css";

type HostItem = {
    host_id: string;
    alias: string;
    address: string;
    port: number;
    username: string;
    auth_mode: string;
    proxy_jump: string;
    key_id?: string | null;
};

type InvokeErrorDto = {
    code?: string;
    message?: string;
};

type RemoteProcessItem = {
    pid: number;
    user: string;
    cpu_pct: number;
    mem_pct: number;
    stat: string;
    elapsed: string;
    command: string;
    command_line: string;
};

type RemoteProcessListResponse = {
    sampled_at_ms: number;
    items: RemoteProcessItem[];
};

type RemoteServiceItem = {
    unit: string;
    load_state: string;
    active_state: string;
    sub_state: string;
    description: string;
};

type RemoteServiceListResponse = {
    supported: boolean;
    sampled_at_ms: number;
    message?: string | null;
    items: RemoteServiceItem[];
};

type RemoteActionResponse = {
    ok: boolean;
    message: string;
};

function getInvokeError(error: unknown): { code?: string; message: string } {
    if (typeof error === "string") {
        return {message: error};
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
            return {message: JSON.stringify(error)};
        } catch {
            return {message: "未知错误"};
        }
    }
    return {message: String(error)};
}

function formatInvokeError(error: unknown): string {
    const payload = getInvokeError(error);
    return payload.code ? `[${payload.code}] ${payload.message}` : payload.message;
}

function formatPercent(value: number): string {
    return `${Math.max(0, value).toFixed(1)}%`;
}

export function SystemWorkspace() {
    const [hosts, setHosts] = useState<HostItem[]>([]);
    const [selectedHostId, setSelectedHostId] = useState("");
    const [notice, setNotice] = useState("先选择一个 Host，再拉取进程与服务状态。");
    const [busyKey, setBusyKey] = useState<string | null>(null);
    const [processItems, setProcessItems] = useState<RemoteProcessItem[]>([]);
    const [serviceItems, setServiceItems] = useState<RemoteServiceItem[]>([]);
    const [serviceSupported, setServiceSupported] = useState(true);
    const [serviceNotice, setServiceNotice] = useState("");
    const [processFilter, setProcessFilter] = useState("");
    const [serviceFilter, setServiceFilter] = useState("");
    const [processSampledAt, setProcessSampledAt] = useState<number | null>(null);
    const [serviceSampledAt, setServiceSampledAt] = useState<number | null>(null);
    const passwordCacheRef = useRef<Record<string, string>>({});

    const selectedHost = useMemo(
        () => hosts.find((item) => item.host_id === selectedHostId) ?? null,
        [hosts, selectedHostId],
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

    const callRemoteWithHost = useCallback(
        async <T,>(
            commandName: string,
            host: HostItem,
            buildInput: (password: string | null) => Record<string, unknown>,
        ): Promise<T> => {
            const attempt = async (forcePrompt: boolean): Promise<T> => {
                const password = requestPasswordForHost(host, forcePrompt);
                if (host.auth_mode === "password" && password === null) {
                    throw new Error("PASSWORD_PROMPT_CANCELED");
                }
                return invoke<T>(commandName, buildInput(password));
            };
            try {
                return await attempt(false);
            } catch (error: unknown) {
                if (error instanceof Error && error.message === "PASSWORD_PROMPT_CANCELED") {
                    throw error;
                }
                const payload = getInvokeError(error);
                if (host.auth_mode === "password" && payload.code === "AUTH_FAILED") {
                    delete passwordCacheRef.current[host.host_id];
                    return attempt(true);
                }
                throw error;
            }
        },
        [requestPasswordForHost],
    );

    const loadHosts = useCallback(async () => {
        try {
            const response = await invoke<HostItem[]>("store_hosts_list");
            setHosts(response);
            setSelectedHostId((current) => {
                if (current && response.some((item) => item.host_id === current)) {
                    return current;
                }
                return response[0]?.host_id ?? "";
            });
            if (response.length === 0) {
                setNotice("当前还没有 Host，请先去 Hosts 页面保存一台远端机器。");
            }
        } catch (error: unknown) {
            setNotice(`读取 Host 列表失败：${formatInvokeError(error)}`);
        }
    }, []);

    const refreshProcesses = useCallback(async () => {
        if (!selectedHost) {
            return;
        }
        setBusyKey("process:list");
        try {
            const response = await callRemoteWithHost<RemoteProcessListResponse>(
                "process_list_remote",
                selectedHost,
                (password) => ({
                    input: {
                        hostId: selectedHost.host_id,
                        password,
                        limit: 80,
                    },
                }),
            );
            setProcessItems(response.items);
            setProcessSampledAt(response.sampled_at_ms);
            setNotice(`已刷新 ${selectedHost.alias} 的进程列表。`);
        } catch (error: unknown) {
            if (error instanceof Error && error.message === "PASSWORD_PROMPT_CANCELED") {
                setNotice("已取消进程查询。");
            } else {
                setNotice(`拉取进程列表失败：${formatInvokeError(error)}`);
            }
        } finally {
            setBusyKey((current) => (current === "process:list" ? null : current));
        }
    }, [callRemoteWithHost, selectedHost]);

    const refreshServices = useCallback(async () => {
        if (!selectedHost) {
            return;
        }
        setBusyKey("service:list");
        try {
            const response = await callRemoteWithHost<RemoteServiceListResponse>(
                "service_list_remote",
                selectedHost,
                (password) => ({
                    input: {
                        hostId: selectedHost.host_id,
                        password,
                        limit: 120,
                    },
                }),
            );
            setServiceItems(response.items);
            setServiceSupported(response.supported);
            setServiceNotice(response.message ?? "");
            setServiceSampledAt(response.sampled_at_ms);
            setNotice(
                response.supported
                    ? `已刷新 ${selectedHost.alias} 的服务列表。`
                    : `${selectedHost.alias} 当前不是 systemd 环境。`,
            );
        } catch (error: unknown) {
            if (error instanceof Error && error.message === "PASSWORD_PROMPT_CANCELED") {
                setNotice("已取消服务查询。");
            } else {
                setNotice(`拉取服务列表失败：${formatInvokeError(error)}`);
            }
        } finally {
            setBusyKey((current) => (current === "service:list" ? null : current));
        }
    }, [callRemoteWithHost, selectedHost]);

    const refreshAll = useCallback(async () => {
        await refreshProcesses();
        if (!selectedHost) {
            return;
        }
        if (selectedHost.auth_mode !== "password" || passwordCacheRef.current[selectedHost.host_id]) {
            await refreshServices();
        }
    }, [refreshProcesses, refreshServices, selectedHost]);

    const runProcessSignal = useCallback(
        async (pid: number, signal: "TERM" | "KILL" | "HUP" | "INT") => {
            if (!selectedHost) {
                return;
            }
            if (signal === "KILL" && !window.confirm(`确认对 PID ${pid} 发送 KILL？这可能会立即终止进程。`)) {
                return;
            }
            setBusyKey(`process:${pid}:${signal}`);
            try {
                const response = await callRemoteWithHost<RemoteActionResponse>(
                    "process_signal_remote",
                    selectedHost,
                    (password) => ({
                        input: {
                            hostId: selectedHost.host_id,
                            password,
                            pid,
                            signal,
                        },
                    }),
                );
                setNotice(response.message);
                await refreshProcesses();
            } catch (error: unknown) {
                if (error instanceof Error && error.message === "PASSWORD_PROMPT_CANCELED") {
                    setNotice("已取消进程动作。");
                } else {
                    setNotice(`执行进程动作失败：${formatInvokeError(error)}`);
                }
            } finally {
                setBusyKey((current) => (current === `process:${pid}:${signal}` ? null : current));
            }
        },
        [callRemoteWithHost, refreshProcesses, selectedHost],
    );

    const runServiceAction = useCallback(
        async (unit: string, action: "start" | "stop" | "restart" | "reload") => {
            if (!selectedHost) {
                return;
            }
            if (
                (action === "stop" || action === "restart") &&
                !window.confirm(`确认对 ${unit} 执行 ${action}？`)
            ) {
                return;
            }
            setBusyKey(`service:${unit}:${action}`);
            try {
                const response = await callRemoteWithHost<RemoteActionResponse>(
                    "service_action_remote",
                    selectedHost,
                    (password) => ({
                        input: {
                            hostId: selectedHost.host_id,
                            password,
                            unit,
                            action,
                        },
                    }),
                );
                setNotice(response.message);
                await refreshServices();
            } catch (error: unknown) {
                if (error instanceof Error && error.message === "PASSWORD_PROMPT_CANCELED") {
                    setNotice("已取消服务动作。");
                } else {
                    setNotice(`执行服务动作失败：${formatInvokeError(error)}`);
                }
            } finally {
                setBusyKey((current) => (current === `service:${unit}:${action}` ? null : current));
            }
        },
        [callRemoteWithHost, refreshServices, selectedHost],
    );

    useEffect(() => {
        void loadHosts();
    }, [loadHosts]);

    useEffect(() => {
        if (!selectedHost) {
            setProcessItems([]);
            setServiceItems([]);
            setServiceSupported(true);
            setServiceNotice("");
            return;
        }
        if (selectedHost.proxy_jump.trim()) {
            setProcessItems([]);
            setServiceItems([]);
            setServiceSupported(false);
            setServiceNotice("当前主机配置了 ProxyJump，进程与服务管理暂不支持。");
            setNotice("当前主机配置了 ProxyJump，进程与服务管理请改用直连 Host。");
            return;
        }
        if (selectedHost.auth_mode === "password" && !passwordCacheRef.current[selectedHost.host_id]) {
            setNotice(`已选择 ${selectedHost.alias}，点击“刷新全部”后输入一次性密码即可开始巡检。`);
            return;
        }
        void refreshAll();
    }, [refreshAll, selectedHost]);

    const filteredProcesses = useMemo(() => {
        const keyword = processFilter.trim().toLowerCase();
        if (!keyword) {
            return processItems;
        }
        return processItems.filter((item) =>
            [String(item.pid), item.user, item.command, item.command_line]
                .join(" ")
                .toLowerCase()
                .includes(keyword),
        );
    }, [processFilter, processItems]);

    const filteredServices = useMemo(() => {
        const keyword = serviceFilter.trim().toLowerCase();
        if (!keyword) {
            return serviceItems;
        }
        return serviceItems.filter((item) =>
            [item.unit, item.description, item.active_state, item.sub_state]
                .join(" ")
                .toLowerCase()
                .includes(keyword),
        );
    }, [serviceFilter, serviceItems]);

    return (
        <section className="system-workspace">
            <div className="system-toolbar">
                <div className="system-toolbar-main">
                    <div>
                        <h3>System Ops</h3>
                        <p>面向 Linux 远端主机的进程巡检与 systemctl 服务管理。</p>
                    </div>
                    <div className="system-host-picker">
                        <label>
                            Host
                            <select
                                value={selectedHostId}
                                onChange={(event) => setSelectedHostId(event.currentTarget.value)}
                            >
                                <option value="">选择远端 Host</option>
                                {hosts.map((item) => (
                                    <option key={item.host_id} value={item.host_id}>
                                        {item.alias} · {item.username}@{item.address}:{item.port}
                                    </option>
                                ))}
                            </select>
                        </label>
                        <button type="button" onClick={() => void loadHosts()}>
                            刷新 Host
                        </button>
                        <button
                            type="button"
                            onClick={() => void refreshAll()}
                            disabled={!selectedHost || !!selectedHost.proxy_jump.trim()}
                        >
                            刷新全部
                        </button>
                    </div>
                </div>
                {selectedHost ? (
                    <div className="system-host-summary">
                        <span>{selectedHost.username}@{selectedHost.address}:{selectedHost.port}</span>
                        <span>认证：{selectedHost.auth_mode}</span>
                        {selectedHost.key_id ? <span>密钥：{selectedHost.key_id.slice(0, 8)}</span> : null}
                        {selectedHost.proxy_jump ? <span>ProxyJump：{selectedHost.proxy_jump}</span> : <span>直连主机</span>}
                    </div>
                ) : null}
            </div>

            <div className="system-notice">{notice}</div>

            {!selectedHost ? (
                <div className="system-empty-state">
                    <strong>还没有选中 Host</strong>
                    <p>请先到 Hosts 页面保存远端主机，然后回来选择目标机器。</p>
                </div>
            ) : selectedHost.proxy_jump ? (
                <div className="system-empty-state warning">
                    <strong>当前不支持 ProxyJump 主机</strong>
                    <p>里程碑 7 先支持直连主机的进程与 systemctl 管理，跳板机场景后续再补。</p>
                </div>
            ) : (
                <div className="system-grid">
                    <section className="system-panel">
                        <div className="system-panel-header">
                            <div>
                                <h4>进程列表</h4>
                                <p>
                                    最近刷新：
                                    {processSampledAt ? new Date(processSampledAt).toLocaleTimeString() : "-"}
                                </p>
                            </div>
                            <div className="system-panel-actions">
                                <input
                                    value={processFilter}
                                    onChange={(event) => setProcessFilter(event.currentTarget.value)}
                                    placeholder="按 PID / 用户 / 命令过滤"
                                />
                                <button type="button" onClick={() => void refreshProcesses()}>
                                    {busyKey === "process:list" ? "刷新中..." : "刷新进程"}
                                </button>
                            </div>
                        </div>
                        <div className="system-table-wrap">
                            <table className="system-table">
                                <thead>
                                <tr>
                                    <th>PID</th>
                                    <th>用户</th>
                                    <th>CPU</th>
                                    <th>MEM</th>
                                    <th>状态</th>
                                    <th>运行时长</th>
                                    <th>命令</th>
                                    <th>动作</th>
                                </tr>
                                </thead>
                                <tbody>
                                {filteredProcesses.map((item) => (
                                    <tr key={`${item.pid}-${item.command_line}`}>
                                        <td>{item.pid}</td>
                                        <td>{item.user}</td>
                                        <td>{formatPercent(item.cpu_pct)}</td>
                                        <td>{formatPercent(item.mem_pct)}</td>
                                        <td>{item.stat}</td>
                                        <td>{item.elapsed}</td>
                                        <td>
                                            <div className="system-command-cell">
                                                <strong>{item.command}</strong>
                                                <span>{item.command_line}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <div className="system-inline-actions">
                                                <button
                                                    type="button"
                                                    onClick={() => void runProcessSignal(item.pid, "TERM")}
                                                    disabled={busyKey === `process:${item.pid}:TERM`}
                                                >
                                                    TERM
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={() => void runProcessSignal(item.pid, "KILL")}
                                                    disabled={busyKey === `process:${item.pid}:KILL`}
                                                >
                                                    KILL
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                                {filteredProcesses.length === 0 ? (
                                    <tr>
                                        <td colSpan={8} className="system-empty-row">
                                            暂无进程数据
                                        </td>
                                    </tr>
                                ) : null}
                                </tbody>
                            </table>
                        </div>
                    </section>

                    <section className="system-panel">
                        <div className="system-panel-header">
                            <div>
                                <h4>systemctl 服务</h4>
                                <p>
                                    最近刷新：
                                    {serviceSampledAt ? new Date(serviceSampledAt).toLocaleTimeString() : "-"}
                                </p>
                            </div>
                            <div className="system-panel-actions">
                                <input
                                    value={serviceFilter}
                                    onChange={(event) => setServiceFilter(event.currentTarget.value)}
                                    placeholder="按服务名 / 描述过滤"
                                />
                                <button type="button" onClick={() => void refreshServices()}>
                                    {busyKey === "service:list" ? "刷新中..." : "刷新服务"}
                                </button>
                            </div>
                        </div>
                        {!serviceSupported ? <div className="system-warning-banner">{serviceNotice}</div> : null}
                        <div className="system-table-wrap">
                            <table className="system-table">
                                <thead>
                                <tr>
                                    <th>服务</th>
                                    <th>Load</th>
                                    <th>Active</th>
                                    <th>Sub</th>
                                    <th>描述</th>
                                    <th>动作</th>
                                </tr>
                                </thead>
                                <tbody>
                                {filteredServices.map((item) => (
                                    <tr key={item.unit}>
                                        <td>{item.unit}</td>
                                        <td>{item.load_state}</td>
                                        <td>{item.active_state}</td>
                                        <td>{item.sub_state}</td>
                                        <td>{item.description}</td>
                                        <td>
                                            <div className="system-inline-actions">
                                                <button
                                                    type="button"
                                                    onClick={() => void runServiceAction(item.unit, "start")}
                                                    disabled={!serviceSupported || busyKey === `service:${item.unit}:start`}
                                                >
                                                    Start
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={() => void runServiceAction(item.unit, "stop")}
                                                    disabled={!serviceSupported || busyKey === `service:${item.unit}:stop`}
                                                >
                                                    Stop
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={() => void runServiceAction(item.unit, "restart")}
                                                    disabled={!serviceSupported || busyKey === `service:${item.unit}:restart`}
                                                >
                                                    Restart
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={() => void runServiceAction(item.unit, "reload")}
                                                    disabled={!serviceSupported || busyKey === `service:${item.unit}:reload`}
                                                >
                                                    Reload
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                                {filteredServices.length === 0 ? (
                                    <tr>
                                        <td colSpan={6} className="system-empty-row">
                                            {serviceSupported ? "暂无服务数据" : "当前主机不支持 systemctl"}
                                        </td>
                                    </tr>
                                ) : null}
                                </tbody>
                            </table>
                        </div>
                    </section>
                </div>
            )}
        </section>
    );
}
