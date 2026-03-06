export type TerminalStatus = "connecting" | "ready" | "closed" | "error";

export type TerminalOutputPayload = {
    terminal_id: string;
    chunk_b64: string;
};

export type TerminalStatusPayload = {
    terminal_id: string;
    state: TerminalStatus;
    message?: string | null;
};

export type TerminalSessionResponse = {
    terminal_id: string;
    connection_id?: string | null;
};

export type TerminalTabKind = "local" | "ssh";

export type MonitorProfile = "basic" | "disk" | "path_probe";

export type MonitorBasicPayload = {
    cpu_total_pct: number;
    load1: number;
    load5: number;
    load15: number;
    mem_total_kb: number;
    mem_used_kb: number;
    mem_cached_kb: number;
    swap_total_kb: number;
    swap_used_kb: number;
    uptime_s: number;
    net: Array<{
        ifname: string;
        rx_bytes_per_s: number;
        tx_bytes_per_s: number;
        rx_total_bytes: number;
        tx_total_bytes: number;
    }>;
};

export type MonitorDiskPayload = {
    mounts: Array<{
        device: string;
        fstype: string;
        mount: string;
        total_bytes: number;
        used_bytes: number;
        avail_bytes: number;
        used_pct: number;
    }>;
};

export type MonitorPathProbePayload = {
    paths: Array<{
        path: string;
        exists: boolean;
        readable: boolean;
        writable: boolean;
        mount?: string | null;
        avail_bytes: number;
        total_bytes: number;
        dir_size_bytes?: number | null;
    }>;
};

export type MonitorUpdatePayload = {
    connection_id: string;
    ts_ms: number;
    kind: MonitorProfile;
    payload_json: string;
};

export type MonitorSubscribeResponse = {
    subscription_id: string;
};

export type TerminalPaneModel = {
    pane_id: string;
    terminal_id: string;
    status: TerminalStatus;
    message?: string;
};

export type TerminalTabModel = {
    tab_id: string;
    title: string;
    panes: TerminalPaneModel[];
    active_pane_id: string;
    tab_kind: TerminalTabKind;
    host_id?: string;
    host_alias?: string;
    connection_id?: string;
};

export type RemoteFileEntryType = "file" | "dir" | "symlink" | "unknown";

export type RemoteFileEntry = {
    name: string;
    path: string;
    entry_type: RemoteFileEntryType;
    size_bytes: number;
    mtime_ms: number;
    mode_octal: string;
    uid: number;
    gid: number;
};

export type RemoteFileListResponse = {
    cwd: string;
    entries: RemoteFileEntry[];
};

export type RemoteDeleteResponse = {
    deleted_count: number;
};

export type RemoteReadTextResponse = {
    path: string;
    text: string;
    encoding: string;
    mtime_ms: number;
};

export type RemoteWriteTextResponse = {
    new_mtime_ms: number;
};

export type ArchiveFormat = "tar_gz" | "tar" | "tar_bz2" | "tar_xz" | "zip";

export type ArchiveExtractStrategy = "same_dir" | "new_dir" | "custom";

export const ARCHIVE_FORMAT_OPTIONS: readonly ArchiveFormat[] = ["tar_gz", "tar", "tar_bz2", "tar_xz", "zip"];

export type TransferState = "queued" | "running" | "done" | "error" | "canceled";

export type TransferUpdatePayload = {
    transfer_id: string;
    state: TransferState;
    done_bytes: number;
    total_bytes?: number | null;
    message?: string | null;
};

export type TransferStartResponse = {
    transfer_id: string;
    resolved_local_path?: string | null;
    resolved_remote_path?: string | null;
};

export type TransferVerifyResponse = {
    ok: boolean;
    sha256?: string | null;
};

export type TransferVerifyState = "running" | "done" | "error";

export type TransferVerifyPayload = {
    transfer_id: string;
    state: TransferVerifyState;
    sha256?: string | null;
    message?: string | null;
};
