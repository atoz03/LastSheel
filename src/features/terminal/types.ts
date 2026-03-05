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
};

export type TerminalTabKind = "local" | "ssh";

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
