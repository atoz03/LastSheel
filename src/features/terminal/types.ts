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
};
