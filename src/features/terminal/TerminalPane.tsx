import { useEffect, useRef } from "react";
import { FitAddon } from "@xterm/addon-fit";
import { WebglAddon } from "@xterm/addon-webgl";
import { Terminal } from "xterm";
import "xterm/css/xterm.css";

type TerminalPaneProps = {
  terminalId: string;
  chunks: string[];
  onInput: (terminalId: string, data: string) => void;
  onResize: (terminalId: string, cols: number, rows: number) => void;
};

export function TerminalPane({ terminalId, chunks, onInput, onResize }: TerminalPaneProps) {
  const hostRef = useRef<HTMLDivElement | null>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const renderedChunksRef = useRef<number>(0);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) {
      return;
    }

    const terminal = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: "Menlo, Monaco, 'Courier New', monospace",
      theme: {
        background: "#0b1222",
        foreground: "#d6e2ff",
      },
      convertEol: true,
      allowProposedApi: true,
      scrollback: 5000,
    });
    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);

    try {
      terminal.loadAddon(new WebglAddon());
    } catch {
      terminal.writeln("⚠️ WebGL 加速不可用，已自动降级到 Canvas。");
    }

    terminal.open(host);
    fitAddon.fit();
    onResize(terminalId, terminal.cols, terminal.rows);

    const disposer = terminal.onData((data) => {
      onInput(terminalId, data);
    });

    const resizeObserver = new ResizeObserver(() => {
      fitAddon.fit();
      onResize(terminalId, terminal.cols, terminal.rows);
    });
    resizeObserver.observe(host);

    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;
    renderedChunksRef.current = 0;

    return () => {
      resizeObserver.disconnect();
      disposer.dispose();
      terminal.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, [onInput, onResize, terminalId]);

  useEffect(() => {
    const terminal = terminalRef.current;
    if (!terminal) {
      return;
    }

    const start = renderedChunksRef.current;
    for (let index = start; index < chunks.length; index += 1) {
      terminal.write(chunks[index]);
    }
    renderedChunksRef.current = chunks.length;
  }, [chunks]);

  return <div ref={hostRef} className="terminal-pane" />;
}
