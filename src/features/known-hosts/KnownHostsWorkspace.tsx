import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./known-hosts-workspace.css";

type KnownHostItem = {
  host_id: string;
  address: string;
  port: number;
  algorithm: string;
  fingerprint_sha256: string;
  trusted_at_ms: number;
};

function formatTime(value: number): string {
  return new Date(value).toLocaleString();
}

export function KnownHostsWorkspace() {
  const [items, setItems] = useState<KnownHostItem[]>([]);
  const [notice, setNotice] = useState("展示应用内 known_hosts 信任记录。");

  const refresh = useCallback(async () => {
    try {
      const response = await invoke<KnownHostItem[]>("known_hosts_list");
      setItems(response);
      setNotice(`已加载 ${response.length} 条记录。`);
    } catch (error: unknown) {
      setNotice(`加载失败：${String(error)}`);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return (
    <section className="known-hosts-workspace">
      <header>
        <h3>Known Hosts</h3>
        <p>{notice}</p>
        <button type="button" onClick={() => void refresh()}>
          刷新
        </button>
      </header>
      <ul>
        {items.map((item) => (
          <li key={`${item.address}:${item.port}`}>
            <div>
              <strong>
                {item.address}:{item.port}
              </strong>
              <span>算法：{item.algorithm}</span>
            </div>
            <div>
              <span>{item.fingerprint_sha256}</span>
              <span>信任时间：{formatTime(item.trusted_at_ms)}</span>
            </div>
          </li>
        ))}
        {items.length === 0 ? <li className="empty">暂无可信主机</li> : null}
      </ul>
    </section>
  );
}
