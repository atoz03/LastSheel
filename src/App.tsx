import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { HashRouter, Navigate, NavLink, Route, Routes } from "react-router-dom";
import { NAV_ITEMS } from "./navigation";
import {
  HostsPage,
  KeychainPage,
  LogsPage,
  KnownHostsPage,
  PortForwardingPage,
  SettingsPage,
  SnippetsPage,
} from "./pages";
import "./App.css";

type BootstrapInfo = {
  product_name: string;
  version: string;
  active_milestone: string;
  default_download_dir: string;
  features: string[];
};

function App() {
  const [bootstrap, setBootstrap] = useState<BootstrapInfo | null>(null);
  const [errorMessage, setErrorMessage] = useState<string>("");

  useEffect(() => {
    invoke<BootstrapInfo>("app_get_bootstrap")
      .then((res) => {
        setBootstrap(res);
        setErrorMessage("");
      })
      .catch((error: unknown) => {
        setErrorMessage(`初始化失败：${String(error)}`);
      });
  }, []);

  return (
    <HashRouter>
      <div className="app-shell">
        <aside className="global-nav">
          <h1 className="brand-title">LastSheel</h1>
          <p className="brand-subtitle">V1 开发骨架</p>
          <nav className="nav-list">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.path}
                className={({ isActive }) =>
                  isActive ? "nav-link nav-link-active" : "nav-link"
                }
                to={item.path}
              >
                <span className="nav-label">{item.label}</span>
                <span className="nav-description">{item.description}</span>
              </NavLink>
            ))}
          </nav>
        </aside>
        <main className="content">
          <header className="content-header">
            <section>
              <h2>{bootstrap?.active_milestone ?? "正在初始化..."}</h2>
              <p>下载目录：{bootstrap?.default_download_dir ?? "-"}</p>
            </section>
            <section className="build-meta">
              <span>版本：{bootstrap?.version ?? "0.1.0"}</span>
              <span>产品：{bootstrap?.product_name ?? "LastSheel"}</span>
            </section>
          </header>
          {errorMessage ? <p className="error-banner">{errorMessage}</p> : null}
          <Routes>
            <Route path="/" element={<Navigate replace to="/hosts" />} />
            <Route path="/hosts" element={<HostsPage />} />
            <Route path="/keychain" element={<KeychainPage />} />
            <Route path="/port-forwarding" element={<PortForwardingPage />} />
            <Route path="/snippets" element={<SnippetsPage />} />
            <Route path="/known-hosts" element={<KnownHostsPage />} />
            <Route path="/logs" element={<LogsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
      </div>
    </HashRouter>
  );
}

export default App;
