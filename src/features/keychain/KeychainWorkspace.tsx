import type { FormEvent } from "react";
import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./keychain-workspace.css";

type VaultStatus = {
  initialized: boolean;
  unlocked: boolean;
};

type KeyMetadata = {
  key_id: string;
  name: string;
  has_passphrase: boolean;
  created_at_ms: number;
};

function formatTimestamp(timestamp: number): string {
  return new Date(timestamp).toLocaleString();
}

export function KeychainWorkspace() {
  const [status, setStatus] = useState<VaultStatus>({ initialized: false, unlocked: false });
  const [masterPassword, setMasterPassword] = useState("");
  const [keyName, setKeyName] = useState("");
  const [privateKeyText, setPrivateKeyText] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [items, setItems] = useState<KeyMetadata[]>([]);
  const [notice, setNotice] = useState("请先使用主密码解锁保险箱。");

  const refreshStatus = useCallback(async () => {
    try {
      const response = await invoke<VaultStatus>("vault_status");
      setStatus(response);
      if (response.unlocked) {
        const keys = await invoke<KeyMetadata[]>("key_list");
        setItems(keys);
      } else {
        setItems([]);
      }
    } catch {
      setNotice("Vault 命令暂不可用，请通过 `pnpm tauri dev` 启动。");
    }
  }, []);

  const unlockVault = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!masterPassword.trim()) {
        setNotice("主密码不能为空。");
        return;
      }
      try {
        const response = await invoke<VaultStatus>("vault_unlock", {
          masterPassword,
        });
        setStatus(response);
        setMasterPassword("");
        const keys = await invoke<KeyMetadata[]>("key_list");
        setItems(keys);
        setNotice(response.initialized ? "保险箱已解锁。" : "保险箱初始化成功并已解锁。");
      } catch (error: unknown) {
        setNotice(`解锁失败：${String(error)}`);
      }
    },
    [masterPassword],
  );

  const lockVault = useCallback(async () => {
    try {
      const response = await invoke<VaultStatus>("vault_lock");
      setStatus(response);
      setItems([]);
      setNotice("保险箱已锁定。");
    } catch (error: unknown) {
      setNotice(`锁定失败：${String(error)}`);
    }
  }, []);

  const importPrivateKey = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!status.unlocked) {
        setNotice("请先解锁保险箱。");
        return;
      }
      try {
        await invoke("key_import_private_key", {
          name: keyName,
          pemText: privateKeyText,
          passphrase: passphrase || null,
        });
        const keys = await invoke<KeyMetadata[]>("key_list");
        setItems(keys);
        setKeyName("");
        setPrivateKeyText("");
        setPassphrase("");
        setNotice("私钥已导入保险箱。");
      } catch (error: unknown) {
        setNotice(`导入失败：${String(error)}`);
      }
    },
    [keyName, passphrase, privateKeyText, status.unlocked],
  );

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  return (
    <section className="keychain-workspace">
      <header className="keychain-header">
        <div>
          <h3>Keychain / Vault</h3>
          <p>{notice}</p>
        </div>
        <div className="vault-badge">
          状态：{status.unlocked ? "已解锁" : status.initialized ? "已初始化（已锁定）" : "未初始化"}
        </div>
      </header>

      <div className="keychain-grid">
        <section className="card">
          <h4>主密码</h4>
          <form onSubmit={(event) => void unlockVault(event)}>
            <input
              type="password"
              value={masterPassword}
              onChange={(event) => setMasterPassword(event.currentTarget.value)}
              placeholder="输入主密码并解锁"
            />
            <div className="action-row">
              <button type="submit">解锁 / 初始化</button>
              <button type="button" onClick={() => void lockVault()}>
                锁定
              </button>
              <button type="button" onClick={() => void refreshStatus()}>
                刷新
              </button>
            </div>
          </form>
        </section>

        <section className="card">
          <h4>导入私钥（V1 不生成）</h4>
          <form onSubmit={(event) => void importPrivateKey(event)}>
            <input
              value={keyName}
              onChange={(event) => setKeyName(event.currentTarget.value)}
              placeholder="密钥名称"
              required
            />
            <textarea
              value={privateKeyText}
              onChange={(event) => setPrivateKeyText(event.currentTarget.value)}
              placeholder="粘贴 PEM 私钥内容"
              required
            />
            <input
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.currentTarget.value)}
              placeholder="可选：私钥口令"
            />
            <button type="submit">导入到 Vault</button>
          </form>
        </section>
      </div>

      <section className="card">
        <h4>已导入密钥</h4>
        <ul className="key-list">
          {items.map((item) => (
            <li key={item.key_id}>
              <div>
                <strong>{item.name}</strong>
                <span>ID: {item.key_id.slice(0, 8)}</span>
              </div>
              <div>
                <span>{item.has_passphrase ? "有口令" : "无口令"}</span>
                <span>{formatTimestamp(item.created_at_ms)}</span>
              </div>
            </li>
          ))}
          {items.length === 0 ? <li className="empty">暂无私钥</li> : null}
        </ul>
      </section>
    </section>
  );
}
