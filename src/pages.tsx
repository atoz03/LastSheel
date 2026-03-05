import { HostsWorkspace } from "./features/terminal/HostsWorkspace";

type FeaturePageProps = {
  title: string;
  summary: string;
  bullets: string[];
};

function FeaturePage({ title, summary, bullets }: FeaturePageProps) {
  return (
    <section className="feature-page">
      <h3>{title}</h3>
      <p>{summary}</p>
      <ul>
        {bullets.map((bullet) => (
          <li key={bullet}>{bullet}</li>
        ))}
      </ul>
    </section>
  );
}

export function HostsPage() {
  return <HostsWorkspace />;
}

export function KeychainPage() {
  return (
    <FeaturePage
      title="Keychain"
      summary="本地加密管理私钥、密码与口令，支持密钥生成与部署。"
      bullets={[
        "支持导入私钥（含 passphrase）",
        "支持生成 Ed25519 并复制公钥",
        "支持一键部署公钥到 authorized_keys",
      ]}
    />
  );
}

export function PortForwardingPage() {
  return (
    <FeaturePage
      title="Port Forwarding"
      summary="统一管理 -L/-R/-D 生命周期，并显示风险状态。"
      bullets={[
        "默认仅监听 127.0.0.1",
        "切换到 0.0.0.0 时必须二次确认",
        "断线自动清理并提示具体错误原因",
      ]}
    />
  );
}

export function SnippetsPage() {
  return (
    <FeaturePage
      title="Snippets"
      summary="支持全局与会话级模板，快捷发送并可选自动回车。"
      bullets={[
        "模板变量：${HOST} ${USER} ${PORT} ${SESSION_NAME}",
        "支持参数化片段与会话日志审计",
        "支持从历史命令一键收藏",
      ]}
    />
  );
}

export function KnownHostsPage() {
  return (
    <FeaturePage
      title="Known Hosts"
      summary="严格主机指纹校验，未知主机需确认，变更强制阻断。"
      bullets={[
        "首次连接必须确认指纹",
        "指纹变化返回 HOSTKEY_CHANGED",
        "信任记录仅写应用内数据库",
      ]}
    />
  );
}

export function LogsPage() {
  return (
    <FeaturePage
      title="Logs"
      summary="记录关键操作与错误码，帮助定位问题并支持导出。"
      bullets={[
        "统一错误结构：{ code, message, detail? }",
        "禁止记录敏感信息到日志",
        "支持会话维度过滤和关键字检索",
      ]}
    />
  );
}

export function SettingsPage() {
  return (
    <FeaturePage
      title="Settings"
      summary="管理下载目录、并发度、历史行为与界面布局。"
      bullets={[
        "默认下载目录为系统 Downloads/LastSheel/<host>",
        "上传/下载并发默认 4，可配置",
        "历史命令默认仅内存 ring buffer，不落盘",
      ]}
    />
  );
}
