export type NavItem = {
  path: string;
  label: string;
  description: string;
};

export const NAV_ITEMS: NavItem[] = [
  { path: "/hosts", label: "Hosts", description: "会话树与连接入口" },
  { path: "/keychain", label: "Keychain", description: "密钥与口令管理" },
  { path: "/port-forwarding", label: "Port Forwarding", description: "L/R/D 转发管理" },
  { path: "/snippets", label: "Snippets", description: "快速发送与模板" },
  { path: "/known-hosts", label: "Known Hosts", description: "主机指纹与信任策略" },
  { path: "/logs", label: "Logs", description: "连接与操作日志" },
  { path: "/settings", label: "Settings", description: "下载目录与行为配置" },
];
