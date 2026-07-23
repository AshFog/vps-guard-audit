#!/usr/bin/env bash
# shellcheck shell=bash
# v6 加固动作注册表。动作编号、风险分组和检查映射属于稳定接口。

hardening_registry_visit() {
  register_hardening_action "HARD-1001" "regular" "修复账户文件权限" \
    "保护 passwd、shadow、group 和 gshadow，防止未授权读取或修改。" \
    "low" "perm./etc/passwd,perm./etc/shadow,perm./etc/group,perm./etc/gshadow" \
    "/etc/passwd /etc/shadow /etc/group /etc/gshadow" "yes" "HARD-1001"
  register_hardening_action "HARD-1002" "regular" "修复 SSH 密钥权限" \
    "收紧主机私钥和 authorized_keys 权限，不改变登录认证方式。" \
    "low" "keys.*.mode,keys.host_private" \
    "~/.ssh/authorized_keys /etc/ssh/ssh_host_*_key" "yes" "HARD-1002"
  register_hardening_action "HARD-1003" "regular" "修复 sudoers 权限" \
    "先通过 visudo 验证，再修复 sudoers 及其片段的所有者和权限。" \
    "low" "sudo.mode" "/etc/sudoers /etc/sudoers.d/*" "yes" "HARD-1003"
  register_hardening_action "HARD-1004" "regular" "修复计划任务权限" \
    "保护系统 crontab 和 cron.d 配置，避免普通用户植入定时任务。" \
    "low" "cron.mode" "/etc/crontab /etc/cron.d/*" "yes" "HARD-1004"
  register_hardening_action "HARD-1005" "regular" "禁止 SSH 空密码登录" \
    "明确设置 PermitEmptyPasswords no；不会关闭正常的密码或密钥登录。" \
    "low" "ssh.empty" "/etc/ssh/sshd_config.d/90-vpsga-hardening.conf" "yes" "HARD-1005"
  register_hardening_action "HARD-1006" "regular" "限制 SSH 认证尝试次数" \
    "把单次连接允许的认证尝试限制在合理范围，降低暴力猜测效率。" \
    "low" "ssh.tries" "/etc/ssh/sshd_config.d/90-vpsga-hardening.conf" "yes" "HARD-1006"
  register_hardening_action "HARD-1007" "regular" "关闭 SSH X11 转发" \
    "普通 VPS 通常不需要远程图形转发；正在使用 X11 的主机不应选择。" \
    "low" "ssh.x11" "/etc/ssh/sshd_config.d/90-vpsga-hardening.conf" "yes" "HARD-1007"
  register_hardening_action "HARD-1008" "regular" "启用自动安全更新" \
    "安装并配置 unattended-upgrades，只自动应用安全更新。" \
    "low" "pkg.unattended" "/etc/apt/apt.conf.d/20auto-upgrades" "planned" "HARD-1008"
  register_hardening_action "HARD-1009" "regular" "应用兼容性高的内核与网络参数" \
    "处理地址随机化、链接保护、源路由和重定向等通用参数，不改 IP 转发或禁用 IPv6。" \
    "low" "sysctl.kernel.randomize_va_space,sysctl.kernel.kptr_restrict,sysctl.kernel.yama.ptrace_scope,sysctl.fs.protected_hardlinks,sysctl.fs.protected_symlinks,sysctl.net.ipv4.tcp_syncookies,sysctl.net.ipv4.conf.*.accept_redirects,sysctl.net.ipv4.conf.*.send_redirects,sysctl.net.ipv4.conf.*.accept_source_route,sysctl.net.ipv4.icmp_echo_ignore_broadcasts,sysctl.net.ipv4.conf.all.log_martians,sysctl.net.ipv6.conf.*.accept_redirects" \
    "/etc/sysctl.d/90-vpsga-hardening.conf" "planned" "HARD-1009"
  register_hardening_action "HARD-1010" "regular" "限制 Core Dump" \
    "限制服务和普通进程生成包含内存敏感信息的核心转储。" \
    "low" "coredump.enabled,coredump.unlimited" \
    "/etc/security/limits.d/90-vpsga-hardening.conf /etc/systemd/coredump.conf.d/90-vpsga.conf" "planned" "HARD-1010"

  register_hardening_action "HARD-2001" "sensitive" "禁止 root 直接通过 SSH 登录" \
    "没有已验证的 sudo 管理用户时，执行后可能无法再次登录。" \
    "critical" "ssh.root" "/etc/ssh/sshd_config.d/90-vpsga-hardening.conf" "planned" "HARD-2001"
  register_hardening_action "HARD-2002" "sensitive" "禁止 SSH 密码登录" \
    "密钥未实际验证或客户端丢失私钥时，执行后会失去 SSH 登录能力。" \
    "critical" "ssh.password" "/etc/ssh/sshd_config.d/90-vpsga-hardening.conf" "planned" "HARD-2002"
  register_hardening_action "HARD-2003" "sensitive" "启用 UFW 防火墙" \
    "必须先识别并放行当前 SSH、网站、面板、代理及容器所需端口。" \
    "critical" "fw.none,fw.ufw.absent" "/etc/ufw/*" "planned" "HARD-2003"
  register_hardening_action "HARD-2004" "sensitive" "清理或收紧防火墙规则" \
    "过时规则也可能仍被业务依赖，删除前必须逐条确认端口用途。" \
    "high" "fw.ufw.stale,fw.pre_ufw_accept" "/etc/ufw/*" "planned" "HARD-2004"
  register_hardening_action "HARD-2005" "sensitive" "启用 Fail2ban SSH 防护" \
    "来源 IP 不稳定或白名单错误时，管理员可能被临时封禁。" \
    "high" "f2b.absent,f2b.active,f2b.sshd_jail" "/etc/fail2ban/jail.d/vpsga-sshd.local" "planned" "HARD-2005"
  register_hardening_action "HARD-2006" "sensitive" "关闭 SSH 端口转发" \
    "会中断 SSH 隧道、开发工具、代理转发和部分远程管理工作流。" \
    "high" "ssh.forward" "/etc/ssh/sshd_config.d/90-vpsga-hardening.conf" "planned" "HARD-2006"
  register_hardening_action "HARD-2007" "sensitive" "调整 IP 转发或 IPv6" \
    "可能破坏 Docker、VPN、代理、软路由和双栈网络，不能套用统一值。" \
    "critical" "sysctl.ip_forward,sysctl.ipv6_forward,sysctl.ipv6" \
    "/etc/sysctl.d/90-vpsga-hardening.conf" "planned" "HARD-2007"
  register_hardening_action "HARD-2008" "sensitive" "停用确认不需要的服务" \
    "服务名称相同不代表用途相同，判断错误会直接中断现有业务。" \
    "critical" "service.unneeded,port.cups.*,port.avahi" "systemd unit" "planned" "HARD-2008"
}
