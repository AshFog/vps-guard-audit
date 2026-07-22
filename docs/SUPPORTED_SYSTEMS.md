# 支持系统与验证范围

VPS Guard Audit v5.0.0 面向采用 `apt`、OpenSSH 和常见 Linux 网络工具的 Ubuntu / Debian 主机。

## 已验证版本

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

## 主要场景

- 通用 VPS
- 网站服务器
- Docker 主机
- 代理服务器
- 家庭服务器
- 桌面 Linux

## 边界

其他 Ubuntu / Debian 版本可能可以运行，但会被标记为未验证。其他 Linux 发行版、BSD 和商业 UNIX 不在当前支持范围内。

容器中运行时，宿主机的 systemd、防火墙、内核、AppArmor 和网络状态可能不可见。工具会将这些结果标记为不适用或无法确认，而不会写成确定结论。

系统命令的原始输出可能仍是英文，这是为了保留证据原貌和脚本兼容性。
