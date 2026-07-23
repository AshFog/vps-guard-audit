# 支持系统与验证范围

VPS Guard Audit v6.0.0-dev.9 面向采用 `apt`、OpenSSH、systemd 和常见 Linux 网络工具的 Ubuntu / Debian 主机。

## 支持与发行验收矩阵

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

上述版本均进入自动化发行验收矩阵，覆盖18项隔离加固动作、全新安装、真实 v5.0.0 升级、安装完整性和升级后只读审计。自动化矩阵使用一次性发行版容器，因此它能验证用户空间兼容性，但不能证明 VPS 厂商控制台、真实 SSH 重连、宿主机内核、防火墙或 systemd timer 的行为。

v6 正式发布前，还必须按照 [v6 发布验收清单](RELEASE_ACCEPTANCE_V6.md) 在全新 Ubuntu 与 Debian 虚拟机上完成真实连接验收。只有自动化矩阵和人工 VM 验收都通过，才应把候选版本标记为稳定版。

## 主要场景

- 通用 VPS
- 网站服务器
- Docker 主机
- 代理服务器
- 家庭服务器
- 桌面 Linux

## 边界

其他 Ubuntu / Debian 版本可能可以运行，但会被标记为未验证。其他 Linux 发行版、BSD 和商业 UNIX 不在当前支持范围内。

容器中运行时，宿主机的 systemd、防火墙、内核、AppArmor 和网络状态可能不可见。工具会将这些结果标记为不适用或无法确认，而不会写成确定结论。容器中的加固测试使用隔离根目录和伪系统命令，不会修改 CI 宿主机。

系统命令的原始输出可能仍是英文，这是为了保留证据原貌和脚本兼容性。
