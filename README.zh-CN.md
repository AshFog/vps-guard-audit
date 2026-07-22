# VPS Guard Audit

[English](README.md) | **简体中文**

VPS Guard Audit 是一款双语、默认只读的 Ubuntu 与 Debian 安全审计工具。它不会自动修改 SSH、防火墙、用户、服务或系统配置。报告会用自然语言解释检测结果，并生成一个经过更强脱敏、适合提交给可信 AI 助手分析的副本。

## 支持的系统

已经验证：

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

脚本会自动识别 `vps`、`server`、`desktop` 和 `container`。其他 Ubuntu 或 Debian 版本可能也能运行，但报告会提示它们不在已验证范围内。

## 快速开始

### 第一次使用：安装并立即检测

复制这一条命令：

```bash
curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash
```

它会自动完成：

1. 显示中文 / English 语言选择菜单；
2. 下载完整项目；
3. 将 VPS Guard Audit 安装或更新到 `/usr/local/lib/vps-guard-audit`；
4. 创建全局命令 `/usr/local/bin/vpsga`；
5. 检查安装是否完整；
6. 立即开始安全检测；
7. 把报告保存到执行一键命令时所在的目录。

### 以后每次运行

无论当前位于哪个目录，只输入：

```bash
vpsga
```

普通用户执行时会自动请求 sudo 密码。输出目录属于当前用户时，生成的报告会交还给当前用户，不会只能由 root 读取。

不要在任意目录执行：

```bash
sudo ./vps-guard-audit.sh
```

`./` 的意思是“在当前目录寻找这个文件”。只有已经克隆仓库并进入项目目录时，这种写法才有效。安装完成后的正常使用方式始终是 `vpsga`。

## 检查安装状态

```bash
command -v vpsga
vpsga --version
vpsga doctor
```

正常的命令位置是：

```text
/usr/local/bin/vpsga
```

如果找不到 `vpsga`，或者 `vpsga doctor` 提示 `current` 路径异常，重新运行一次一键安装命令。新版安装器会自动迁移早期开发版本留下的错误目录结构。

## 更新与卸载

```bash
vpsga update
vpsga uninstall
```

`vpsga update` 会下载当前仓库版本，先检查待安装文件，再安装并执行安装后健康检查。

`vpsga uninstall` 会要求明确确认，并询问是否保留历史检测数据。

## 报告文件

普通检测会生成三个具有相同时间戳的文件：

```text
vpsga-20260722-153045-full.txt
vpsga-20260722-153045-ai.txt
vpsga-20260722-153045.json
```

### 完整 TXT 报告

`*-full.txt` 包含完整技术信息、自然语言总结、风险说明、操作提醒、与上一次检测的比较，以及用于向 AI 请求修复方案的提问模板。

### AI 脱敏报告

`*-ai.txt` 会额外替换或隐藏部分：

- 主机名和完整主机名；
- 非 root 用户名；
- Docker 容器名称；
- 检测到的网站域名；
- IPv4 地址；
- 邮箱和 MAC 地址；
- SSH 密钥指纹。

自动脱敏无法保证覆盖所有自定义名称和凭据，提交给 AI 前仍要亲自检查。不要提交密码、私钥、API Key、访问令牌、Cookie 或其他凭据。

### JSON 报告

JSON 文件保存结构化检测结果，可用于历史比较、自动化和后续功能集成。

## 历史比较

默认会把精简状态保存在：

```text
/var/lib/vps-guard-audit/history/
```

从第二次运行开始，报告可以显示：

- 新增的警告或错误；
- 已经解决的问题；
- 严重程度发生变化的项目。

只保留最近 30 次状态文件。

单次关闭历史记录：

```bash
vpsga --no-history
```

## 常用命令

```bash
vpsga
vpsga --lang zh
vpsga --output-dir /home/user/audit-reports
vpsga --rootkit-check
vpsga --no-history
vpsga --version
vpsga --help
vpsga doctor
vpsga update
vpsga uninstall
```

## 参数

```text
--lang zh|en
--output-dir DIR
--format text|json|both
--config FILE
--login-lines N
--no-update-check
--refresh-package-index
--profile auto|vps|server|desktop|container
--policy baseline|strict
--full-identifiers
--rootkit-check
--no-history
--quiet
-h, --help
-v, --version
```

### 基线策略和严格策略

默认使用 `baseline`，不会把合理的 OpenSSH 默认值直接判断为错误。`strict` 会对 root 公钥登录、`MaxAuthTries > 3` 和 SSH TCP 转发等额外设置给出提醒。

## 只读行为

普通检测不会：

- 安装或删除系统软件包；
- 修改 SSH、sysctl 或防火墙设置；
- 修改密码或 SSH 密钥；
- 启用、停用或重启服务；
- 删除日志或用户文件；
- 自动修复检测结果。

第一次运行的一键启动器和 `vpsga update` 只会在 `/usr/local` 下安装或更新 VPS Guard Audit 自身。

默认只读取现有 APT 缓存，不会运行 `apt-get update`。只有显式使用 `--refresh-package-index` 时，才会刷新 APT 元数据并写入 `/var/lib/apt/lists`。

`--rootkit-check` 只会运行系统中已经安装的 `rkhunter` 或 `chkrootkit`。VPS Guard Audit 不会自动安装第三方扫描器。

## 主要检查项目

- 系统支持状态、主机类型和 AppArmor 状态
- 合并 IPv4/IPv6 后的全部接口 TCP、UDP 监听端口
- UFW、firewalld、nftables 和 iptables
- SSH 配置和登录策略
- Fail2ban、CrowdSec 和 sshguard 状态
- Debian 13 `wtmpdb`、`last`、`lastb`、journal 和 `lslogins` 兼容路径
- 登录记录和来源确认
- UID 0 账户、密码、sudo 和 SSH 密钥摘要
- 失败服务、Cron 和 systemd timer
- APT 更新、安全更新源、hold 软件包、内核和重启状态
- 内核与网络加固参数
- 敏感文件权限和 SUID/SGID 文件
- Docker 端口、特权、命名空间、capability 和挂载
- 可疑进程、已删除但仍运行的文件和临时可执行文件
- 代理、VPN、挖矿、扫描器和可选 Rootkit 检查

## 可选配置

```bash
cp config/audit.conf.example config/audit.conf
nano config/audit.conf
sudo vpsga --config config/audit.conf
```

配置文件可以声明可信登录 IP、主动开放的自定义端口、主机类型、审计策略和长列表输出数量。

## 源码和贡献者使用方式

普通用户不需要克隆仓库。开发者或贡献者可以使用：

```bash
git clone https://github.com/AshFog/vps-guard-audit.git
cd vps-guard-audit
sudo ./install.sh
vpsga
```

只有处于已克隆的项目目录中时，才可以直接运行原始脚本：

```bash
sudo ./vps-guard-audit.sh
```

## 退出代码

| 代码 | 含义 |
|---:|---|
| 0 | 没有警告或错误 |
| 1 | 发现警告 |
| 2 | 发现需要尽快处理的问题 |
| 64 | 参数错误 |
| 65 | 没有可用的交互终端 |
| 66 | 配置或安装源文件缺失 |
| 69 | 必要文件、工具或安装资源不可用 |
| 77 | 需要 root 权限 |

退出代码 1 或 2 是检测结果，不代表脚本崩溃。

## 安全限制

任何 Shell 脚本都不能绝对证明系统没有被入侵，也不能仅凭本机监听状态证明端口可以从公网访问。云防火墙、NAT、路由器、Docker 转发和内核级异常都会影响实际暴露情况。

AI 生成的修复方案同样需要人工审核。修改 SSH、防火墙、Docker、网络或执行重启前，应保持当前会话，确认备份或快照可用，并确保能够使用控制台或救援模式。

## 开发检查

```bash
bash -n vps-guard-audit.sh vpsga-manager.sh bootstrap.sh install.sh lib/*.sh
shellcheck vps-guard-audit.sh vpsga-manager.sh bootstrap.sh install.sh lib/*.sh
```

GitHub Actions 会检查语法、ShellCheck、报告文件、历史比较、全新安装、旧目录迁移、已安装命令执行和报告文件归属。

## 许可证

MIT
