# VPS Guard Audit

> v6.0.0 正在进行发布验收：面向 Ubuntu/Debian 常见 VPS 的 10 项常规加固和 8 项连接敏感加固均已接入。连接敏感动作必须通过用途确认、控制台确认、备用管理员、延时回滚和第二 SSH 终端验证。

面向中文用户的 Ubuntu / Debian VPS 安全审计与可控加固工具。

VPS Guard Audit 重点解决三个问题：传统安全报告看不懂、不了解风险含义、不知道下一步该怎样继续排查。它不追求检查数量或模糊的安全分数，而是为常见 VPS 场景提供低误报、可解释、可比较的中文审计结果。

## 项目特点

- 一条命令完成安装和检测；
- 检测过程默认只读，只有用户明确输入 `APPLY` 才执行已开放的加固动作；
- 所有程序提示、检查结论、报告和 AI 提示词均使用中文；
- 每个检查使用固定编号，标题变化不会破坏历史比较；
- 区分正常、问题、不适用、缺少命令、本机无法确认和需要用户判断；
- 生成完整中文报告、AI 脱敏报告和 JSON；
- 自动比较前后两次检测结果；
- 主要适配 Ubuntu、Debian、Docker、SSH、防火墙和常见 VPS 服务。

## 支持系统

已验证：

- Ubuntu 26.04、24.04、22.04 LTS
- Debian 13、12、11

其他 Ubuntu / Debian 版本通常也能运行，但报告会明确提示其不在已验证范围内。项目不会把未验证结果描述成确定结论。

## 一键安装并检测

```bash
curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash
```

检测后单独输出中文加固计划：

```bash
vpsga plan
```

在交互式终端直接运行 `vpsga`，检测完成后会显示“常规安全加固”和“连接敏感加固”菜单。非交互执行、定时任务和 CI 不会等待输入。连接敏感项目的说明入口位于 [docs/hardening](docs/hardening/index.md)。

当前可执行项目为 `HARD-1001` 至 `HARD-1010` 和 `HARD-2001` 至 `HARD-2008`。常规动作需输入 `APPLY`；连接敏感动作还必须确认 VPS 控制台可用、选择具备安全公钥的非 root sudo 管理员，并从第二个独立 SSH 会话完成确认。未在5分钟内确认时，systemd timer 会自动恢复修改前的配置或服务状态。UFW 必须人工提交端口清单；关闭 SSH 转发、网络能力或候选服务还需要额外确认实际业务用途。

发布前验收分为两层：Ubuntu/Debian 发行版矩阵自动验证18项隔离动作、全新安装与真实 v5.0.0 升级；真实 VM 再验证 systemd、OpenSSH、防火墙和第二终端失联恢复。完整步骤见 [v6 发布验收清单](docs/RELEASE_ACCEPTANCE_V6.md)。

执行连接敏感动作前，可以先运行 `vpsga connection-check`。它会检查当前 SSH 入口、具备安全公钥的非 root sudo 管理员，以及 systemd 延时回滚支持；VPS 控制台是否真正可用仍需用户人工确认。

涉及 SSH 隧道、IP 转发、IPv6、Docker/VPN 或 CUPS/Avahi 服务时，先运行 `vpsga workload-plan` 查看只读用途清单。它只提供证据，不会替用户判断某项业务是否可以停止。

安装完成后，以后在任意目录直接运行：

```bash
vpsga
```

普通用户运行时，`vpsga` 会自动请求 sudo 权限。报告默认保存到执行命令时所在的目录，并在目录属于原用户时自动归还文件所有权。

## 常用命令

```bash
vpsga
vpsga --depth quick
vpsga --depth standard
vpsga --depth deep
vpsga --profile web
vpsga --output-dir /home/user/audit-reports
vpsga --format json
vpsga --no-history
vpsga --version
vpsga --help
vpsga doctor
vpsga update
vpsga rollback
vpsga connection-check
vpsga firewall-plan
vpsga workload-plan
vpsga uninstall
```

## 检测深度

| 模式 | 适合场景 | 主要行为 |
|---|---|---|
| `quick` | 日常快速确认 | 跳过 APT 更新、内核参数和耗时文件扫描 |
| `standard` | 默认例行审计 | 检查主要系统、网络、SSH、账户、软件包和容器项目 |
| `deep` | 首次接管或异常排查 | 增加文件权限、SUID/SGID、容器隔离、临时目录和已安装 Rootkit 扫描器检查 |

深度检查可能耗时较长。Rootkit 工具误报较多，结果只能作为继续排查的线索，不能单独证明系统已被入侵。

## 配置档案

`--profile` 支持：

- `auto`：自动选择；
- `general`：通用 VPS；
- `web`：网站服务器；
- `docker`：Docker 主机；
- `proxy`：代理服务器；
- `home`：家庭服务器；
- `desktop`：桌面 Linux。

当前版本主要用档案降低场景误报，后续会继续增加按角色启用检查和端口基线的能力。

源码仓库和安装目录都提供了对应的中文配置模板。例如：

```bash
sudo vpsga --config /usr/local/lib/vps-guard-audit/current/config/profiles/web.conf
```

## 状态标签

终端和 TXT 报告使用以下标签：

| 标签 | 含义 |
|---|---|
| `[正常]` | 检查符合当前基线 |
| `[提醒]` | 建议确认或改进，不代表已经被入侵 |
| `[问题]` | 有明确证据，需要尽快处理 |
| `[信息]` | 帮助理解环境的补充信息 |
| `[跳过]` | 不适用、缺少条件或当前模式未检查 |

## 稳定检查编号

v5 引入固定检查编号，例如：

```text
SYS-1001  系统版本支持状态
NET-2001  全接口监听端口
FW-3001   防火墙运行状态
SSH-4001  SSH 密码登录
USR-5001  异常 UID 0 账户
PKG-6001  待安装安全更新
CTR-7001  Docker 对外发布端口
MAL-8001  临时目录可执行文件
```

编号属于检查本身，不随标题改变。端口、用户、容器等可重复对象通过 JSON 的 `instance_key` 区分，因此历史比较既稳定，又不会把多个实例互相覆盖。

## 报告文件

普通检测会生成：

```text
vpsga-20260722-153045-full.txt
vpsga-20260722-153045-ai.txt
vpsga-20260722-153045.json
```

`*-full.txt` 是完整中文人类报告，包含原始证据、自然语言解释、风险提醒、历史比较和 AI 分析提示词。

`*-ai.txt` 会进一步替换部分主机名、用户名、容器名、域名、IPv4、邮箱、MAC 地址和 SSH 指纹。自动脱敏无法保证覆盖所有自定义标识符，分享前仍需亲自检查。不要提交密码、SSH 私钥、API Key、访问令牌、Cookie 或其他凭据。

JSON 使用稳定的机器格式。v5 的核心结构示例：

```json
{
  "schema_version": "2.0",
  "test_id": "SSH-4001",
  "instance_key": "ssh.password",
  "status": "warn",
  "confidence": "needs_review",
  "applicability": "applicable",
  "evidence": [],
  "references": []
}
```

JSON 字段名、检查编号、Linux 命令和配置名称保留英文或 ASCII，以保证脚本和外部程序兼容。`ufw`、`systemctl`、`docker`、`apt` 等系统工具的原始输出也不会强行翻译，避免破坏证据。

## 历史比较

默认在 `/var/lib/vps-guard-audit/history/` 保存最多 30 份紧凑状态文件。从第二次检测开始，报告会显示新增问题、已经解决的问题和严重程度变化。

单次禁用历史记录：

```bash
vpsga --no-history
```

## 安装完整性保护

v5 在运行和维护过程中会：

- 使用安全 `umask`；
- 通过运行锁阻止两个 `vpsga` 同时执行；
- 拒绝覆盖已有文件或符号链接报告路径；
- 检查安装目录所有者和可写权限；
- 使用 `MANIFEST.sha256` 校验程序和模块；
- 按字段解析配置文件，不把配置文件作为 Shell 脚本执行；
- 在中断或退出时清理临时文件；
- 通过 `vpsga doctor` 检查命令、模块、权限、语法和完整性。

## 只读边界

默认检测不会安装或删除系统软件包，不编辑 SSH、sysctl、防火墙或账户配置，不重启服务，不删除日志，也不自动修复问题。

以下操作是明确例外：

- 首次安装和 `vpsga update` 只修改 VPS Guard Audit 自身在 `/usr/local` 下的文件；
- `--refresh-package-index` 会执行 `apt-get update`；
- 历史比较会写入 `/var/lib/vps-guard-audit/history/`；
- 报告会写入指定输出目录。

## 配置文件

```bash
cp config/audit.conf.example config/audit.conf
nano config/audit.conf
sudo vpsga --config config/audit.conf
```

配置文件可声明可信登录 IP、主动开放端口、预期 UID 0 用户、配置档案、安全策略、检测深度和输出数量限制。

## 退出码

| 代码 | 含义 |
|---:|---|
| 0 | 没有提醒或问题 |
| 1 | 发现提醒项 |
| 2 | 发现问题项 |
| 64 | 命令参数无效 |
| 66 | 配置或安装源缺失 |
| 69 | 必要文件、命令或下载资源不可用 |
| 73 | 报告路径已经存在或不安全 |
| 75 | 已有检测正在运行 |
| 76 | 安装权限或完整性校验失败 |
| 77 | 需要 root 权限 |

退出码 1 或 2 表示审计结果，不表示脚本崩溃。

## 安全限制

任何 Shell 脚本都无法绝对证明主机安全，也无法仅凭本机监听状态证明端口可从互联网访问。云防火墙、NAT、路由、Docker 转发和内核层异常都会影响真实暴露面。

涉及 SSH、防火墙、Docker、网络或重启的修改前，应保留当前会话，确认备份或快照，并确保拥有云控制台、VNC、串口控制台或救援模式。VPS Guard Audit 不提供“一键自动修复全部”。

## 许可证

VPS Guard Audit 使用 MIT 许可证。项目会学习 Lynis 等工具的审计框架思想和工程方法，但不复制或改写 GPLv3 代码。
