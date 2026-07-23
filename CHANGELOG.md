# Changelog

## 6.0.0-dev.6

- 新增 `vpsga firewall-plan`，只读列出当前 SSH 入口、主机监听端口、Docker 发布端口与 UFW 编号规则。
- 开放 `HARD-2003`：用户必须明确提交 `端口/协议` 白名单，且清单必须包含当前 SSH 端口；配置验证后才能进入第二终端确认。
- 开放 `HARD-2004`：只删除用户逐条确认的 UFW 规则编号，按倒序处理并验证目标规则已消失；超时恢复原规则文件。
- 开放 `HARD-2005`：使用实际 SSH 端口建立独立 Fail2ban jail，并把当前管理 IP 加入豁免；配置测试和服务启动失败会恢复。
- UFW 与 Fail2ban 缺失时可安装发行版官方软件包；回滚恢复配置和服务状态，但不自动卸载新安装的软件包。
- UFW 启用前拒绝与运行中的 firewalld 叠加，并明确提示 Docker 发布端口可能绕过普通 UFW 入站规则。
- 新增网络加固隔离测试，覆盖 SSH 端口遗漏、第二终端提交、规则超时恢复、Fail2ban 端口识别及服务失败回滚。

## 6.0.0-dev.5

- 开放 `HARD-2001`：设置 `PermitRootLogin no`，禁止 root 直接通过 SSH 登录。
- 开放 `HARD-2002`：同时关闭 `PasswordAuthentication` 与 `KbdInteractiveAuthentication`。
- 两项动作均强制经过控制台确认、备用 sudo 管理员检查、5分钟 systemd 延时回滚和第二 SSH 会话确认。
- SSH 写入后使用 `sshd -t` 检查语法，并使用 `sshd -T` 检查最终生效值；配置冲突或 reload 失败会立即恢复。
- 普通常规动作执行器明确拒绝 `HARD-2xxx`，避免敏感动作绕过防失联流程。
- 修正全局 `vpsga` 包装器的管理命令分发，确保第二终端确认与 systemd 自动回滚在安装后真正可用。
- 新增敏感 SSH 隔离测试，覆盖确认提交、确认超时恢复和 reload 故障回滚。

## 6.0.0-dev.4

- 新增连接敏感加固的统一防失联模块，真实识别当前 SSH 客户端、服务器地址与端口。
- 备用管理员必须为非 root sudo/admin 用户，并拥有权限安全、包含有效公钥的 `authorized_keys`。
- 第二终端确认必须来自不同 SSH 会话、相同服务器入口，并由指定备用管理员完成。
- 新增 `vpsga connection-check` 与 `vpsga connection-confirm TOKEN`。
- 建立 systemd 临时 timer 延时回滚接口；无法建立可靠 timer 时，连接敏感动作必须拒绝执行。
- 事务新增 `pending_confirmation` 状态，超时只自动恢复尚未由第二终端确认的连接敏感变更。
- 自动回滚前校验修改后指纹，拒绝覆盖事务完成后发生的其他配置变更。

## 6.0.0-dev.3

- 开放 `HARD-1008` 至 `HARD-1010`：自动安全更新、兼容性较高的 sysctl 基线和 Core Dump 限制。
- 自动安全更新使用独立 APT 配置片段，不覆盖 Ubuntu/Debian 官方软件包维护的安全来源策略。
- 审计现在同时确认 unattended-upgrades 是否安装、是否启用周期更新，避免“已安装但未运行”的假闭环。
- sysctl 动作只处理当前内核实际存在的参数，不修改 IP 转发，不禁用 IPv6；部分应用失败时恢复原运行时值。
- Core Dump 动作同时限制普通用户与 systemd-coredump，并支持对新建配置目录进行安全回滚。
- 增加 APT、sysctl 和 Core Dump 的隔离事务及故障注入测试。

## 6.0.0-dev.2

- 开放 `HARD-1005` 至 `HARD-1007`：禁止 SSH 空密码、限制认证尝试次数、关闭 X11 转发。
- SSH 加固统一写入受管理的 drop-in 文件，写入前备份，写入后同时运行 `sshd -t` 和 `sshd -T` 验证。
- SSH 配置验证或服务 reload 失败时恢复旧文件，并重新加载恢复后的配置。
- 严格策略的 `MaxAuthTries` 基线与自动加固值统一为 4，确保加固后复检能够闭环。
- 事务提交时记录修改后文件指纹，拒绝越过较新变更回滚旧事务。
- 增加隔离 SSH 故障注入测试，不修改测试主机的真实 `/etc/ssh`。

## 6.0.0-dev.1

- 建立独立的 18 项加固动作注册表：10 项常规安全加固、8 项连接敏感加固。
- 新增 `vpsga plan`，根据本次审计结果生成自然中文的只读加固计划。
- 交互式检测完成后显示双风险菜单；非交互运行保持无阻塞。
- 为连接敏感项目增加 GitHub Pages 文档结构和失联恢复总指南。
- 补充 SSH 主机私钥和 Core Dump 基线检测，使对应加固项目具有真实审计证据。
- 自动执行暂不开放，等待备份、配置验证、延时回滚与复检机制完成。
- 新增加固事务框架：每次动作使用独立事务目录，保存原文件、权限、所有者、哈希与执行状态。
- 首批开放 `HARD-1001` 至 `HARD-1004`：账户文件、SSH 密钥、sudoers 与 Cron 权限修复。
- 所有已开放动作均需在交互菜单输入 `APPLY` 明确确认，修改后验证失败会立即自动回滚。
- 事务与备份默认保存在 `/var/lib/vps-guard-audit/hardening/`，目录权限为 `0700`。
- 增加 `vpsga rollback`：可列出已保存事务，并在再次输入 `ROLLBACK` 后恢复已提交动作。
- 程序在动作进行中收到退出或中断信号时会尝试自动回滚；卸载默认保留检测历史与加固回滚记录。

## 5.0.0 — 2026-07-22

### 中文原生审计框架

- 项目正式定位为面向中文用户的 Ubuntu / Debian VPS 只读安全审计工具。
- 删除语言选择和英文报告；安装、检测、帮助、管理命令、报告、AI 提示词、README 与配置注释全部改为中文。
- 终端状态改为 `[正常]`、`[提醒]`、`[问题]`、`[信息]`、`[跳过]`。
- 引入 `SYS-1001`、`NET-2001`、`FW-3001`、`SSH-4001` 等稳定检查编号和检查注册表。
- 增加检查分类、适用系统、所需命令、前置条件、风险、可信度、来源和检测深度元数据。
- 增加 `quick`、`standard`、`deep` 三种检测深度，以及通用、网站、Docker、代理、家庭和桌面配置档案。
- JSON 升级为 Schema 2.0，加入 `test_id`、`instance_key`、`status`、`confidence`、`applicability`、`evidence` 和 `references`。
- 历史比较改用稳定检查编号与实例键，避免标题变化或重复实例破坏比较。
- 增加运行锁、安全 `umask`、报告路径原子创建、安装目录权限检查和 `MANIFEST.sha256` 完整性校验。
- `vpsga doctor` 现在检查模块清单和哈希完整性。
- v4.4.0 保留为最后一个双语稳定版本，既有 Tag 不作修改。

## 4.4.0 — 2026-07-22

Report bundle, stronger AI redaction, history comparison, safer installation, and management-command release.

### Added

- Timestamped audit bundles using `vpsga-YYYYMMDD-HHMMSS` as the shared base name.
- A complete `*-full.txt` report.
- A stronger `*-ai.txt` redacted report for submission to trusted AI assistants.
- Automatic comparison with the previous audit, showing new, resolved, and severity-changed findings.
- Up to 30 compact history state files under `/var/lib/vps-guard-audit/history/`.
- `--no-history` for audits that should not read or save comparison state.
- `vpsga doctor`, `vpsga update`, and `vpsga uninstall` management commands.
- Separate English and Simplified Chinese documentation: `README.md` and `README.zh-CN.md`.
- CI coverage for bilingual report bundles, history comparison, clean installation, legacy-layout migration, non-root execution, report ownership, and manager commands.

### Fixed

- Repairs the installation failure that occurred when an earlier development build left `/usr/local/lib/vps-guard-audit/current` as a real directory instead of a symlink.
- Prevents `ln` from creating a nested `current/VERSION` symlink that made the global `vpsga` command report an incomplete installation.
- Validates staged scripts and modules before switching the active release.
- Verifies the installed `vpsga` version and runs `vpsga doctor` before the bootstrap starts the first audit.
- Returns report ownership to the non-root user who invoked `vpsga` when the selected output directory belongs to that user.
- Captures Debian failed-login fallback output consistently instead of printing some fallback data outside the report variable.
- Treats unavailable sysctl values as `SKIP` rather than security warnings.
- Accepts secure `0600` and `0640` modes for `/etc/shadow` and `/etc/gshadow`.
- Avoids claiming that no ports are listening when the `ss` command is unavailable.
- Avoids claiming Docker security checks passed when `docker inspect` data could not be read.
- Quotes Docker container IDs safely and removes unreliable unquoted expansion.
- Treats host firewall and AppArmor visibility more carefully inside containers.
- Makes update temporary-directory cleanup safe with `set -u`.

### Changed

- Report names no longer contain the hostname or language; the generation timestamp identifies the matching bundle.
- The AI guidance tells users to prefer the `*-ai.txt` report over the complete report.
- The system installer uses versioned releases and a verified `current` symlink.
- README documentation presents `vpsga` as the normal installed command and reserves `sudo ./vps-guard-audit.sh` for contributors working inside a cloned source directory.
- The earlier HTML report and local viewer commands were removed before release because they added little value for typical SSH-based use.

### Security

- The AI report maps or removes some hostnames, usernames, container names, domains, IPv4 addresses, email addresses, MAC addresses, and SSH fingerprints.
- Automatic redaction remains best-effort, and reports must still be reviewed before sharing.
- Installation files are checked for syntax and required modules before activation.
- `vpsga doctor` verifies that the active release stays inside the managed releases directory and that installed files are not group- or world-writable.

## 4.3.0 — 2026-07-22

Beginner-report release focused on clarity, safe next steps, AI-assisted remediation, and easier repeated use.

### Changed

- Rewrites the final summary in careful, natural Chinese and English instead of presenting only security-engineering terminology.
- Separates findings into prompt attention, owner confirmation, and suggested improvements.
- Explains that warnings do not automatically mean the host is compromised.
- Groups multiple sysctl deviations into one understandable hardening item while keeping the individual values in the report.
- Keeps the project strictly audit-only: no automatic repair menu and no unattended configuration changes.
- The official one-command bootstrap now installs or updates the program under `/usr/local` before running the audit.

### Added

- Plain-language explanations for common SSH, firewall, package, Docker, account, service, port, malware, and kernel findings.
- Suggested next steps and explicit cautions for operations that may interrupt SSH, networking, containers, or running services.
- A detailed Chinese and English AI handoff section in every TXT report.
- A copy-ready prompt asking an AI assistant for issue prioritization, safe commands, backups, verification, and rollback guidance.
- Privacy guidance warning users not to share passwords, private keys, API keys, tokens, cookies, or other credentials.
- Structured in-memory finding metadata used to build the beginner summary without changing the JSON finding schema.
- Chinese and English summary smoke tests in GitHub Actions.
- A global `vpsga` command in `/usr/local/bin`, available from any directory after the first one-command run.
- A compatibility `vps-guard-audit` command in `/usr/local/sbin`.
- Versioned installation directories under `/usr/local/lib/vps-guard-audit/releases/` with a `current` symlink.
- A CI smoke test for system-wide installation and installed-command execution.

## 4.2.1 — 2026-07-22

Startup reliability fix.

### Fixed

- Reads the language menu directly from `/dev/tty` when launched through `curl | bash`.
- Removes the extra Enter-to-start prompt that could wait on the pipeline input.
- Saves one-command reports in the directory where the command was launched.
- Keeps the startup title as `VPS Guard Audit` without the former Chinese brand suffix.

## 4.2.0 — 2026-07-22

Compatibility and accuracy release based on Debian 13 and Ubuntu 24.04 field tests.

### Fixed

- Supports Debian 13 login history through `wtmpdb`, with `last`, `lastb`, `journalctl` and `lslogins` fallbacks.
- Excludes the currently running audit and its temporary directory from temporary-executable findings.
- Merges duplicate IPv4 and IPv6 listeners before scoring and counting.
- Fixes JSON summaries being reset by the previous `tee` pipeline subshell.
- Prevents `/etc/os-release` from overwriting the audit's own `VERSION` variable.
- Missing optional commands now produce `SKIP` instead of false `PASS` results.
- Rootkit scanners now distinguish missing tools, execution warnings and successful completion.
- Fail2ban inactivity no longer produces a second jail warning and a duplicate failed-unit warning.
- Clarifies why optional rootkit scanners are not launched or installed automatically.

### Changed

- Renames “public listener” findings to “all-interface listener”; local checks do not claim Internet reachability.
- Adds automatic `vps`, `server`, `desktop` and `container` host profiles.
- Treats Avahi/mDNS as normal desktop discovery but warns on server profiles.
- Adds `baseline` and `strict` SSH policies to reduce false positives from reasonable OpenSSH defaults.
- Stops refreshing APT metadata by default; `--refresh-package-index` is now explicit.
- Limits package, service, cron, timer and SUID output.
- Suppresses full hardware identifiers, login IPs and SSH fingerprints by default.
- AppArmor output is summarized instead of dumping every loaded profile.
- Splits the audit engine into maintainable modules under `lib/`.

### Added

- Native nftables and firewalld detection alongside UFW and iptables.
- Docker published-port warnings that explain UFW INPUT limitations.
- Docker checks for host namespaces, weak security options, high-risk capabilities and sensitive mounts.
- APT index age, security-source, held-package, reboot and running-kernel checks.
- Host-only SUID/SGID inventory that excludes Docker, containerd and Snap storage layers.
- `--profile`, `--policy`, `--full-identifiers` and `--refresh-package-index` options.
- CI JSON smoke test.

## 4.1.0 — 2026-07-22

Field-tested hardening release based on a real Ubuntu 24.04 VPS audit.

### Fixed

- Correctly detects listeners bound to `0.0.0.0`, `*`, and `[::]`.
- No longer reports “no public listeners” when `ss` clearly shows exposed services.
- Limits Fail2ban output to summary data and at most 20 sample banned IPs.
- Adds a `/dev/tty`-safe bootstrap command so the language menu works without `/dev/fd`.

### Added

- High-risk detection for public CUPS (`631/tcp`) and Docker API (`2375/2376`).
- Review warnings for publicly exposed database and data-service ports.
- Detection of direct `iptables ACCEPT` rules placed before UFW chains.
- Detection of UFW allow rules with no corresponding active listener.
- UFW boot-enable check.
