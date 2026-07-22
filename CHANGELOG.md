# Changelog

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
