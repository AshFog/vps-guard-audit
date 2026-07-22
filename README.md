# VPS Guard Audit

面向 VPS 新手、服务器管理员和 Debian/Ubuntu 主机用户的双语安全审计工具。它默认只读，不会自动修改 SSH、防火墙、用户、服务或系统配置。除了完整技术检查，报告还会用更自然的语言说明发现了什么、为什么值得关注、下一步可以怎么确认，并附带一个可直接提交给可信 AI 助手的分析模板。

A bilingual security audit for VPS beginners and Debian/Ubuntu hosts. It is read-only by default and does not automatically modify SSH, firewalls, users, services, or system configuration. In addition to technical evidence, the TXT report explains findings in plain language, suggests safe next steps, and includes a ready-to-use prompt for a trusted AI assistant.

## Supported systems

Validated releases:

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

The audit auto-detects `vps`, `server`, `desktop`, and `container` profiles. Other Ubuntu/Debian versions may run, but the report warns when they are outside the validated matrix.

## One-command run and installation

```bash
curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash
```

The first one-command run:

1. reads the bilingual language menu directly from `/dev/tty`;
2. downloads the complete repository archive once;
3. installs or updates the audit under `/usr/local/lib/vps-guard-audit`;
4. creates the global command `/usr/local/bin/vpsga`;
5. runs the audit and saves reports in the directory where the command was launched;
6. removes the downloaded temporary archive and extraction directory.

After the first run, start the audit from any directory with:

```bash
vpsga
```

When run by a non-root user, `vpsga` uses `sudo` because several security checks require root access. Reports are saved in the current directory unless `--output-dir` is supplied.

Running the official one-command installer again updates the installed `vpsga` files to the current `main` branch and then starts a new audit.

For higher assurance, pin a release tag or commit SHA instead of the moving `main` branch.

## Local run

```bash
git clone https://github.com/AshFog/vps-guard-audit.git
cd vps-guard-audit
sudo ./vps-guard-audit.sh
```

The script asks:

```text
1) 中文
2) English
```

## Reports

A normal run generates:

```text
vps-guard-audit-HOST-TIME-LANG.txt
vps-guard-audit-HOST-TIME-LANG.json
```

The TXT file contains:

- the complete technical evidence collected by the audit;
- a beginner-friendly conclusion;
- findings separated into prompt attention, owner confirmation, and suggested improvements;
- plain-language explanations, suggested next steps, and cautions for disruptive changes;
- a privacy reminder and a copy-ready AI analysis prompt.

The JSON file contains structured findings for tools, automation, and comparison.

## Using AI with the report

The audit does not automatically repair the host. After reviewing the TXT file for privacy, you may submit it to a trusted AI assistant and ask for a system-specific remediation plan.

For better guidance, also describe:

- what the server is intended to run;
- the active SSH port;
- which ports, containers, proxies, and websites were intentionally deployed;
- whether provider console, VNC, serial console, or rescue access is available;
- whether changes can be scheduled during a maintenance window.

Never share passwords, SSH private keys, API keys, access tokens, cookies, or other credentials. The report redacts some identifiers by default, but it should still be reviewed before sharing.

## Read-only behavior

The normal audit does not:

- install or remove operating-system packages;
- edit SSH, sysctl, or firewall settings;
- change passwords or SSH keys;
- enable, disable, or restart services;
- delete logs or user files;
- automatically repair findings.

The bootstrap only installs or updates the VPS Guard Audit program itself under `/usr/local` so that `vpsga` is available system-wide.

By default the audit reads the existing APT cache and does **not** run `apt-get update`. The optional `--refresh-package-index` flag refreshes APT metadata and therefore writes under `/var/lib/apt/lists`.

`--rootkit-check` only launches `rkhunter` or `chkrootkit` when already installed. The normal audit does not install third-party scanners.

## Major checks

- OS support, host profile, and compact AppArmor status
- All-interface TCP/UDP listeners with IPv4/IPv6 deduplication
- Context-aware Avahi/mDNS and CUPS findings
- Public Docker API and common database ports
- UFW, firewalld, native nftables, and iptables backends
- Direct `iptables ACCEPT` rules that may bypass UFW
- UFW allow rules with no matching active listener
- Baseline or strict SSH policy
- Fail2ban, CrowdSec, and sshguard with dependency-aware scoring
- Debian 13 `wtmpdb` login-history support and journal fallback
- UID 0 accounts, empty password hashes, sudo, and redacted SSH-key summaries
- Failed services, cron, and systemd timers with bounded output
- APT index age, update counts, security updates, held packages, and kernel/reboot state
- Kernel and network hardening values
- Sensitive permissions and host-only SUID/SGID inventory
- Docker published ports, privileged mode, host namespaces, capabilities, and sensitive mounts
- Deleted executables and temporary executables while excluding the audit itself
- Common miner and scanner process names
- Proxy/VPN services and risky helper scripts
- Optional existing rootkit scanners

## Options

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
--quiet
-h, --help
-v, --version
```

Examples after installation:

```bash
vpsga
vpsga --lang en
vpsga --output-dir /root/audit-reports
vpsga --rootkit-check
vpsga --version
```

### Baseline vs strict

`baseline` is the default and avoids treating reasonable OpenSSH defaults as security failures. `strict` warns on settings such as root public-key login, `MaxAuthTries > 3`, and SSH TCP forwarding.

### Privacy

Default reports avoid full hardware identifiers and SSH fingerprints and mask the last octet of IPv4 login addresses. Use `--full-identifiers` only when a complete forensic report is required.

## Optional configuration

```bash
cp config/audit.conf.example config/audit.conf
nano config/audit.conf
sudo ./vps-guard-audit.sh --config config/audit.conf
```

Use the configuration file to mark trusted login IPs, intentional custom ports, the host profile, policy, and output limit.

## Manual system-wide installation

From a cloned or downloaded repository:

```bash
sudo ./install.sh
vpsga
```

The installer keeps versioned program files under:

```text
/usr/local/lib/vps-guard-audit/releases/VERSION/
```

The current installation is selected through:

```text
/usr/local/lib/vps-guard-audit/current
```

The compatibility command `vps-guard-audit` remains available in `/usr/local/sbin`.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | No warnings or failures |
| 1 | Warnings found |
| 2 | Failures found |
| 64 | Invalid option |
| 65 | Interactive terminal unavailable |
| 66 | Unreadable config or incomplete installation source |
| 69 | Required audit files could not be downloaded or installed |
| 77 | Root privileges required |

A warning or failure exit code is an audit result, not a script crash. Do not append `exit $?` inside an active SSH shell.

## Security limitations

No shell script can prove that a host is clean or that an all-interface listener is reachable from the public Internet. Cloud firewalls, NAT, routers, Docker forwarding, and kernel compromise can change the effective exposure. Unknown successful logins, unexpected UID 0 accounts, malicious processes, or unexplained persistence should be treated seriously.

AI-generated remediation steps must also be reviewed. Before SSH, firewall, Docker, networking, or reboot changes, preserve the current session, verify backups or snapshots, and ensure console or rescue access is available.

## Development

```bash
bash -n vps-guard-audit.sh bootstrap.sh install.sh lib/*.sh
shellcheck vps-guard-audit.sh bootstrap.sh install.sh lib/*.sh
```

GitHub Actions performs syntax checks, ShellCheck, JSON validation, Chinese/English beginner-report tests, and a system-wide `vpsga` installation smoke test.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT
