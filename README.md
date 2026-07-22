# VPS Guard Audit

VPS Guard Audit 是一款双语、默认只读的 Ubuntu 与 Debian 安全审计工具。它不会自动修改 SSH、防火墙、用户、服务或系统配置。报告会用自然语言说明发现了什么、为什么值得关注、下一步如何确认，并生成适合提交给可信 AI 助手的脱敏副本。

VPS Guard Audit is a bilingual, read-only-by-default security audit tool for Ubuntu and Debian. It does not automatically modify SSH, firewalls, users, services, or system configuration. Reports explain findings in plain language and include a redacted copy designed for submission to a trusted AI assistant.

## Supported systems

Validated releases:

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

The audit auto-detects `vps`, `server`, `desktop`, and `container` profiles. Other Ubuntu/Debian versions may run, but the report warns when they are outside the validated matrix.

## One-command installation

```bash
curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash
```

The first run:

1. reads the bilingual language menu directly from `/dev/tty`;
2. downloads the complete repository archive once;
3. installs or updates the program under `/usr/local/lib/vps-guard-audit`;
4. creates `/usr/local/bin/vpsga`;
5. runs the audit and saves reports in the directory where the command was launched;
6. removes the temporary archive and extraction directory.

After installation, run the audit from any directory:

```bash
vpsga
```

A non-root user is automatically prompted through `sudo`. Reports are saved in the current directory unless `--output-dir` is supplied.

Update the installed program later with:

```bash
vpsga update
```

## Report names

Version 4.4 uses short, timestamped names:

```text
vpsga-20260722-153045-full.txt
vpsga-20260722-153045-ai.txt
vpsga-20260722-153045.json
```

The three files share the same generation time, making one audit bundle easy to identify.

### Full TXT

`*-full.txt` contains the complete technical evidence, natural-language conclusion, findings, cautions, history comparison, and AI prompt.

### AI TXT

`*-ai.txt` is generated from the full report with stronger automatic redaction. It replaces some:

- hostnames and FQDNs;
- non-root login usernames;
- Docker container names;
- configured web domains;
- IPv4 addresses;
- email and MAC addresses;
- SSH fingerprints.

Automatic redaction cannot guarantee that every custom identifier or credential is removed. Review the file before sharing it. Never submit passwords, private keys, API keys, access tokens, cookies, or other credentials.

### JSON

The JSON file contains structured findings for automation, history comparison, and future integrations.

## History comparison

By default, the audit stores a small structured state file under:

```text
/var/lib/vps-guard-audit/history/
```

The next audit reports:

- new warnings or failures;
- findings that have been resolved;
- findings whose severity changed.

Only the latest 30 state files are retained. Use `--no-history` for a run that should not read or save history.

## Management commands

```bash
vpsga doctor
vpsga update
vpsga uninstall
```

`vpsga doctor` checks the installed executable, version, current-release link, required modules, and PATH command.

`vpsga uninstall` requires an explicit confirmation and asks whether audit history should be retained.

## Read-only behavior

The normal audit does not:

- install or remove operating-system packages;
- edit SSH, sysctl, or firewall settings;
- change passwords or SSH keys;
- enable, disable, or restart services;
- delete logs or user files;
- automatically repair findings.

The bootstrap and `vpsga update` only install or update VPS Guard Audit itself under `/usr/local`.

By default, the audit reads the existing APT cache and does **not** run `apt-get update`. The optional `--refresh-package-index` flag refreshes APT metadata and therefore writes under `/var/lib/apt/lists`.

`--rootkit-check` only launches `rkhunter` or `chkrootkit` when already installed. The audit does not install third-party scanners.

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

## Audit options

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

Examples:

```bash
vpsga
vpsga --lang en
vpsga --output-dir /root/audit-reports
vpsga --rootkit-check
vpsga --no-history
vpsga --version
```

### Baseline vs strict

`baseline` is the default and avoids treating reasonable OpenSSH defaults as security failures. `strict` warns on settings such as root public-key login, `MaxAuthTries > 3`, and SSH TCP forwarding.

### Privacy

Full reports avoid some complete hardware identifiers and mask parts of login information by default. Use `--full-identifiers` only when a more complete forensic report is required. The AI report applies an additional redaction layer but must still be reviewed manually.

## Optional configuration

```bash
cp config/audit.conf.example config/audit.conf
nano config/audit.conf
sudo ./vps-guard-audit.sh --config config/audit.conf
```

Use the configuration file to mark trusted login IPs, intentional custom ports, the host profile, policy, and output limit.

## Manual installation

```bash
git clone https://github.com/AshFog/vps-guard-audit.git
cd vps-guard-audit
sudo ./install.sh
vpsga
```

Versioned files are stored under:

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
| 66 | Missing config or installation source |
| 69 | Required files, tools, or installation resources unavailable |
| 77 | Root privileges required |

A warning or failure exit code is an audit result, not a script crash. Do not append `exit $?` inside an active SSH shell.

## Security limitations

No shell script can prove that a host is clean or that an all-interface listener is reachable from the public Internet. Cloud firewalls, NAT, routers, Docker forwarding, and kernel compromise can change effective exposure. Unknown successful logins, unexpected UID 0 accounts, malicious processes, or unexplained persistence should be treated seriously.

AI-generated remediation steps must also be reviewed. Before SSH, firewall, Docker, networking, or reboot changes, preserve the current session, verify backups or snapshots, and ensure console or rescue access is available.

## Development

```bash
bash -n vps-guard-audit.sh vpsga-manager.sh bootstrap.sh install.sh lib/*.sh
shellcheck vps-guard-audit.sh vpsga-manager.sh bootstrap.sh install.sh lib/*.sh
```

GitHub Actions checks syntax, ShellCheck, JSON output, Chinese and English report bundles, history comparison, system installation, and the `vpsga` manager.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT
