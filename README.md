# VPS Guard Audit

VPS Guard Audit 是一款双语、默认只读的 Ubuntu 与 Debian 安全审计工具。它不会自动修改 SSH、防火墙、用户、服务或系统配置。报告会用自然语言解释检测结果，并生成适合提交给可信 AI 助手的脱敏副本。

VPS Guard Audit is a bilingual, read-only-by-default security audit tool for Ubuntu and Debian. It does not automatically modify SSH, firewalls, users, services, or system configuration. Reports explain findings in plain language and include a redacted copy intended for a trusted AI assistant.

## Supported systems

Validated releases:

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

The audit automatically detects `vps`, `server`, `desktop`, and `container` profiles.

## Quick start

### First use: install and run

Copy this single command:

```bash
curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash
```

It will:

1. display the Chinese / English language menu;
2. download the complete project;
3. install or update VPS Guard Audit under `/usr/local/lib/vps-guard-audit`;
4. create the global command `/usr/local/bin/vpsga`;
5. immediately run the audit;
6. save reports in the directory where the command was launched.

### Every later run

From any directory, use only:

```bash
vpsga
```

A non-root user will be prompted for the sudo password automatically. Do not add `sudo` unless you have a specific reason.

### Important command distinction

This is the normal installed command:

```bash
vpsga
```

Do **not** run this from an arbitrary directory:

```bash
sudo ./vps-guard-audit.sh
```

`./` means “find this file in the current directory.” That command works only after cloning the source repository and changing into its directory. It is not the one-command user experience and is not needed after installation.

Check the installation with:

```bash
command -v vpsga
vpsga --version
vpsga doctor
```

Expected command path:

```text
/usr/local/bin/vpsga
```

If `vpsga` is not found, run the one-command installer again.

## Updating

After installation:

```bash
vpsga update
```

Then verify:

```bash
vpsga --version
vpsga doctor
```

## Report files

A normal run creates three matching files with the same timestamp:

```text
vpsga-20260722-153045-full.txt
vpsga-20260722-153045-ai.txt
vpsga-20260722-153045.json
```

### Full TXT

`*-full.txt` contains the complete technical evidence, natural-language conclusion, warnings, cautions, history comparison, and AI prompt.

### AI TXT

`*-ai.txt` applies an additional redaction layer to some:

- hostnames and FQDNs;
- non-root usernames;
- Docker container names;
- configured web domains;
- IPv4 addresses;
- email and MAC addresses;
- SSH fingerprints.

Automatic redaction cannot guarantee that every custom identifier or credential is removed. Review the file before sharing it. Never submit passwords, private keys, API keys, access tokens, cookies, or other credentials.

### JSON

The JSON file contains structured findings for history comparison, automation, and future integrations.

## History comparison

By default, VPS Guard Audit stores a compact state under:

```text
/var/lib/vps-guard-audit/history/
```

From the second run onward, the report can show:

- new warnings or failures;
- findings that have been resolved;
- severity changes.

Only the latest 30 state files are retained.

Disable history for one run:

```bash
vpsga --no-history
```

## Management commands

```bash
vpsga doctor
vpsga update
vpsga uninstall
```

- `vpsga doctor` checks the installed executable, version, modules, current-release link, and PATH command.
- `vpsga update` downloads and installs the current repository version.
- `vpsga uninstall` removes the installed program and asks whether history should be kept.

## Common audit commands

```bash
vpsga
vpsga --lang en
vpsga --output-dir /root/audit-reports
vpsga --rootkit-check
vpsga --no-history
vpsga --version
vpsga --help
```

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
--no-history
--quiet
-h, --help
-v, --version
```

### Baseline and strict policies

`baseline` is the default and avoids treating reasonable OpenSSH defaults as failures. `strict` warns on additional settings such as root public-key login, `MaxAuthTries > 3`, and SSH TCP forwarding.

## Read-only behavior

The normal audit does not:

- install or remove operating-system packages;
- edit SSH, sysctl, or firewall settings;
- change passwords or SSH keys;
- enable, disable, or restart services;
- delete logs or user files;
- automatically repair findings.

The first-run bootstrap and `vpsga update` only install or update VPS Guard Audit itself under `/usr/local`.

By default, the audit reads the existing APT cache and does **not** run `apt-get update`. The optional `--refresh-package-index` flag refreshes APT metadata and writes under `/var/lib/apt/lists`.

`--rootkit-check` launches `rkhunter` or `chkrootkit` only when one is already installed. VPS Guard Audit does not install third-party scanners.

## Major checks

- OS support, host profile, and AppArmor status
- All-interface TCP and UDP listeners with IPv4/IPv6 deduplication
- UFW, firewalld, nftables, and iptables backends
- SSH configuration and login policy
- Fail2ban, CrowdSec, and sshguard status
- Login history and suspicious sources
- UID 0 accounts, passwords, sudo, and SSH-key summaries
- Failed services, cron jobs, and systemd timers
- APT updates, security sources, held packages, kernel, and reboot state
- Kernel and network hardening settings
- Sensitive permissions and SUID/SGID files
- Docker ports, privileges, namespaces, capabilities, and mounts
- Suspicious processes, deleted executables, and temporary executables
- Proxy, VPN, miner, scanner, and optional rootkit checks

## Advanced source usage

The source form is for contributors or users who deliberately clone the repository:

```bash
git clone https://github.com/AshFog/vps-guard-audit.git
cd vps-guard-audit
sudo ./install.sh
vpsga
```

Only while inside that cloned directory can the raw source script be run directly:

```bash
sudo ./vps-guard-audit.sh
```

Normal users should use `vpsga` instead.

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

A warning or failure exit code is an audit result, not a script crash.

## Security limitations

No shell script can prove that a host is clean or that an all-interface listener is reachable from the public Internet. Cloud firewalls, NAT, routers, Docker forwarding, and kernel compromise can change effective exposure.

AI-generated remediation steps must also be reviewed. Before SSH, firewall, Docker, networking, or reboot changes, preserve the current session, verify backups or snapshots, and ensure console or rescue access is available.

## Development

```bash
bash -n vps-guard-audit.sh vpsga-manager.sh bootstrap.sh install.sh lib/*.sh
shellcheck vps-guard-audit.sh vpsga-manager.sh bootstrap.sh install.sh lib/*.sh
```

## License

MIT
