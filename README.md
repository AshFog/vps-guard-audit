# VPS Guard Audit

**English** | [简体中文](README.zh-CN.md)

VPS Guard Audit is a bilingual, read-only-by-default security audit tool for Ubuntu and Debian. It does not automatically modify SSH, firewalls, users, services, or system configuration. Reports explain findings in plain language and include a more strongly redacted copy intended for analysis by a trusted AI assistant.

## Supported systems

Validated releases:

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

The audit automatically detects `vps`, `server`, `desktop`, and `container` profiles. Other Ubuntu or Debian releases may run, but the report warns when they are outside the validated matrix.

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
5. verify the installation;
6. immediately run the audit;
7. save reports in the directory where the command was launched.

### Every later run

From any directory, use only:

```bash
vpsga
```

A non-root user will be prompted for the sudo password automatically. Reports are returned to the invoking user when the output directory belongs to that user.

Do not run this from an arbitrary directory:

```bash
sudo ./vps-guard-audit.sh
```

`./` means “find this file in the current directory.” That form works only after cloning the source repository and changing into its directory. It is not the normal installed workflow.

## Verify the installation

```bash
command -v vpsga
vpsga --version
vpsga doctor
```

Expected command path:

```text
/usr/local/bin/vpsga
```

If `vpsga` is unavailable or `vpsga doctor` reports a broken `current` path, run the one-command installer again. The installer migrates older development layouts where `current` was accidentally created as a real directory.

## Update or uninstall

```bash
vpsga update
vpsga uninstall
```

`vpsga update` downloads the current repository version, validates the staged files, installs them, and runs a post-install health check.

`vpsga uninstall` requires explicit confirmation and asks whether audit history should be retained.

## Report files

A normal run creates three matching files with the same timestamp:

```text
vpsga-20260722-153045-full.txt
vpsga-20260722-153045-ai.txt
vpsga-20260722-153045.json
```

### Full TXT

`*-full.txt` contains the complete technical evidence, natural-language conclusion, findings, cautions, history comparison, and a prompt for requesting an AI-assisted remediation plan.

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

By default, VPS Guard Audit stores compact state files under:

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

## Common commands

```bash
vpsga
vpsga --lang en
vpsga --output-dir /home/user/audit-reports
vpsga --rootkit-check
vpsga --no-history
vpsga --version
vpsga --help
vpsga doctor
vpsga update
vpsga uninstall
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
- Debian 13 `wtmpdb`, `last`, `lastb`, journal, and `lslogins` fallbacks
- Login history and suspicious sources
- UID 0 accounts, passwords, sudo, and SSH-key summaries
- Failed services, cron jobs, and systemd timers
- APT updates, security sources, held packages, kernel, and reboot state
- Kernel and network hardening settings
- Sensitive permissions and SUID/SGID files
- Docker ports, privileges, namespaces, capabilities, and mounts
- Suspicious processes, deleted executables, and temporary executables
- Proxy, VPN, miner, scanner, and optional rootkit checks

## Optional configuration

```bash
cp config/audit.conf.example config/audit.conf
nano config/audit.conf
sudo vpsga --config config/audit.conf
```

The configuration file can define trusted login IPs, intentional custom ports, host profile, audit policy, and output limits.

## Source and contributor workflow

Normal users do not need to clone the repository. Contributors can use:

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

## Development checks

```bash
bash -n vps-guard-audit.sh vpsga-manager.sh bootstrap.sh install.sh lib/*.sh
shellcheck vps-guard-audit.sh vpsga-manager.sh bootstrap.sh install.sh lib/*.sh
```

GitHub Actions validates syntax, ShellCheck, report bundles, history comparison, clean installation, legacy-layout migration, installed-command execution, and report ownership.

## License

MIT
