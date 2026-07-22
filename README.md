# VPS Guard Audit

面向 VPS、新手服务器管理员和 Debian/Ubuntu 主机用户的双语、交互式安全审计工具。默认只读，重点减少误报，并帮助发现监听端口、防火墙绕过、SSH 风险、异常账户、危险持久化、Docker 暴露及常见挖矿木马特征。

A bilingual, interactive security audit for Ubuntu and Debian hosts. It is read-only by default, favors low-noise findings, and checks listeners, firewall bypasses, SSH, accounts, persistence, Docker exposure and common miner/scanner indicators.

## Supported systems

Validated releases:

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

The audit auto-detects `vps`, `server`, `desktop` and `container` profiles. Other Ubuntu/Debian versions may run, but the report warns when they are outside the validated matrix.

## One-command run

```bash
curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash
```

The bootstrap downloads the audit to a temporary file, reads the language menu from `/dev/tty`, runs with root privileges, and removes the temporary file afterward. The launcher downloads its versioned audit modules automatically when they are not available locally.

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

It prints a report and saves TXT and JSON copies.

## Read-only behavior

The normal audit does not:

- install or remove packages
- edit SSH, sysctl or firewall settings
- change passwords or SSH keys
- enable, disable or restart services
- delete logs or files

By default it reads the existing APT cache and does **not** run `apt-get update`. The optional `--refresh-package-index` flag refreshes APT metadata and therefore writes under `/var/lib/apt/lists`.

`--rootkit-check` only launches `rkhunter` or `chkrootkit` when already installed.

## Major checks

- OS support, host profile and compact AppArmor status
- All-interface TCP/UDP listeners with IPv4/IPv6 deduplication
- Context-aware Avahi/mDNS and CUPS findings
- Public Docker API and common database ports
- UFW, firewalld, native nftables and iptables backends
- Direct `iptables ACCEPT` rules that may bypass UFW
- UFW allow rules with no matching active listener
- Baseline or strict SSH policy
- Fail2ban, CrowdSec and sshguard with dependency-aware scoring
- Debian 13 `wtmpdb` login-history support and journal fallback
- UID 0 accounts, empty password hashes, sudo and redacted SSH-key summaries
- Failed services, cron and systemd timers with bounded output
- APT index age, update counts, security updates, held packages and kernel/reboot state
- Kernel/network hardening values
- Sensitive permissions and host-only SUID/SGID inventory
- Docker published ports, privileged mode, host namespaces, capabilities and sensitive mounts
- Deleted executables and temporary executables while excluding the audit itself
- Common miner/scanner process names
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

Use the configuration file to mark trusted login IPs, intentional custom ports, the host profile, policy and output limit.

## Install system-wide

```bash
sudo ./install.sh
sudo vps-guard-audit
```

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | No warnings or failures |
| 1 | Warnings found |
| 2 | Failures found |
| 64 | Invalid option |
| 66 | Unreadable config |
| 69 | Required audit modules could not be downloaded |
| 77 | Root required |

A warning or failure exit code is an audit result, not a script crash. Do not append `exit $?` inside an active SSH shell.

## Security limitations

No shell script can prove that a host is clean or that an all-interface listener is reachable from the public Internet. Cloud firewalls, NAT, routers, Docker forwarding and kernel compromise can change the effective exposure. Unknown successful logins, unexpected UID 0 accounts, malicious processes or unexplained persistence should be treated seriously.

## Development

```bash
bash -n vps-guard-audit.sh bootstrap.sh install.sh lib/*.sh
shellcheck vps-guard-audit.sh bootstrap.sh install.sh lib/*.sh
```

GitHub Actions also performs a non-mutating JSON smoke test.

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT
