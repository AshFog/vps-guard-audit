# VPS Guard Audit

面向 VPS 新手的双语、交互式、只读安全审计工具。它帮助发现错误配置、弱 SSH 设置、异常账户、陌生登录、暴露端口、防火墙绕过、危险持久化以及常见挖矿木马特征。

A bilingual, interactive, read-only VPS security audit for beginners. It checks exposed services, firewall bypasses, SSH hardening, unexpected accounts, persistence, unsafe permissions and common miner/scanner indicators.

## Supported systems

Validated releases:

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

Other Ubuntu/Debian versions may run, but the report warns when they are outside the validated matrix.

## One-command run

```bash
curl -fsSL https://raw.githubusercontent.com/AshFog/vps-guard-audit/main/bootstrap.sh | bash
```

The bootstrap downloads the audit to a temporary file, reads the interactive language choice from `/dev/tty`, runs with root privileges, and removes the temporary file afterward.

For higher assurance, use a release tag or commit SHA instead of the moving `main` branch.

## Local run

```bash
git clone https://github.com/AshFog/vps-guard-audit.git
cd vps-guard-audit
sudo ./vps-guard-audit.sh
```

The script first asks:

```text
1) 中文
2) English
```

It prints a detailed report and saves TXT and JSON copies.

## Safe by design

The normal audit does not:

- install or remove packages
- edit SSH or sysctl settings
- add or delete firewall rules
- change passwords or SSH keys
- enable or disable services
- delete logs or files

`--rootkit-check` only launches `rkhunter` or `chkrootkit` when already installed.

## Major checks

- OS support and AppArmor
- Public TCP/UDP listeners, including wildcard IPv4 and IPv6 bindings
- Public CUPS, Docker API and common database ports
- UFW status, boot enablement and default-deny policy
- Direct `iptables ACCEPT` rules that may bypass UFW
- UFW rules with no matching active public listener
- SSH password, key, root-login, forwarding and retry settings
- Fail2ban status with compact output
- UID 0 accounts, empty password hashes, sudo and SSH key fingerprints
- Successful and failed login history
- Enabled services, failed units, cron and systemd timers
- Pending package updates and unattended-upgrades
- Kernel/network hardening values
- Sensitive permissions, world-writable files and SUID/SGID inventory
- Docker privileged containers and host networking
- Deleted executables still in use
- Recent executable files in temporary directories
- Common miner/scanner process names
- Proxy/VPN services and risky helper scripts
- Optional existing rootkit scanners

## Install system-wide

```bash
sudo ./install.sh
sudo vps-guard-audit
```

## Options

```text
--lang zh|en
--output-dir DIR
--format text|json|both
--config FILE
--login-lines N
--no-update-check
--rootkit-check
--quiet
-h, --help
-v, --version
```

## Optional configuration

```bash
cp config/audit.conf.example config/audit.conf
nano config/audit.conf
sudo ./vps-guard-audit.sh --config config/audit.conf
```

Use the configuration file to mark trusted login IPs and intentionally exposed custom ports.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | No warnings or failures |
| 1 | Warnings found |
| 2 | Failures found |
| 64 | Invalid option |
| 66 | Unreadable config |
| 77 | Root required |

A warning or failure exit code is an audit result, not a script crash. Do not append `exit $?` when running it inside an active SSH shell.

## Security limitations

No shell script can prove that a server is clean. A sophisticated attacker may hide processes, alter logs or compromise the kernel. Unknown successful logins, unexpected UID 0 accounts, malicious processes or unexplained persistence should be treated seriously: isolate the VPS, rotate credentials from a clean device and consider rebuilding from a trusted image.

## Development

```bash
bash -n vps-guard-audit.sh bootstrap.sh install.sh
shellcheck vps-guard-audit.sh bootstrap.sh install.sh
```

See [CHANGELOG.md](CHANGELOG.md) for release notes.

## License

MIT
