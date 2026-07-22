# VPS Guard Audit

面向 VPS 新手的双语、交互式、只读安全审计工具。目标是帮助普通用户尽早发现错误配置、弱 SSH 设置、异常账户、陌生登录、暴露端口、危险持久化和常见挖矿木马特征，降低 VPS 被滥用为“肉鸡”的风险。

A bilingual, interactive, read-only VPS security audit for beginners. It helps detect weak SSH settings, unexpected accounts, unfamiliar logins, exposed ports, persistence, unsafe permissions and common miner/scanner indicators.

## Supported systems

Validated releases:

- Ubuntu 26.04 LTS
- Ubuntu 24.04 LTS
- Ubuntu 22.04 LTS
- Debian 13
- Debian 12
- Debian 11

Other Ubuntu/Debian versions may run, but the report will clearly warn that they are outside the validated support matrix.

## One-command experience

```bash
sudo ./vps-guard-audit.sh
```

The script first asks:

```text
1) 中文
2) English
```

It then runs the full read-only audit, prints a detailed report in the selected language, and shows the saved TXT and JSON report paths.

## Safe by design

The script does not:

- install or remove packages
- edit SSH
- add or delete firewall rules
- change passwords or keys
- enable or disable services
- delete logs or files
- apply sysctl settings

The normal run is inspection-only. `--rootkit-check` only launches `rkhunter` or `chkrootkit` when they are already installed.

## Checks

- Operating-system support and AppArmor
- Public TCP/UDP listeners
- UFW and iptables default policies
- SSH key/password/root-login security
- Fail2ban status
- UID 0 accounts, empty password hashes and sudo
- SSH key fingerprints and permissions
- Successful and failed login history
- Enabled services, cron and systemd timers
- Pending package updates and unattended-upgrades
- Kernel/network hardening values
- Sensitive file permissions and world-writable files
- SUID/SGID inventory
- Docker privileged containers and host networking
- Deleted executables still in use
- Recent executable files in `/tmp`, `/var/tmp`, `/dev/shm`
- Common miner/scanner process names
- Proxy/VPN services and risky helper scripts
- Optional existing rootkit scanners

## Install

```bash
git clone https://github.com/YOUR_NAME/vps-guard-audit.git
cd vps-guard-audit
sudo ./install.sh
sudo vps-guard-audit
```

## Direct download

For real deployments, pin a release tag or commit SHA rather than a moving main branch.

```bash
curl -fsSLo vps-guard-audit.sh \
  https://raw.githubusercontent.com/YOUR_NAME/vps-guard-audit/main/vps-guard-audit.sh

chmod +x vps-guard-audit.sh
sudo ./vps-guard-audit.sh
```

## Optional configuration

```bash
cp config/audit.conf.example config/audit.conf
nano config/audit.conf
sudo ./vps-guard-audit.sh --config config/audit.conf
```

Configuration is optional and contains no personal defaults.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | No warnings or failures |
| 1 | Warnings found |
| 2 | Failures found |
| 64 | Invalid option |
| 66 | Unreadable config |
| 77 | Root required |

## Security limitations

A script cannot prove that a server is clean. A sophisticated attacker may hide processes, alter logs or compromise the kernel. Unknown successful logins, unexpected UID 0 accounts, malicious processes or unexplained persistence should be treated seriously: isolate the VPS, rotate credentials from a clean device and consider rebuilding from a trusted image.

## Development

```bash
bash -n vps-guard-audit.sh
shellcheck vps-guard-audit.sh install.sh
```

## License

MIT
