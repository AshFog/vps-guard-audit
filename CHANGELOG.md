# Changelog

## 4.4.0 — 2026-07-22

Report bundle, stronger AI redaction, history comparison, and management-command release.

### Added

- Timestamped audit bundles using `vpsga-YYYYMMDD-HHMMSS` as the shared base name.
- A complete `*-full.txt` report.
- A stronger `*-ai.txt` redacted report for submission to trusted AI assistants.
- Automatic comparison with the previous audit, showing new, resolved, and severity-changed findings.
- Up to 30 compact history state files under `/var/lib/vps-guard-audit/history/`.
- `--no-history` for audits that should not read or save comparison state.
- `vpsga doctor`, `vpsga update`, and `vpsga uninstall` management commands.
- CI coverage for report bundles, history comparison, system installation, and manager commands.

### Changed

- Report names no longer contain the hostname or language; the generation timestamp identifies the matching bundle.
- The AI guidance now tells users to prefer the `*-ai.txt` report over the complete report.
- The system installer now includes the report manager and report-output module.
- README introduction and documentation were simplified in both Chinese and English.
- The earlier HTML report and local viewer commands were removed before the v4.4 release because they added little value for typical SSH-based VPS use.

### Security

- The AI report maps or removes some hostnames, usernames, container names, domains, IPv4 addresses, email addresses, MAC addresses, and SSH fingerprints.
- Automatic redaction remains best-effort, and reports must still be reviewed before sharing.

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
