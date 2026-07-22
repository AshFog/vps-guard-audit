# Changelog

## 4.1.0 — 2026-07-22

Field-tested hardening release based on a real Ubuntu 24.04 VPS audit.

### Fixed

- Correctly detects public listeners bound to `0.0.0.0`, `*`, and `[::]`.
- No longer reports “no public listeners” when `ss` clearly shows exposed services.
- Limits Fail2ban output to summary data and at most 20 sample banned IPs.
- Adds a `/dev/tty`-safe bootstrap command so the language menu works without `/dev/fd`.

### Added

- High-risk detection for public CUPS (`631/tcp`) and Docker API (`2375/2376`).
- Review warnings for publicly exposed database and data-service ports.
- Detection of direct `iptables ACCEPT` rules placed before UFW chains.
- Detection of UFW allow rules with no corresponding active public listener.
- UFW boot-enable check.
- Public-listener count in the final findings.

### Documentation

- Replaced placeholder repository URLs with `AshFog/vps-guard-audit`.
- Added safer one-command usage and release notes.
