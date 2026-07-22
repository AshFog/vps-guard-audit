# Supported OS matrix

| Distribution | Version | Status |
|---|---:|---|
| Ubuntu | 26.04 LTS | Validated |
| Ubuntu | 24.04 LTS | Validated |
| Ubuntu | 22.04 LTS | Validated |
| Debian | 13 | Validated, including `wtmpdb` login history |
| Debian | 12 | Validated |
| Debian | 11 | Validated |

The script may run on other systemd-based Ubuntu/Debian releases, but emits an explicit warning.

## Host profiles

The default `auto` profile uses virtualization and chassis information to choose one of:

- `vps`
- `server`
- `desktop`
- `container`

Profile selection changes context-sensitive findings such as Avahi/mDNS, CUPS and SSH X11 forwarding. It does not modify the system.

## Firewall backends

The audit understands UFW, firewalld, native nftables and iptables/iptables-nft. Docker networking is evaluated separately because published container ports may traverse forwarding chains rather than the host `INPUT` chain.
