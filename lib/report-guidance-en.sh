#!/usr/bin/env bash
# shellcheck shell=bash

finding_plain_text_en() {
  local id="$1"
  case "$id" in
    os.*)
      PLAIN_MEANING="This operating system is outside the releases validated by the project, so some conclusions may be inaccurate."
      PLAIN_ACTION="Confirm the exact release and package sources. Ask a trusted AI assistant to re-check the report against this distribution before applying generic hardening."
      ;;
    platform.systemd)
      PLAIN_MEANING="The audit could not confirm that systemd is PID 1, so service and startup checks may be incomplete."
      PLAIN_ACTION="First determine whether the host is a container. On a normal host, inspect PID 1 and the boot environment."
      ;;
    kernel.apparmor)
      PLAIN_MEANING="AppArmor is not providing the expected application isolation. This is not evidence that the host is compromised."
      PLAIN_ACTION="Confirm whether the distribution normally uses AppArmor and whether important services have profiles. Test Docker, proxies, and production applications before enforcement."
      ;;
    port.docker_api.*)
      PLAIN_MEANING="The Docker management API listens on all interfaces. Unsafe exposure may allow control of containers or the host."
      PLAIN_ACTION="Restrict it to localhost or a trusted private network and verify mutual TLS. Preserve Docker configuration and the container inventory first."
      PLAIN_CAUTION="Changing Docker daemon settings may restart Docker and interrupt services."
      ;;
    port.cups.*|port.database.*|port.avahi|port.*)
      PLAIN_MEANING="The service is bound to all network interfaces. This does not prove public reachability; firewall, routing, and intended use still matter."
      PLAIN_ACTION="Confirm that you installed the program, then review UFW, nftables, provider firewall rules, and routing. Local-only services can often bind to 127.0.0.1."
      PLAIN_CAUTION="Do not close a port until you know it is not used by SSH, a proxy, website, database, or reverse proxy."
      ;;
    fw.none|fw.ufw.*|fw.pre_ufw_accept)
      PLAIN_MEANING="The host firewall is not in the expected state, or rules may bypass UFW."
      PLAIN_ACTION="Identify the real SSH port, existing rules, and their source before making individual changes. Do not reset UFW or flush iptables/nftables."
      PLAIN_CAUTION="A firewall mistake can immediately disconnect SSH. Keep the current session, test a second connection, and confirm console or rescue access."
      ;;
    ssh.password|ssh.pubkey|ssh.root|ssh.empty|ssh.syntax|ssh.missing)
      PLAIN_MEANING="A core SSH login setting requires prompt review, and an incorrect change may lock you out."
      PLAIN_ACTION="Back up the configuration and confirm key login first. Run sshd -t after changes and test from a second terminal."
      PLAIN_CAUTION="Do not remove the current login path without a working sudo user, second connection, and console access."
      ;;
    ssh.tries|ssh.x11|ssh.forward)
      PLAIN_MEANING="Some optional SSH features are looser than the selected policy. This is usually not evidence of compromise."
      PLAIN_ACTION="Decide based on actual use; SSH tunnels, remote graphics, and development tools may require these settings."
      ;;
    f2b.*)
      PLAIN_MEANING="Brute-force protection is not fully active. This is less urgent with key-only SSH, but may still reduce abusive connections and log noise."
      PLAIN_ACTION="Check systemctl status fail2ban --no-pager and journalctl -u fail2ban -n 50 --no-pager before repairing a jail or choosing another tool."
      ;;
    users.uid0|users.empty|sudo.syntax)
      PLAIN_MEANING="An account or sudo finding affects high privileges and requires confirmation of account ownership and configuration integrity."
      PLAIN_ACTION="Preserve /etc/passwd, /etc/shadow, sudoers, and logs. An unknown UID 0 account calls for isolation, credential rotation, and possible rebuild."
      ;;
    login.*)
      PLAIN_MEANING="A login source needs owner confirmation; the audit cannot know which IP addresses, terminals, and times belong to you."
      PLAIN_ACTION="Review every successful login. For an unknown login, restrict access, rotate passwords and SSH keys, and inspect persistence."
      ;;
    systemd.failed)
      PLAIN_MEANING="A service failed. It may be unused, or it may affect networking, protection, or the application."
      PLAIN_ACTION="Run systemctl --failed --no-pager, then inspect the service with systemctl status and journalctl."
      ;;
    cron.mode|world.*|perm.*|suid.unusual)
      PLAIN_MEANING="A sensitive file permission or location differs from the baseline and may allow local users to alter privileged configuration or programs."
      PLAIN_ACTION="Confirm the owner, package, purpose, and timestamps before the smallest necessary change. Preserve unfamiliar files before investigation."
      ;;
    pkg.dpkg|pkg.index|pkg.index.age|pkg.security_source|pkg.held)
      PLAIN_MEANING="The package manager, metadata, repository, or hold state needs review, so update conclusions may be incomplete."
      PLAIN_ACTION="Review the technical detail, network access, and official repositories. Do not run multiple apt/dpkg processes or remove all holds blindly."
      ;;
    pkg.updates|pkg.unattended)
      PLAIN_MEANING="Packages or security fixes remain pending, and automatic security updates may not be configured. Security counts are estimates from current APT metadata."
      PLAIN_ACTION="Review apt list --upgradable, then run apt update and apt upgrade in a backed-up maintenance window. Read the plan before adding -y."
      PLAIN_CAUTION="Upgrades may restart services; kernel updates normally require a reboot."
      ;;
    pkg.reboot|pkg.kernel_running)
      PLAIN_MEANING="Installed updates may require a reboot, or the host is still running an older kernel."
      PLAIN_ACTION="Confirm backups, service impact, and console access, then schedule a maintenance-window reboot and repeat the audit."
      PLAIN_CAUTION="A reboot disconnects SSH and interrupts services."
      ;;
    sysctl.*)
      PLAIN_MEANING="A kernel or network value is looser than the general baseline, but routing, containers, debugging, or desktop roles may intentionally differ."
      PLAIN_ACTION="Do not paste a complete generic sysctl template. Give the full report and host role to a trusted AI assistant and request only applicable changes with backup, verification, and rollback."
      ;;
    docker.published)
      PLAIN_MEANING="Docker publishes a container port on all interfaces, and UFW INPUT rules alone do not prove that it is blocked."
      PLAIN_ACTION="Use docker ps and docker inspect to confirm its purpose. A local reverse-proxy backend can often bind to 127.0.0.1."
      PLAIN_CAUTION="Changing port mappings normally recreates or restarts the container."
      ;;
    docker.priv|docker.host_modes|docker.weak_isolation|docker.mounts)
      PLAIN_MEANING="A container has strong host privileges or sensitive resource access, weakening isolation."
      PLAIN_ACTION="Preserve compose and inspect output, then confirm whether privileged mode, host namespaces, capabilities, or mounts are necessary."
      PLAIN_CAUTION="Reducing permissions may stop the application; use a rollback-ready maintenance window."
      ;;
    malware.process|malware.deleted|malware.tmp)
      PLAIN_MEANING="A suspicious process name, temporary executable, or deleted file still in use was found. It may be a normal upgrade artifact or require investigation."
      PLAIN_ACTION="Preserve process, network, hashes, and timestamps. For unknown activity, restrict access, rotate credentials, and consider rebuilding from trusted images."
      ;;
    proxy.*)
      PLAIN_MEANING="A proxy, VPN, or risky helper script needs confirmation as an intentional installation."
      PLAIN_ACTION="Review the service, installation source, configuration directory, and listening ports; an unknown proxy may alter traffic paths."
      ;;
    rootkit.*)
      PLAIN_MEANING="An optional rootkit scanner returned warnings or errors. These tools are noisy and cannot prove compromise by themselves."
      PLAIN_ACTION="Preserve the complete output and correlate it with processes, kernel modules, file integrity, and login history."
      ;;
    *)
      PLAIN_MEANING="This check differs from a common security baseline and needs context about the host's role."
      [[ -n "$PLAIN_ACTION" ]] || PLAIN_ACTION="Review the technical evidence and submit the full TXT report to a trusted AI assistant for risk, backup, remediation, verification, and rollback guidance."
      ;;
  esac
}
