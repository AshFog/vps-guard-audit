#!/usr/bin/env bash
# shellcheck shell=bash
# 检查注册表：标题可以变化，稳定编号不得变化。

registry_lookup() {
  local legacy_id="$1"
  CHECK_LEGACY_ID="$legacy_id"
  CHECK_CATEGORY="其他"
  CHECK_REQUIRED_COMMANDS=""
  CHECK_PREREQUISITE="无"
  CHECK_RISK="info"
  CHECK_SOURCE="VPS Guard Audit"
  CHECK_DEPTH="quick"
  CHECK_APPLICABLE_SYSTEMS="Ubuntu,Debian"

  case "$legacy_id" in
    os.*) CHECK_ID="SYS-1001"; CHECK_CATEGORY="系统" ;;
    platform.systemd) CHECK_ID="SYS-1002"; CHECK_CATEGORY="系统"; CHECK_REQUIRED_COMMANDS="systemctl" ;;
    kernel.apparmor|apparmor.tool) CHECK_ID="SYS-1003"; CHECK_CATEGORY="系统"; CHECK_DEPTH="standard" ;;
    ports.tool|ports.none|ports.count) CHECK_ID="NET-2001"; CHECK_CATEGORY="网络"; CHECK_REQUIRED_COMMANDS="ss" ;;
    port.cups.*) CHECK_ID="NET-2002"; CHECK_CATEGORY="网络"; CHECK_REQUIRED_COMMANDS="ss" ;;
    port.docker_api.*) CHECK_ID="NET-2003"; CHECK_CATEGORY="网络"; CHECK_REQUIRED_COMMANDS="ss"; CHECK_RISK="high" ;;
    port.database.*) CHECK_ID="NET-2004"; CHECK_CATEGORY="网络"; CHECK_REQUIRED_COMMANDS="ss" ;;
    port.avahi) CHECK_ID="NET-2005"; CHECK_CATEGORY="网络"; CHECK_REQUIRED_COMMANDS="ss" ;;
    port.*) CHECK_ID="NET-2006"; CHECK_CATEGORY="网络"; CHECK_REQUIRED_COMMANDS="ss" ;;
    fw.none|fw.ufw.active|fw.ufw.absent) CHECK_ID="FW-3001"; CHECK_CATEGORY="防火墙"; CHECK_PREREQUISITE="主机网络可见"; CHECK_RISK="high" ;;
    fw.ufw.default) CHECK_ID="FW-3002"; CHECK_CATEGORY="防火墙"; CHECK_REQUIRED_COMMANDS="ufw" ;;
    fw.ufw.enabled) CHECK_ID="FW-3003"; CHECK_CATEGORY="防火墙"; CHECK_REQUIRED_COMMANDS="ufw,systemctl" ;;
    fw.ufw.stale) CHECK_ID="FW-3004"; CHECK_CATEGORY="防火墙"; CHECK_REQUIRED_COMMANDS="ufw,ss"; CHECK_DEPTH="standard" ;;
    fw.firewalld) CHECK_ID="FW-3005"; CHECK_CATEGORY="防火墙"; CHECK_REQUIRED_COMMANDS="firewall-cmd" ;;
    fw.nft.*) CHECK_ID="FW-3006"; CHECK_CATEGORY="防火墙"; CHECK_REQUIRED_COMMANDS="nft" ;;
    fw.iptables.*) CHECK_ID="FW-3007"; CHECK_CATEGORY="防火墙"; CHECK_REQUIRED_COMMANDS="iptables" ;;
    fw.pre_ufw_accept) CHECK_ID="FW-3008"; CHECK_CATEGORY="防火墙"; CHECK_REQUIRED_COMMANDS="iptables"; CHECK_DEPTH="standard" ;;
    ssh.password) CHECK_ID="SSH-4001"; CHECK_CATEGORY="SSH"; CHECK_REQUIRED_COMMANDS="sshd"; CHECK_RISK="high" ;;
    ssh.pubkey) CHECK_ID="SSH-4002"; CHECK_CATEGORY="SSH"; CHECK_REQUIRED_COMMANDS="sshd"; CHECK_RISK="high" ;;
    ssh.root) CHECK_ID="SSH-4003"; CHECK_CATEGORY="SSH"; CHECK_REQUIRED_COMMANDS="sshd"; CHECK_RISK="high" ;;
    ssh.empty) CHECK_ID="SSH-4004"; CHECK_CATEGORY="SSH"; CHECK_REQUIRED_COMMANDS="sshd"; CHECK_RISK="high" ;;
    ssh.tries) CHECK_ID="SSH-4005"; CHECK_CATEGORY="SSH"; CHECK_REQUIRED_COMMANDS="sshd" ;;
    ssh.x11|ssh.forward) CHECK_ID="SSH-4006"; CHECK_CATEGORY="SSH"; CHECK_REQUIRED_COMMANDS="sshd"; CHECK_DEPTH="standard" ;;
    ssh.syntax|ssh.missing) CHECK_ID="SSH-4007"; CHECK_CATEGORY="SSH"; CHECK_REQUIRED_COMMANDS="sshd"; CHECK_RISK="high" ;;
    f2b.*) CHECK_ID="SSH-4101"; CHECK_CATEGORY="SSH"; CHECK_PREREQUISITE="SSH 服务存在"; CHECK_DEPTH="standard" ;;
    users.uid0) CHECK_ID="USR-5001"; CHECK_CATEGORY="账户"; CHECK_RISK="high" ;;
    users.empty) CHECK_ID="USR-5002"; CHECK_CATEGORY="账户"; CHECK_RISK="high" ;;
    sudo.syntax|sudo.mode) CHECK_ID="USR-5003"; CHECK_CATEGORY="账户"; CHECK_REQUIRED_COMMANDS="visudo" ;;
    keys.*) CHECK_ID="USR-5004"; CHECK_CATEGORY="账户"; CHECK_DEPTH="standard" ;;
    login.*) CHECK_ID="USR-5005"; CHECK_CATEGORY="账户"; CHECK_PREREQUISITE="登录记录可读"; CHECK_DEPTH="standard" ;;
    systemd.failed) CHECK_ID="SYS-1101"; CHECK_CATEGORY="服务"; CHECK_REQUIRED_COMMANDS="systemctl" ;;
    cron.mode) CHECK_ID="SYS-1102"; CHECK_CATEGORY="持久化" ;;
    pkg.updates) CHECK_ID="PKG-6001"; CHECK_CATEGORY="软件包"; CHECK_REQUIRED_COMMANDS="apt" ;;
    pkg.security_source) CHECK_ID="PKG-6002"; CHECK_CATEGORY="软件包"; CHECK_REQUIRED_COMMANDS="apt" ;;
    pkg.unattended|pkg.unattended.config) CHECK_ID="PKG-6003"; CHECK_CATEGORY="软件包" ;;
    pkg.reboot|pkg.kernel_running) CHECK_ID="PKG-6004"; CHECK_CATEGORY="软件包" ;;
    pkg.dpkg|pkg.index|pkg.index.refresh|pkg.index.age|pkg.held) CHECK_ID="PKG-6005"; CHECK_CATEGORY="软件包"; CHECK_DEPTH="standard" ;;
    sysctl.*) CHECK_ID="SYS-1201"; CHECK_CATEGORY="内核"; CHECK_REQUIRED_COMMANDS="sysctl"; CHECK_DEPTH="standard" ;;
    coredump.*) CHECK_ID="SYS-1202"; CHECK_CATEGORY="内核"; CHECK_DEPTH="standard" ;;
    perm.*|world.*|suid.unusual) CHECK_ID="SYS-1301"; CHECK_CATEGORY="文件权限"; CHECK_DEPTH="deep" ;;
    docker.published) CHECK_ID="CTR-7001"; CHECK_CATEGORY="容器"; CHECK_REQUIRED_COMMANDS="docker"; CHECK_PREREQUISITE="Docker 正在运行" ;;
    docker.priv) CHECK_ID="CTR-7002"; CHECK_CATEGORY="容器"; CHECK_REQUIRED_COMMANDS="docker"; CHECK_DEPTH="standard" ;;
    docker.host_modes|docker.weak_isolation|docker.mounts) CHECK_ID="CTR-7003"; CHECK_CATEGORY="容器"; CHECK_REQUIRED_COMMANDS="docker"; CHECK_DEPTH="deep" ;;
    docker.*) CHECK_ID="CTR-7004"; CHECK_CATEGORY="容器"; CHECK_REQUIRED_COMMANDS="docker" ;;
    malware.tmp) CHECK_ID="MAL-8001"; CHECK_CATEGORY="可疑活动"; CHECK_DEPTH="deep"; CHECK_RISK="high" ;;
    malware.process) CHECK_ID="MAL-8002"; CHECK_CATEGORY="可疑活动"; CHECK_RISK="high" ;;
    malware.deleted) CHECK_ID="MAL-8003"; CHECK_CATEGORY="可疑活动"; CHECK_REQUIRED_COMMANDS="lsof"; CHECK_DEPTH="deep" ;;
    proxy.*) CHECK_ID="MAL-8101"; CHECK_CATEGORY="代理服务"; CHECK_DEPTH="standard" ;;
    rootkit.*) CHECK_ID="MAL-8201"; CHECK_CATEGORY="Rootkit"; CHECK_DEPTH="deep"; CHECK_PREREQUISITE="用户主动启用并已安装扫描器" ;;
    *) CHECK_ID="SYS-1999" ;;
  esac

  case "$CHECK_ID" in
    SYS-1001) CHECK_NAME="系统版本支持状态" ;;
    NET-2001) CHECK_NAME="全接口监听端口" ;;
    FW-3001) CHECK_NAME="防火墙运行状态" ;;
    SSH-4001) CHECK_NAME="SSH 密码登录" ;;
    USR-5001) CHECK_NAME="异常 UID 0 账户" ;;
    PKG-6001) CHECK_NAME="待安装安全更新" ;;
    CTR-7001) CHECK_NAME="Docker 对外发布端口" ;;
    MAL-8001) CHECK_NAME="临时目录可执行文件" ;;
    *) CHECK_NAME="${CHECK_CATEGORY}安全检查" ;;
  esac
}
