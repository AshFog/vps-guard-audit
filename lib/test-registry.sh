#!/usr/bin/env bash
# shellcheck shell=bash

# 测试注册表不会决定检测结果，只为每个稳定检查 ID 补充分类、编号、
# 最低检测模式、可信度和适用性元数据。现有语义 ID 继续保留，避免破坏历史比较。

mode_rank() {
  case "$1" in
    quick) printf '1' ;;
    standard) printf '2' ;;
    deep) printf '3' ;;
    *) printf '0' ;;
  esac
}

mode_enabled() {
  local required="${1:-quick}"
  (( $(mode_rank "$MODE") >= $(mode_rank "$required") ))
}

registry_lookup() {
  local id="$1" suffix=""
  TEST_CODE="GEN-0000"
  TEST_CATEGORY="其他"
  TEST_REQUIRED_MODE="quick"
  TEST_CONFIDENCE="confirmed"
  TEST_APPLICABILITY="applicable"

  case "$id" in
    os.*) TEST_CODE="SYS-1001"; TEST_CATEGORY="系统支持" ;;
    platform.systemd) TEST_CODE="SYS-1002"; TEST_CATEGORY="系统启动" ;;
    kernel.apparmor|apparmor.tool) TEST_CODE="SYS-1003"; TEST_CATEGORY="强制访问控制" ;;
    ports.tool|ports.none|ports.count) TEST_CODE="NET-2001"; TEST_CATEGORY="监听端口" ;;
    port.cups.*) suffix="${id##*.}"; TEST_CODE="NET-2101:$suffix"; TEST_CATEGORY="监听端口" ;;
    port.docker_api.*) suffix="${id##*.}"; TEST_CODE="NET-2102:$suffix"; TEST_CATEGORY="监听端口" ;;
    port.database.*) suffix="${id##*.}"; TEST_CODE="NET-2103:$suffix"; TEST_CATEGORY="监听端口" ;;
    port.avahi) TEST_CODE="NET-2104"; TEST_CATEGORY="监听端口" ;;
    port.*) TEST_CODE="NET-2199:${id#port.}"; TEST_CATEGORY="监听端口"; TEST_CONFIDENCE="requires_owner" ;;
    fw.ufw.*) TEST_CODE="FW-3001:${id#fw.ufw.}"; TEST_CATEGORY="防火墙" ;;
    fw.nft.*|fw.nft*) TEST_CODE="FW-3002:${id#fw.}"; TEST_CATEGORY="防火墙" ;;
    fw.iptables.*|fw.pre_ufw_accept) TEST_CODE="FW-3003:${id#fw.}"; TEST_CATEGORY="防火墙" ;;
    fw.firewalld|fw.none) TEST_CODE="FW-3099:${id#fw.}"; TEST_CATEGORY="防火墙" ;;
    ssh.password) TEST_CODE="SSH-4001"; TEST_CATEGORY="SSH" ;;
    ssh.pubkey) TEST_CODE="SSH-4002"; TEST_CATEGORY="SSH" ;;
    ssh.root) TEST_CODE="SSH-4003"; TEST_CATEGORY="SSH" ;;
    ssh.empty) TEST_CODE="SSH-4004"; TEST_CATEGORY="SSH" ;;
    ssh.tries) TEST_CODE="SSH-4005"; TEST_CATEGORY="SSH" ;;
    ssh.x11) TEST_CODE="SSH-4006"; TEST_CATEGORY="SSH" ;;
    ssh.forward) TEST_CODE="SSH-4007"; TEST_CATEGORY="SSH" ;;
    ssh.syntax|ssh.missing) TEST_CODE="SSH-4008"; TEST_CATEGORY="SSH" ;;
    f2b.*) TEST_CODE="SSH-4100:${id#f2b.}"; TEST_CATEGORY="暴力破解防护" ;;
    users.uid0) TEST_CODE="ACC-5001"; TEST_CATEGORY="账户" ;;
    users.empty) TEST_CODE="ACC-5002"; TEST_CATEGORY="账户" ;;
    sudo.syntax) TEST_CODE="ACC-5003"; TEST_CATEGORY="账户" ;;
    keys.*) TEST_CODE="ACC-5100:${id#keys.}"; TEST_CATEGORY="SSH 密钥" ;;
    login.*) TEST_CODE="ACC-5200:${id#login.}"; TEST_CATEGORY="登录记录"; TEST_CONFIDENCE="requires_owner" ;;
    systemd.failed) TEST_CODE="SVC-6001"; TEST_CATEGORY="服务" ;;
    cron.*) TEST_CODE="SVC-6100:${id#cron.}"; TEST_CATEGORY="计划任务" ;;
    pkg.*) TEST_CODE="PKG-7000:${id#pkg.}"; TEST_CATEGORY="软件更新" ;;
    sysctl.*) TEST_CODE="KRN-8000:${id#sysctl.}"; TEST_CATEGORY="内核加固" ;;
    perm.*|world.*|suid.*) TEST_CODE="FIL-9000:${id%%.*}"; TEST_CATEGORY="文件权限" ;;
    docker.*) TEST_CODE="CTR-1000:${id#docker.}"; TEST_CATEGORY="容器"; TEST_REQUIRED_MODE="standard" ;;
    malware.*) TEST_CODE="MAL-1100:${id#malware.}"; TEST_CATEGORY="可疑活动"; TEST_REQUIRED_MODE="standard" ;;
    proxy.*) TEST_CODE="NET-2200:${id#proxy.}"; TEST_CATEGORY="代理与 VPN"; TEST_REQUIRED_MODE="standard"; TEST_CONFIDENCE="requires_owner" ;;
    rootkit.*) TEST_CODE="MAL-1200:${id#rootkit.}"; TEST_CATEGORY="Rootkit 扫描"; TEST_REQUIRED_MODE="deep" ;;
    deep.auditd) TEST_CODE="DEP-1201"; TEST_CATEGORY="审计日志"; TEST_REQUIRED_MODE="deep" ;;
    deep.systemd_security) TEST_CODE="DEP-1202"; TEST_CATEGORY="服务隔离"; TEST_REQUIRED_MODE="deep" ;;
    deep.cert_expiry*) TEST_CODE="DEP-1203"; TEST_CATEGORY="TLS 证书"; TEST_REQUIRED_MODE="deep" ;;
    deep.tmp_mount*) TEST_CODE="DEP-1204"; TEST_CATEGORY="文件系统"; TEST_REQUIRED_MODE="deep" ;;
    deep.integrity) TEST_CODE="DEP-1205"; TEST_CATEGORY="文件完整性"; TEST_REQUIRED_MODE="deep" ;;
    deep.compiler) TEST_CODE="DEP-1206"; TEST_CATEGORY="开发工具"; TEST_REQUIRED_MODE="deep"; TEST_CONFIDENCE="informational" ;;
    deep.entropy) TEST_CODE="DEP-1207"; TEST_CATEGORY="随机数"; TEST_REQUIRED_MODE="deep" ;;
    mode.quick.*) TEST_CODE="RUN-0001"; TEST_CATEGORY="检测模式"; TEST_APPLICABILITY="not_run_in_quick_mode" ;;
    *) TEST_CODE="GEN:${id}" ;;
  esac
}
