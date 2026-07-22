#!/usr/bin/env bash
# shellcheck shell=bash

finding_plain_text_zh() {
  local id="$1"
  case "$id" in
    os.*)
      PLAIN_MEANING="当前系统不在项目已经验证的范围内，因此部分判断可能不够准确。"
      PLAIN_ACTION="确认系统版本和软件源。不要直接照搬通用加固命令，可把完整报告交给可信 AI，要求它按当前发行版重新核对。" ;;
    platform.systemd)
      PLAIN_MEANING="脚本没有确认 systemd 正常作为系统的第一个进程运行，服务和启动项检查可能不完整。"
      PLAIN_ACTION="先确认机器是否运行在容器中；普通主机则应检查 PID 1 和启动方式。" ;;
    kernel.apparmor)
      PLAIN_MEANING="AppArmor 没有提供预期的程序隔离保护。这不代表系统已经被入侵。"
      PLAIN_ACTION="确认发行版是否默认使用 AppArmor，以及关键服务是否已有规则；启用前先测试 Docker、代理和业务程序。" ;;
    port.docker_api.*)
      PLAIN_MEANING="Docker 管理接口监听了全部网络接口，错误暴露可能让外部人员控制容器甚至宿主机。"
      PLAIN_ACTION="优先限制为本机或可信私网访问，并确认双向 TLS。处理前保存 Docker 配置和容器清单。"
      PLAIN_CAUTION="修改 Docker 启动参数可能重启 Docker 并中断业务。" ;;
    port.cups.*|port.database.*|port.avahi|port.*)
      PLAIN_MEANING="服务绑定到了全部网络接口，但这不等于一定能从公网访问；仍需结合防火墙、路由和服务用途判断。"
      PLAIN_ACTION="确认程序是否由你主动部署，再检查 UFW、nftables、云防火墙和路由。只供本机使用时，可考虑绑定 127.0.0.1。"
      PLAIN_CAUTION="关闭端口前先确认它不是 SSH、代理、网站、数据库或反向代理正在使用的端口。" ;;
    fw.none|fw.ufw.*|fw.pre_ufw_accept)
      PLAIN_MEANING="主机防火墙没有达到推荐状态，或存在可能绕过 UFW 的规则。"
      PLAIN_ACTION="先确认真实 SSH 端口、现有规则和规则来源，再逐项调整。不要重置 UFW，也不要清空 iptables/nftables。"
      PLAIN_CAUTION="防火墙配置错误可能立即断开 SSH；保持当前会话，测试第二个连接，并确认控制台或救援模式可用。" ;;
    ssh.password|ssh.pubkey|ssh.root|ssh.empty|ssh.syntax|ssh.missing)
      PLAIN_MEANING="SSH 的基础登录配置需要尽快核对，错误修改可能影响安全或导致无法登录。"
      PLAIN_ACTION="先备份配置并确认密钥登录可用。修改后运行 sshd -t，并在第二个终端测试连接。"
      PLAIN_CAUTION="不要在没有备用 sudo 用户、第二个连接和控制台访问时关闭当前登录方式。" ;;
    ssh.tries|ssh.x11|ssh.forward)
      PLAIN_MEANING="部分 SSH 可选功能比当前策略更宽松，通常不是入侵迹象。"
      PLAIN_ACTION="根据实际用途判断；SSH 隧道、远程图形和开发工具可能需要这些设置。" ;;
    f2b.*)
      PLAIN_MEANING="暴力破解防护没有完整运行。SSH 已关闭密码登录时通常不紧急，但仍会增加无效连接和日志噪声。"
      PLAIN_ACTION="先查看 systemctl status fail2ban --no-pager 和 journalctl -u fail2ban -n 50 --no-pager，再决定修复 jail 或改用其他工具。" ;;
    users.uid0|users.empty|sudo.syntax)
      PLAIN_MEANING="账户或 sudo 配置存在高权限风险，需要确认账户来源和配置完整性。"
      PLAIN_ACTION="先保存 /etc/passwd、/etc/shadow、sudoers 和相关日志。发现陌生 UID 0 账户时应隔离服务器、轮换凭据并考虑重建。" ;;
    login.*)
      PLAIN_MEANING="登录来源需要你本人确认，脚本无法知道哪些 IP、终端和时间属于正常操作。"
      PLAIN_ACTION="逐条核对成功登录。发现陌生成功登录时，应限制外部访问、轮换密码和 SSH 密钥，并检查持久化项目。" ;;
    systemd.failed)
      PLAIN_MEANING="有服务启动失败，可能是旧服务，也可能影响网络、防护或业务。"
      PLAIN_ACTION="先运行 systemctl --failed --no-pager，再查看对应服务的 systemctl status 和 journalctl 日志。" ;;
    cron.mode|world.*|perm.*|suid.unusual)
      PLAIN_MEANING="关键文件的权限或位置与安全基线不同，可能允许本地账户修改高权限配置或程序。"
      PLAIN_ACTION="先确认文件所有者、所属软件包、用途和创建时间，再进行最小化修改；陌生文件先备份调查，不要直接删除。" ;;
    pkg.dpkg|pkg.index|pkg.index.age|pkg.security_source|pkg.held)
      PLAIN_MEANING="软件包管理器、索引或更新源需要检查，当前更新判断可能不完整。"
      PLAIN_ACTION="查看本项技术细节，确认网络和官方软件源；不要同时运行多个 apt/dpkg 进程，也不要盲目解除全部 hold。" ;;
    pkg.updates|pkg.unattended)
      PLAIN_MEANING="系统还有软件包或安全更新需要处理，自动安全更新也可能未配置。安全更新数量是根据当前 APT 信息估算的。"
      PLAIN_ACTION="先查看 apt list --upgradable，在有备份的维护时间运行 apt update 和 apt upgrade；先阅读计划，不要一开始就添加 -y。"
      PLAIN_CAUTION="升级可能重启服务；内核更新通常需要重启。" ;;
    pkg.reboot|pkg.kernel_running)
      PLAIN_MEANING="已安装更新可能需要重启才能生效，或当前仍在运行旧内核。"
      PLAIN_ACTION="确认备份、业务影响和控制台访问后安排维护窗口重启，重启后重新审计。"
      PLAIN_CAUTION="重启会断开 SSH 并中断服务。" ;;
    sysctl.*)
      PLAIN_MEANING="内核或网络设置比脚本采用的通用基线更宽松，但路由、容器、调试或桌面用途可能故意使用不同值。"
      PLAIN_ACTION="不要复制整套 sysctl 模板。把完整报告和服务器用途交给可信 AI，只调整确实适用的项目，并要求备份、验证和回滚步骤。" ;;
    docker.published)
      PLAIN_MEANING="Docker 把容器端口发布到了全部接口，UFW 的 INPUT 规则不能单独证明端口已被阻止。"
      PLAIN_ACTION="用 docker ps 和 docker inspect 确认用途；仅供本机反向代理时可考虑绑定 127.0.0.1。"
      PLAIN_CAUTION="修改端口映射通常需要重建或重启容器。" ;;
    docker.priv|docker.host_modes|docker.weak_isolation|docker.mounts)
      PLAIN_MEANING="容器获得了较强宿主机权限或敏感资源访问，隔离能力被削弱。"
      PLAIN_ACTION="保存 compose 和 inspect 输出，再逐项确认 privileged、host namespace、capability 或挂载是否必要。"
      PLAIN_CAUTION="减少权限可能让应用无法启动，应在可回滚的维护窗口处理。" ;;
    malware.process|malware.deleted|malware.tmp)
      PLAIN_MEANING="发现可疑进程名称、临时可执行文件，或已删除但仍在使用的文件；可能是正常升级，也可能需要调查。"
      PLAIN_ACTION="先保存进程、网络、文件哈希和时间信息。来源不明时限制外部访问、轮换凭据，并考虑从可信镜像重建。" ;;
    proxy.*)
      PLAIN_MEANING="检测到代理、VPN 或高风险辅助脚本，需要确认是否由你主动安装。"
      PLAIN_ACTION="核对服务名称、安装来源、配置目录和监听端口；陌生代理可能改变网络流量路径。" ;;
    rootkit.*)
      PLAIN_MEANING="可选 Rootkit 扫描器返回警告或执行异常，但这类工具误报较多，不能单独证明系统已被入侵。"
      PLAIN_ACTION="保存完整输出，并结合进程、内核模块、文件完整性和登录记录继续分析。" ;;
    *)
      PLAIN_MEANING="这项检查与常见安全基线不同，需要结合服务器用途判断。"
      [[ -n "$PLAIN_ACTION" ]] || PLAIN_ACTION="查看上方技术细节，并把完整 TXT 报告提交给可信 AI，要求给出风险、备份、修复、验证和回滚步骤。" ;;
  esac
}
