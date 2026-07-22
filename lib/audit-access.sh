#!/usr/bin/env bash
# shellcheck shell=bash

audit_access() {
    section "$(t ssh)"
    SSH_PASSWORD_DISABLED=0
    if have sshd; then
      SSHD="$(sshd -T 2>/dev/null || true)"
      echo "$SSHD" | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|maxauthtries|maxstartups|maxsessions|logingracetime|x11forwarding|allowtcpforwarding|allowagentforwarding|gatewayports|permittunnel|permituserenvironment|permitemptypasswords|authenticationmethods|allowusers|allowgroups)' || true
      sshval() { awk -v k="$1" '$1==k {print $2; exit}' <<<"$SSHD"; }
      if [[ "$(sshval passwordauthentication)" == no && "$(sshval kbdinteractiveauthentication)" == no ]]; then
        record PASS ssh.password "SSH 密码和交互式登录已关闭" "SSH password and keyboard-interactive authentication are disabled"
        SSH_PASSWORD_DISABLED=1
      else
        record FAIL ssh.password "SSH 密码或交互式登录仍然开启" "SSH password or keyboard-interactive authentication is enabled" "" \
          "先确认密钥登录可用，再关闭 PasswordAuthentication 与 KbdInteractiveAuthentication。" \
          "Verify key login first, then disable PasswordAuthentication and KbdInteractiveAuthentication."
      fi
      [[ "$(sshval pubkeyauthentication)" == yes ]] \
        && record PASS ssh.pubkey "SSH 公钥登录已启用" "SSH public-key authentication is enabled" \
        || record FAIL ssh.pubkey "SSH 公钥登录未启用" "SSH public-key authentication is disabled"
      case "$(sshval permitrootlogin)" in
        no) record PASS ssh.root "root SSH 登录已关闭" "Root SSH login is disabled" ;;
        prohibit-password|without-password)
          if [[ "$POLICY" == strict ]]; then
            record WARN ssh.root "root 仍可通过公钥登录" "Root SSH public-key login is still allowed" "" \
              "普通用户 sudo 可用后，可在严格策略下设置 PermitRootLogin no。" "Under strict policy, set PermitRootLogin no after sudo access is verified."
          else
            record INFO ssh.root "root 仅允许通过公钥登录" "Root login is restricted to public keys"
          fi ;;
        *) record FAIL ssh.root "root SSH 登录策略过于宽松" "Root SSH login is broadly allowed" ;;
      esac
      [[ "$(sshval permitemptypasswords)" == no ]] \
        && record PASS ssh.empty "SSH 禁止空密码" "Empty SSH passwords are forbidden" \
        || record FAIL ssh.empty "SSH 可能允许空密码" "Empty SSH passwords may be allowed"
      tries="$(sshval maxauthtries)"
      if [[ "$tries" =~ ^[0-9]+$ ]]; then
        if [[ "$POLICY" == strict && "$tries" -gt 3 ]]; then
          record WARN ssh.tries "严格策略下 SSH 最大尝试次数偏高" "SSH MaxAuthTries exceeds the strict-policy recommendation" "$tries"
        elif [[ "$tries" -le 6 ]]; then
          record PASS ssh.tries "SSH 最大尝试次数处于合理基线" "SSH MaxAuthTries is within the baseline" "$tries"
        else
          record WARN ssh.tries "SSH 最大尝试次数偏高" "SSH MaxAuthTries may be too high" "$tries"
        fi
      else
        record WARN ssh.tries "无法读取 SSH 最大尝试次数" "Unable to read SSH MaxAuthTries"
      fi
      if [[ "$(sshval x11forwarding)" == no ]]; then
        record PASS ssh.x11 "SSH X11 转发已关闭" "SSH X11 forwarding is disabled"
      elif [[ "$HOST_PROFILE" == desktop && "$POLICY" == baseline ]]; then
        record INFO ssh.x11 "桌面配置启用了 SSH X11 转发" "SSH X11 forwarding is enabled on a desktop profile"
      else
        record WARN ssh.x11 "SSH X11 转发已开启" "SSH X11 forwarding is enabled"
      fi
      if [[ "$(sshval allowtcpforwarding)" == no ]]; then
        record PASS ssh.forward "SSH TCP 转发已关闭" "SSH TCP forwarding is disabled"
      elif [[ "$POLICY" == strict ]]; then
        record WARN ssh.forward "严格策略下 SSH TCP 转发已开启" "SSH TCP forwarding is enabled under strict policy"
      else
        record INFO ssh.forward "SSH TCP 转发已开启，请确认用途" "SSH TCP forwarding is enabled; confirm it is intentional"
      fi
      sshd -t 2>/dev/null \
        && record PASS ssh.syntax "sshd 配置语法正确" "sshd configuration syntax is valid" \
        || record FAIL ssh.syntax "sshd 配置语法错误" "sshd configuration syntax is invalid"
    else
      record FAIL ssh.missing "未找到 sshd" "sshd binary not found"
    fi

    section "$(t f2b)"
    F2B_FAILURE_RECORDED=0
    alternative_guard=""
    systemctl is-active --quiet crowdsec 2>/dev/null && alternative_guard="CrowdSec"
    systemctl is-active --quiet sshguard 2>/dev/null && alternative_guard="${alternative_guard:+$alternative_guard, }sshguard"
    if systemctl cat fail2ban.service >/dev/null 2>&1 || have fail2ban-client; then
      systemctl is-enabled --quiet fail2ban 2>/dev/null \
        && record PASS f2b.enabled "Fail2ban 已设置开机启动" "Fail2ban is enabled at boot" \
        || record WARN f2b.enabled "Fail2ban 未设置开机启动" "Fail2ban is not enabled at boot"
      if systemctl is-active --quiet fail2ban 2>/dev/null; then
        record PASS f2b.active "Fail2ban 正在运行" "Fail2ban is active"
        F2B_STATUS="$(fail2ban-client status 2>/dev/null || true)"
        echo "$F2B_STATUS"
        if grep -q 'Jail list:.*sshd' <<<"$F2B_STATUS"; then
          SSHD_JAIL="$(fail2ban-client status sshd 2>/dev/null || true)"
          echo "$SSHD_JAIL" | grep -v 'Banned IP list:' || true
          banned_count="$(awk -F: '/Currently banned:/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' <<<"$SSHD_JAIL")"
          banned_ips="$(sed -n 's/.*Banned IP list:[[:space:]]*//p' <<<"$SSHD_JAIL")"
          sample="$(tr ' ' '\n' <<<"$banned_ips" | sed '/^$/d' | head -n 20 | xargs)"
          [[ -n "$banned_count" ]] && echo "已封禁 IP 示例（共 ${banned_count} 个，最多显示 20 个）：${sample:-无}"
        else
          record WARN f2b.sshd_jail "Fail2ban 未启用 sshd jail" "Fail2ban sshd jail is not enabled"
        fi
      else
        F2B_FAILURE_RECORDED=1
        if [[ "$SSH_PASSWORD_DISABLED" -eq 1 ]]; then
          record WARN f2b.active "Fail2ban 已安装但未运行；SSH 当前仅密钥登录" "Fail2ban is installed but inactive; SSH currently uses keys only"
        else
          record FAIL f2b.active "Fail2ban 未运行且 SSH 允许密码类认证" "Fail2ban is inactive while SSH permits password-style authentication"
        fi
        record SKIP f2b.sshd_jail "Fail2ban 未运行，跳过 jail 状态检查" "Fail2ban is inactive; jail status check skipped"
      fi
    elif [[ -n "$alternative_guard" ]]; then
      record PASS f2b.alternative "检测到其他暴力破解防护工具" "Alternative brute-force protection detected" "$alternative_guard"
    elif [[ "$SSH_PASSWORD_DISABLED" -eq 1 ]]; then
      record INFO f2b.absent "未检测到 Fail2ban/CrowdSec/sshguard，但 SSH 已关闭密码认证" "No Fail2ban/CrowdSec/sshguard detected, but SSH password authentication is disabled"
    else
      record WARN f2b.absent "未检测到暴力破解防护工具" "No brute-force protection tool detected" "" \
        "公网 SSH 使用密码认证时，建议启用 Fail2ban、CrowdSec 或 sshguard。" "When public SSH accepts passwords, enable Fail2ban, CrowdSec or sshguard."
    fi

    section "$(t accounts)"
    UID0="$(awk -F: '$3==0{print $1}' /etc/passwd | xargs)"
    [[ "$UID0" == "$EXPECTED_UID0_USERS" ]] \
      && record PASS users.uid0 "UID 0 账户符合预期" "UID 0 accounts match expectation" "$UID0" \
      || record FAIL users.uid0 "发现异常 UID 0 账户" "Unexpected UID 0 accounts" "$UID0"
    echo "--- sudo 用户组 ---"; getent group sudo 2>/dev/null || true
    echo "--- 可登录账户 ---"; awk -F: '$7 !~ /(nologin|false)$/ {print $1":"$3":"$6":"$7}' /etc/passwd
    if have visudo; then
      visudo -c >/dev/null 2>&1 \
        && record PASS sudo.syntax "sudoers 配置语法正确" "sudoers syntax is valid" \
        || record FAIL sudo.syntax "sudoers 配置语法错误" "sudoers syntax is invalid"
    else
      record SKIP sudo.syntax "未安装 visudo，跳过 sudoers 语法检查" "visudo is unavailable; sudoers syntax check skipped"
    fi
    EMPTY_PW="$(awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | xargs)"
    [[ -z "$EMPTY_PW" ]] \
      && record PASS users.empty "未发现空密码账户" "No accounts have empty password hashes" \
      || record FAIL users.empty "发现空密码账户" "Accounts with empty password hashes" "$EMPTY_PW"
    while IFS=: read -r user _ uid _ _ home shell; do
      [[ "$shell" =~ (nologin|false)$ ]] && continue
      key="$home/.ssh/authorized_keys"
      [[ -f "$key" ]] || continue
      count="$(grep -cEv '^[[:space:]]*(#|$)' "$key" 2>/dev/null || true)"
      perms="$(stat -c '%a %U:%G' "$key" 2>/dev/null || true)"
      record INFO "keys.$user" "$user 的 authorized_keys" "$user authorized_keys" "$count 个密钥，$perms"
      if [[ "$FULL_IDENTIFIERS" -eq 1 ]]; then
        ssh-keygen -lf "$key" 2>/dev/null || record WARN "keys.$user.invalid" "$user 的密钥文件无法解析" "$user authorized_keys contains an unparsable key"
      else
        awk '!/^[[:space:]]*(#|$)/ {print $1}' "$key" 2>/dev/null | sort | uniq -c | sed 's/^/key type: /' || true
      fi
    done </etc/passwd

    section "$(t logins)"
    LOGIN_SOURCE=""
    SUCCESS_LOGINS=""
    if have wtmpdb; then
      SUCCESS_LOGINS="$(wtmpdb last 2>/dev/null | head -n "$LOGIN_LINES" || true)"
      LOGIN_SOURCE="wtmpdb"
    elif have last; then
      SUCCESS_LOGINS="$(last -a -n "$LOGIN_LINES" 2>/dev/null || true)"
      LOGIN_SOURCE="last"
    fi
    echo "--- 成功登录（${LOGIN_SOURCE:-不可用}）---"
    if [[ -n "$SUCCESS_LOGINS" ]]; then
      printf '%s\n' "$SUCCESS_LOGINS" | redact_stream
    else
      record SKIP login.success "没有可用的成功登录记录工具或记录" "No successful-login records or compatible tool available"
    fi

    echo "--- 失败登录 ---"
    FAILED_LOGINS=""
    FAILED_SOURCE=""
    if have lastb; then
      FAILED_LOGINS="$(lastb -a -n "$LOGIN_LINES" 2>/dev/null || true)"
      FAILED_SOURCE="lastb"
    elif have journalctl; then
      FAILED_LOGINS="$(journalctl -u ssh.service -u sshd.service --since '-30 days' --no-pager 2>/dev/null | grep -Ei 'Failed password|Invalid user|authentication failure' | tail -n "$LOGIN_LINES" || true)"
      FAILED_SOURCE="journalctl"
      if [[ -z "$FAILED_LOGINS" ]] && have lslogins; then
        FAILED_LOGINS="$(lslogins --failed 2>/dev/null | head -n "$LOGIN_LINES" || true)"
        FAILED_SOURCE="lslogins"
      fi
    else
      record SKIP login.failed "缺少 lastb/journalctl，跳过失败登录记录" "lastb and journalctl are unavailable; failed-login history skipped"
    fi
    [[ -n "$FAILED_SOURCE" ]] && echo "失败登录记录来源：$FAILED_SOURCE"
    [[ -n "$FAILED_LOGINS" ]] \
      && printf '%s\n' "$FAILED_LOGINS" | redact_stream \
      || record INFO login.failed.none "近期未读取到失败登录记录" "No recent failed-login records were read"

    if [[ -n "$TRUSTED_LOGIN_IPS" && -n "$SUCCESS_LOGINS" ]]; then
      mapfile -t seen_ips < <(awk '$1!="reboot" && $NF ~ /^[0-9a-fA-F:.]+$/ {print $NF}' <<<"$SUCCESS_LOGINS" | sort -u)
      for ip in "${seen_ips[@]}"; do
        contains_word "$TRUSTED_LOGIN_IPS" "$ip" || record WARN "login.$ip" "发现来自未列入信任清单的成功登录 IP" "Successful login from unlisted IP" "$ip"
      done
    else
      record INFO login.manual "请人工确认所有成功登录来源是否属于自己" "Manually verify every successful-login source"
    fi
}
