#!/usr/bin/env bash
set -euo pipefail

INSTALL_ROOT="/usr/local/lib/vps-guard-audit"
CURRENT="$INSTALL_ROOT/current"
ARCHIVE_URL="https://github.com/AshFog/vps-guard-audit/archive/refs/heads/main.tar.gz"
VPSGA_BIN="/usr/local/bin/vpsga"

REQUIRED_MODULES=(
  check-registry.sh
  audit-platform.sh
  audit-access.sh
  audit-system.sh
  audit-containers.sh
  report-guidance-zh.sh
  report-guidance.sh
  report-output.sh
  audit-summary.sh
)

need_root() {
  if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    return 0
  fi
  command -v sudo >/dev/null 2>&1 || {
    echo "需要 root 权限，但系统中没有 sudo。" >&2
    exit 77
  }
  exec sudo "$0" "$@"
}

cmd_doctor() {
  local failed=0 target manager version resolved wrapper_version bad bad_owner module
  echo "VPS Guard Audit 安装检查"

  if [[ -L "$CURRENT" ]]; then
    resolved="$(readlink -f "$CURRENT" 2>/dev/null || true)"
    if [[ -n "$resolved" && -d "$resolved" ]]; then
      echo "[正常] 当前版本目录：$resolved"
    else
      echo "[问题] 当前版本链接已损坏：$CURRENT"
      failed=1
    fi
  elif [[ -e "$CURRENT" ]]; then
    echo "[问题] current 路径不是符号链接：$CURRENT"
    echo "       请重新运行官方一键安装命令完成安全迁移。"
    failed=1
    resolved=""
  else
    echo "[问题] 缺少当前版本链接：$CURRENT"
    failed=1
    resolved=""
  fi

  target="$CURRENT/vps-guard-audit.sh"
  manager="$CURRENT/vpsga-manager.sh"
  if [[ -x "$target" ]]; then
    version="$("$target" --version 2>/dev/null || true)"
    echo "[正常] 检测程序：$target"
    echo "[正常] 版本：${version:-未知}"
  else
    echo "[问题] 检测程序缺失：$target"
    failed=1
    version=""
  fi

  if [[ -x "$manager" ]]; then
    echo "[正常] 管理程序：$manager"
  else
    echo "[问题] 管理程序缺失：$manager"
    failed=1
  fi

  for module in "${REQUIRED_MODULES[@]}"; do
    if [[ -r "$CURRENT/lib/$module" ]]; then
      echo "[正常] 模块：$module"
    else
      echo "[问题] 模块缺失：$module"
      failed=1
    fi
  done

  if [[ -x "$target" && -x "$manager" ]]; then
    if bash -n "$target" "$manager" "$CURRENT/lib"/*.sh 2>/dev/null; then
      echo "[正常] Bash 语法检查"
    else
      echo "[问题] Bash 语法检查失败"
      failed=1
    fi
  fi

  if [[ -x "$VPSGA_BIN" ]]; then
    wrapper_version="$("$VPSGA_BIN" --version 2>/dev/null || true)"
    echo "[正常] 全局命令：$VPSGA_BIN"
    if [[ -n "$version" && "$wrapper_version" == "$version" ]]; then
      echo "[正常] 全局命令版本：$wrapper_version"
    else
      echo "[问题] 全局命令版本不一致：${wrapper_version:-未知}"
      failed=1
    fi
  else
    echo "[问题] 全局命令缺失：$VPSGA_BIN"
    failed=1
  fi

  if command -v vpsga >/dev/null 2>&1; then
    echo "[正常] PATH 中的命令：$(command -v vpsga)"
  else
    echo "[问题] PATH 中找不到 vpsga"
    failed=1
  fi

  if [[ -n "$resolved" && "$resolved" == "$INSTALL_ROOT/releases/"* ]]; then
    echo "[正常] 版本目录位于受管理的 releases 目录中"
  elif [[ -n "$resolved" ]]; then
    echo "[问题] 当前版本指向受管理目录之外：$resolved"
    failed=1
  fi

  if [[ -n "$resolved" && -d "$resolved" ]]; then
    bad="$(find "$resolved" -xdev -type f -perm /022 -print 2>/dev/null || true)"
    if [[ -z "$bad" ]]; then
      echo "[正常] 安装文件不可由组用户或其他用户写入"
    else
      echo "[问题] 发现组用户或其他用户可写的安装文件："
      printf '%s\n' "$bad"
      failed=1
    fi
    bad_owner="$(find "$resolved" -xdev -type f ! -user root -print 2>/dev/null || true)"
    if [[ -z "$bad_owner" ]]; then
      echo "[正常] 安装文件所有者均为 root"
    else
      echo "[问题] 发现不属于 root 的安装文件："
      printf '%s\n' "$bad_owner"
      failed=1
    fi
  fi

  if [[ -n "$resolved" && -f "$resolved/MANIFEST.sha256" ]]; then
    if (cd "$resolved" && sha256sum -c MANIFEST.sha256 >/dev/null 2>&1); then
      echo "[正常] 模块完整性清单校验通过"
    else
      echo "[问题] 模块完整性清单校验失败"
      failed=1
    fi
  else
    echo "[问题] 缺少模块完整性清单"
    failed=1
  fi

  if ((failed == 0)); then
    echo "安装状态正常。"
  else
    echo "发现安装问题。" >&2
    exit 1
  fi
}

cmd_update() {
  need_root update
  local tmp archive root installer
  command -v curl >/dev/null 2>&1 || { echo "缺少必要命令：curl" >&2; exit 69; }
  command -v tar >/dev/null 2>&1 || { echo "缺少必要命令：tar" >&2; exit 69; }
  tmp="$(mktemp -d)"
  trap 'rm -rf -- "${tmp:-}"' EXIT
  archive="$tmp/vpsga.tar.gz"
  echo "正在下载最新的 VPS Guard Audit 源码……"
  curl --fail --show-error --location --connect-timeout 15 --max-time 120 --retry 2 --retry-delay 1 "$ARCHIVE_URL" -o "$archive"
  tar -xzf "$archive" -C "$tmp"
  root="$(find "$tmp" -mindepth 1 -maxdepth 1 -type d -name 'vps-guard-audit-*' -print -quit)"
  [[ -n "$root" ]] || { echo "下载包中没有项目目录" >&2; exit 69; }
  installer="$root/install.sh"
  [[ -f "$installer" ]] || { echo "下载包不完整" >&2; exit 69; }
  bash "$installer"
  "$CURRENT/vpsga-manager.sh" doctor
  echo "更新完成，当前版本：$("$VPSGA_BIN" --version)"
}

cmd_uninstall() {
  need_root uninstall
  local answer keep_history="yes" history_tmp=""
  if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
    echo "卸载需要交互式终端。" >&2
    exit 65
  fi
  echo "此操作将删除 VPS Guard Audit 程序和 vpsga 命令。" >/dev/tty
  printf "输入 UNINSTALL 继续：" >/dev/tty
  IFS= read -r answer </dev/tty
  [[ "$answer" == UNINSTALL ]] || { echo "已取消。"; exit 0; }

  if [[ -d /var/lib/vps-guard-audit/history ]]; then
    printf "是否保留检测历史？[Y/n]：" >/dev/tty
    IFS= read -r answer </dev/tty
    case "$answer" in n|N|no|NO) keep_history="no" ;; esac
    if [[ "$keep_history" == yes ]]; then
      history_tmp="$(mktemp -d)"
      cp -a /var/lib/vps-guard-audit/history "$history_tmp/"
    fi
  fi

  rm -f /usr/local/bin/vpsga /usr/local/sbin/vps-guard-audit
  rm -rf "$INSTALL_ROOT"
  if [[ "$keep_history" == yes && -n "$history_tmp" && -d "$history_tmp/history" ]]; then
    install -d -m 0700 /var/lib/vps-guard-audit
    cp -a "$history_tmp/history" /var/lib/vps-guard-audit/history
    rm -rf "$history_tmp"
    echo "程序已删除，历史记录保留在 /var/lib/vps-guard-audit/history"
  else
    rm -rf /var/lib/vps-guard-audit
    [[ -n "$history_tmp" ]] && rm -rf "$history_tmp"
    echo "VPS Guard Audit 已卸载。"
  fi
}

usage() {
  cat <<'EOF_USAGE'
VPS Guard Audit 管理命令：
  vpsga doctor                 检查程序安装状态和完整性
  vpsga update                 安装上游最新版本
  vpsga uninstall              卸载程序
EOF_USAGE
}

case "${1:-}" in
  doctor) shift; cmd_doctor "$@" ;;
  update) shift; cmd_update "$@" ;;
  uninstall) shift; cmd_uninstall "$@" ;;
  -h|--help|help|"") usage ;;
  *) echo "未知管理命令：$1" >&2; usage >&2; exit 64 ;;
esac
