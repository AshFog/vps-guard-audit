#!/usr/bin/env bash
set -u

mode="" main=""
while (($#)); do
  case "$1" in
    -t|-T) mode="$1"; shift ;;
    -f) main="${2:?}"; shift 2 ;;
    *) shift ;;
  esac
done
root="${main%/etc/ssh/sshd_config}"
managed="$root/etc/ssh/sshd_config.d/90-vpsga-hardening.conf"
if [[ -e "$root/fail-next-sshd-test" ]]; then
  rm -f -- "$root/fail-next-sshd-test"
  exit 1
fi
[[ -f "$main" ]] || exit 1
if [[ "$mode" == -T ]]; then
  awk '
    $1 == "PermitEmptyPasswords" { empty=tolower($2) }
    $1 == "MaxAuthTries" { tries=$2 }
    $1 == "X11Forwarding" { x11=tolower($2) }
    $1 == "PermitRootLogin" { root=tolower($2) }
    $1 == "PasswordAuthentication" { password=tolower($2) }
    $1 == "KbdInteractiveAuthentication" { keyboard=tolower($2) }
    END {
      print "permitemptypasswords " (empty ? empty : "yes")
      print "maxauthtries " (tries ? tries : "6")
      print "x11forwarding " (x11 ? x11 : "yes")
      print "permitrootlogin " (root ? root : "yes")
      print "passwordauthentication " (password ? password : "yes")
      print "kbdinteractiveauthentication " (keyboard ? keyboard : "yes")
    }
  ' "$managed" 2>/dev/null
fi
