#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
work="$(mktemp -d)"
root="$work/root"
state="$work/state"
trap 'rm -rf -- "$work"' EXIT

mkdir -p "$root/etc/ssh" "$root/etc/sudoers.d" \
  "$root/etc/cron.d" "$root/etc/cron.daily" "$root/etc/cron.hourly" \
  "$root/etc/cron.weekly" "$root/etc/cron.monthly" "$root/home/milo/.ssh" "$state"
cat >"$root/etc/passwd" <<'EOF'
root:x:0:0:root:/root:/bin/bash
milo:x:1000:1000:Milo:/home/milo:/bin/bash
EOF
cat >"$root/etc/group" <<'EOF'
root:x:0:
sudo:x:27:milo
milo:x:1000:
EOF
printf 'root:*:1:0:99999:7:::\n' >"$root/etc/shadow"
printf 'root:*::\n' >"$root/etc/gshadow"
printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeTestOnlyKeyMaterial milo@test\n' \
  >"$root/home/milo/.ssh/authorized_keys"
printf 'fake host private key\n' >"$root/etc/ssh/ssh_host_ed25519_key"
printf 'Defaults env_reset\n' >"$root/etc/sudoers"
printf 'milo ALL=(ALL:ALL) ALL\n' >"$root/etc/sudoers.d/milo"
printf 'SHELL=/bin/sh\n' >"$root/etc/crontab"
printf '# test cron\n' >"$root/etc/cron.d/test-job"
printf '#!/bin/sh\n' >"$root/etc/cron.daily/test-job"

chmod 0666 "$root/etc/passwd" "$root/etc/group" "$root/etc/shadow" "$root/etc/gshadow"
chmod 0777 "$root/home/milo/.ssh"
chmod 0666 "$root/home/milo/.ssh/authorized_keys" "$root/etc/ssh/ssh_host_ed25519_key"
chmod 0666 "$root/etc/sudoers" "$root/etc/sudoers.d/milo"
chmod 0666 "$root/etc/crontab" "$root/etc/cron.d/test-job"
chmod 0777 "$root/etc/cron.daily/test-job"

export VPSGA_SYSTEM_ROOT="$root"
export VPSGA_HARDENING_STATE_ROOT="$state"

# shellcheck source=lib/hardening-transaction.sh
source "$project_dir/lib/hardening-transaction.sh"
# shellcheck source=lib/hardening-actions.sh
source "$project_dir/lib/hardening-actions.sh"

execute_hardening_action HARD-1001 >/dev/null
[[ "$(stat -c %a "$root/etc/passwd")" == 644 ]]
[[ "$(stat -c %a "$root/etc/group")" == 644 ]]
[[ "$(stat -c %a "$root/etc/shadow")" == 640 ]]
[[ "$(stat -c %a "$root/etc/gshadow")" == 640 ]]

execute_hardening_action HARD-1002 >/dev/null
[[ "$(stat -c %a "$root/home/milo/.ssh")" == 700 ]]
[[ "$(stat -c %a "$root/home/milo/.ssh/authorized_keys")" == 600 ]]
[[ "$(stat -c %a "$root/etc/ssh/ssh_host_ed25519_key")" == 600 ]]

execute_hardening_action HARD-1003 >/dev/null
[[ "$(stat -c %a "$root/etc/sudoers")" == 440 ]]
[[ "$(stat -c %a "$root/etc/sudoers.d/milo")" == 440 ]]

execute_hardening_action HARD-1004 >/dev/null
[[ "$(stat -c %a "$root/etc/crontab")" == 644 ]]
[[ "$(stat -c %a "$root/etc/cron.d/test-job")" == 644 ]]
[[ "$(stat -c %a "$root/etc/cron.daily/test-job")" == 755 ]]

[[ "$(find "$state" -mindepth 2 -maxdepth 2 -type f -name status \
  -exec grep -l '^status=committed$' {} + | wc -l)" -eq 4 ]]

# A committed permission transaction remains manually reversible.
tx_1004="$(find "$state" -mindepth 1 -maxdepth 1 -type d -name '*-HARD-1004-*' -print -quit)"
HARDENING_TX_DIR="$tx_1004"
HARDENING_TX_ID="${tx_1004##*/}"
HARDENING_TX_ACTION=HARD-1004
HARDENING_TX_MANIFEST="$tx_1004/manifest.tsv"
HARDENING_TX_AFTER_MANIFEST="$tx_1004/after.tsv"
hardening_tx_rollback 'filesystem permission test' >/dev/null
[[ "$(stat -c %a "$root/etc/crontab")" == 666 ]]
[[ "$(stat -c %a "$root/etc/cron.d/test-job")" == 666 ]]
[[ "$(stat -c %a "$root/etc/cron.daily/test-job")" == 777 ]]

echo 'Filesystem hardening transaction tests passed.'
