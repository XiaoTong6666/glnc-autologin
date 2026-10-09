#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo ./install.sh" >&2
    exit 1
fi

base_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

case "${1:-}" in
    ""|--upgrade) ;;
    *) echo "Usage: sudo ./install.sh [--upgrade]" >&2; exit 2 ;;
esac

config_file=/etc/glnc-autologin.conf

# 这里只询问“不能从网络环境推导出来”的用户身份信息。
# 网卡、IP、MAC、Portal/AC 地址、ePortal 端口和 JS 版本均由运行时发现。
if [ -f "$config_file" ]; then
    # 重装/升级时复用原有凭据，避免把已经正确工作的密码配置覆盖掉。
    echo "Keeping existing $config_file (credentials unchanged)."
elif [ "${1:-}" = "--upgrade" ]; then
    echo "Cannot upgrade: $config_file does not exist." >&2
    exit 1
else
    printf 'Full portal account (for example student-id@cmcc): '
    read -r account
    [ -n "$account" ] || { echo "account is required" >&2; exit 1; }

    printf 'Password: '
    # 仅在首次创建配置时读取密码；退出前恢复终端回显。
    old_stty=$(stty -g)
    trap 'stty "$old_stty"' EXIT HUP INT TERM
    stty -echo
    read -r password
    stty "$old_stty"
    trap - EXIT HUP INT TERM
    printf '\n'
    [ -n "$password" ] || { echo "password is required" >&2; exit 1; }

    umask 077
    cat >"$config_file" <<EOF
GLNC_ACCOUNT=$account
GLNC_PASSWORD=$(printf '%s' "$password" | sed "s/'/'\\''/g; s/^/'/; s/$/'/")
GLNC_PROBE_URL=http://firefox-portal-detection.com/generate_204
GLNC_DISCOVERY_TRIES=10
GLNC_RETRY_DELAY=2
GLNC_VERIFY_TRIES=5
GLNC_VERIFY_DELAY=1
EOF
fi
chmod 600 "$config_file"

install -Dm755 "$base_dir/glnc_autologin.py" /usr/local/libexec/glnc-autologin.py
install -Dm644 "$base_dir/glnc-autologin@.service" /etc/systemd/system/glnc-autologin@.service
install -Dm644 "$base_dir/glnc-autologin-check.service" /etc/systemd/system/glnc-autologin-check.service
install -Dm644 "$base_dir/glnc-autologin-check.timer" /etc/systemd/system/glnc-autologin-check.timer
install -Dm755 "$base_dir/90-glnc-autologin" /etc/NetworkManager/dispatcher.d/90-glnc-autologin

systemctl daemon-reload
# timer 在引导时和每次上一轮检查结束后定期运行；NetworkManager dispatcher
# 仍负责网络刚上线时的即时触发，两者互补。
systemctl enable --now glnc-autologin-check.timer
systemctl start --no-block glnc-autologin-check.service

echo "Installed. Immediate login on NM events + periodic reauthentication checks enabled."
echo "Timer: systemctl list-timers glnc-autologin-check.timer --all"
echo "Logs: journalctl -t glnc-autologin -n 100 --no-pager"
