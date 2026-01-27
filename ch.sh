#!/bin/bash

CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak.$(date +%F-%H%M%S)"

echo "[+] Backup sshd_config -> $BACKUP"
cp "$CONFIG" "$BACKUP" || exit 1

set_option () {
    local key="$1"
    local value="$2"

    if grep -Eq "^[#\s]*$key\s+" "$CONFIG"; then
        sed -i "s|^[#\s]*$key\s\+.*|$key $value|" "$CONFIG"
        echo "[*] Updated: $key $value"
    else
        echo "$key $value" >> "$CONFIG"
        echo "[*] Added: $key $value"
    fi
}

echo "[+] Fixing SSH authentication options..."
set_option "PermitRootLogin" "yes"
set_option "PasswordAuthentication" "yes"
set_option "PubkeyAuthentication" "yes"

echo "[+] Restarting SSH service..."
systemctl restart ssh || exit 1

echo "[+] Changing root password..."
echo "root:nm" | chpasswd || exit 1

echo "[+] Effective SSH configuration:"
sshd -T | grep -E "permitrootlogin|passwordauthentication|pubkeyauthentication"

# =======================
# CHECK IP GLOBAL VPS
# =======================
echo "[+] Detecting public IP address..."

get_ip () {
    curl -fsS "$1" 2>/dev/null
}

PUBLIC_IP=$(
    get_ip https://api.ipify.org ||
    get_ip https://ifconfig.me ||
    get_ip https://icanhazip.com
)

if [[ -n "$PUBLIC_IP" ]]; then
    echo "[✓] VPS Public IP: $PUBLIC_IP"
    echo "[✓] SSH command: ssh root@$PUBLIC_IP"
else
    echo "[!] Could not detect public IP"
fi

echo "[✓] DONE. Root password is now: nm"
