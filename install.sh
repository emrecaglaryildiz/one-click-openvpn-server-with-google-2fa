#!/usr/bin/env bash
# ===============================================
# OpenVPN + EasyRSA + Google Authenticator Manager
# Version: v2 (centralized google-auth dir version)
# Author: Emre Caglar YILDIZ
# ===============================================

set -euo pipefail

# ---------- GLOBALS ----------
OVPN_DIR="/etc/openvpn"
EASYRSA_DIR="$OVPN_DIR/easy-rsa"
PKI_DIR="$EASYRSA_DIR/pki"
CLIENT_DIR="$OVPN_DIR/client-configs"
GAUTH_DIR="$OVPN_DIR/google-auth"
VARS_FILE="$OVPN_DIR/.install-vars"
SERVER_CONF="$OVPN_DIR/server.conf"
TLS_AUTH_KEY="$OVPN_DIR/tls-auth.key"
CRL_FILE="$OVPN_DIR/crl.pem"

VPN_NET="10.10.0.0"
VPN_MASK="255.255.255.0"
VPN_CIDR="10.10.0.0/24"
DATA_CIPHER="AES-256-GCM"
AUTH_DIGEST="SHA256"

# ---------- HELPERS ----------
info(){ echo -e "\e[1;34m[INFO]\e[0m $*"; }
ok(){ echo -e "\e[1;32m[ OK ]\e[0m $*"; }
warn(){ echo -e "\e[1;33m[WARN]\e[0m $*"; }
err(){ echo -e "\e[1;31m[ERR ]\e[0m $*"; }

need_root(){
  if [[ $EUID -ne 0 ]]; then
    err "Bu scripti root olarak çalıştırmalısın (sudo ile)."
    exit 1
  fi
}

detect_distro(){
  if ! command -v apt &>/dev/null; then
    err "Bu script sadece Debian/Ubuntu için tasarlandı."
    exit 1
  fi
}

install_packages(){
  info "Paketler kuruluyor..."
  apt update -y
  DEBIAN_FRONTEND=noninteractive apt install -y \
    openvpn easy-rsa libpam-google-authenticator iptables-persistent qrencode
  ok "Gerekli paketler kuruldu."
}

enable_ip_forward(){
  info "IP forwarding etkinleştiriliyor..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
  ok "IP yönlendirme aktif."
}

configure_nat_rule(){
  local iface="$1"
  info "NAT kuralı ekleniyor (interface: $iface)..."
  if ! iptables -t nat -C POSTROUTING -s "$VPN_CIDR" -o "$iface" -j MASQUERADE &>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$VPN_CIDR" -o "$iface" -j MASQUERADE
    ok "NAT kuralı eklendi."
  else
    warn "NAT kuralı zaten mevcut."
  fi
  netfilter-persistent save || true
}

bootstrap_easyrsa(){
  info "Easy-RSA yapılandırması başlatılıyor..."
  mkdir -p "$EASYRSA_DIR" "$CLIENT_DIR" "$GAUTH_DIR"
  [[ -f "$EASYRSA_DIR/easyrsa" ]] || cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"

  pushd "$EASYRSA_DIR" >/dev/null
  [[ -d "$PKI_DIR" ]] || ./easyrsa init-pki
  [[ -f "$PKI_DIR/ca.crt" ]] || ./easyrsa --batch build-ca nopass
  [[ -f "$PKI_DIR/issued/server.crt" ]] || ./easyrsa --batch build-server-full server nopass
  [[ -f "$PKI_DIR/dh.pem" ]] || ./easyrsa gen-dh
  [[ -f "$PKI_DIR/crl.pem" ]] || ./easyrsa gen-crl
  popd >/dev/null

  install -m 0600 "$PKI_DIR/ca.crt" "$OVPN_DIR/ca.crt"
  install -m 0600 "$PKI_DIR/issued/server.crt" "$OVPN_DIR/server.crt"
  install -m 0600 "$PKI_DIR/private/server.key" "$OVPN_DIR/server.key"
  install -m 0600 "$PKI_DIR/dh.pem" "$OVPN_DIR/dh.pem"
  install -m 0644 "$PKI_DIR/crl.pem" "$CRL_FILE"

  if [[ ! -f "$TLS_AUTH_KEY" ]]; then
    info "tls-auth anahtarı oluşturuluyor..."
    openvpn --genkey --secret "$TLS_AUTH_KEY"
    chmod 600 "$TLS_AUTH_KEY"
  fi
  ok "PKI ve anahtar dosyaları hazır."
}

write_server_conf(){
  local port="$1"
  local proto="udp"
  info "OpenVPN server.conf oluşturuluyor..."

  local pam_plugin="/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so"
  [[ -f "$pam_plugin" ]] || pam_plugin="/usr/lib/openvpn/openvpn-plugin-auth-pam.so"

  cat > "$SERVER_CONF" <<EOF
port $port
proto $proto
dev tun
ca $OVPN_DIR/ca.crt
cert $OVPN_DIR/server.crt
key $OVPN_DIR/server.key
dh $OVPN_DIR/dh.pem

topology subnet
server $VPN_NET $VPN_MASK
ifconfig-pool-persist $OVPN_DIR/ipp.txt

keepalive 10 120
tls-auth $TLS_AUTH_KEY 0
key-direction 0
data-ciphers $DATA_CIPHER
auth $AUTH_DIGEST
user nobody
group nogroup
persist-key
persist-tun
explicit-exit-notify 1
crl-verify $CRL_FILE

plugin $pam_plugin openvpn
verb 3
EOF
  ok "Sunucu yapılandırması tamamlandı."
}

enable_pam_google(){
  info "PAM dosyası düzenleniyor..."
  cat > /etc/pam.d/openvpn <<'EOF'
auth requisite pam_google_authenticator.so user=root secret=/etc/openvpn/google-auth/${USER}/.google_authenticator nullok
account required pam_unix.so
EOF
  ok "PAM yapılandırması merkezi google-auth dizinine göre güncellendi."
}

start_service(){
  systemctl enable openvpn || true
  systemctl restart openvpn
  ok "OpenVPN servisi aktif."
}

save_install_vars(){
  local ip="$1" port="$2" iface="$3"
  cat > "$VARS_FILE" <<EOF
PUBLIC_IP="$ip"
PORT="$port"
IFACE="$iface"
EOF
}

load_install_vars(){
  [[ -f "$VARS_FILE" ]] && source "$VARS_FILE" || { err "Önce kurulum yapılmalı!"; exit 1; }
}

build_client_ovpn(){
  local user="$1" ip="$2" port="$3"
  local outfile="$CLIENT_DIR/${user}.ovpn"
  cat > "$outfile" <<EOF
client
dev tun
proto udp
remote $ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth-user-pass
key-direction 1
verb 3
auth $AUTH_DIGEST
data-ciphers $DATA_CIPHER

<ca>
$(cat $OVPN_DIR/ca.crt)
</ca>
<cert>
$(cat $PKI_DIR/issued/$user.crt)
</cert>
<key>
$(cat $PKI_DIR/private/$user.key)
</key>
<tls-auth>
$(cat $TLS_AUTH_KEY)
</tls-auth>
EOF
  chmod 600 "$outfile"
  echo "$outfile"
}

setup_google_auth_for_user(){
  local user="$1"
  local userdir="$GAUTH_DIR/$user"
  mkdir -p "$userdir"

  info "Google Authenticator oluşturuluyor (user: $user)"
  google-authenticator -t -d -f -r 3 -R 30 -W -s "$userdir/.google_authenticator" >/dev/null

  local secret
  secret="$(head -n1 "$userdir/.google_authenticator" | tr -d ' \t\r\n')"
  [[ -z "$secret" ]] && { err "Secret alınamadı!"; exit 1; }

  local label="OpenVPN ($user)"
  local url="otpauth://totp/$(python3 -c "import urllib.parse; print(urllib.parse.quote('$label'))")?secret=$secret&issuer=OpenVPN"

  qrencode -t ANSIUTF8 "$url"
  qrencode -o "$userdir/qrcode.png" "$url"
  grep -Eo '\b[0-9]{8}\b' "$userdir/.google_authenticator" > "$userdir/recovery-codes.txt" || true
  chmod 700 "$userdir"
  chmod 600 "$userdir"/*
  ok "Google Auth dosyaları oluşturuldu ($userdir)."
}

add_vpn_user(){
  load_install_vars
  read -rp "VPN kullanıcı adı: " user
  [[ -z "$user" ]] && { err "Kullanıcı adı boş olamaz."; exit 1; }

  pushd "$EASYRSA_DIR" >/dev/null
  [[ -f "$PKI_DIR/issued/$user.crt" ]] || ./easyrsa --batch build-client-full "$user" nopass
  popd >/dev/null

  setup_google_auth_for_user "$user"
  local ovpn; ovpn="$(build_client_ovpn "$user" "$PUBLIC_IP" "$PORT")"
  ok "Kullanıcı .ovpn oluşturuldu: $ovpn"
  echo "➡️  Username: $user"
  echo "➡️  Password: Google Authenticator kodu"
}

delete_vpn_user(){
  load_install_vars
  read -rp "Silinecek kullanıcı: " user
  [[ -z "$user" ]] && { err "Kullanıcı adı boş."; exit 1; }

  pushd "$EASYRSA_DIR" >/dev/null
  ./easyrsa --batch revoke "$user" || true
  ./easyrsa gen-crl
  install -m 0644 "$PKI_DIR/crl.pem" "$CRL_FILE"
  systemctl restart openvpn
  popd >/dev/null

  rm -f "$CLIENT_DIR/${user}.ovpn"
  rm -rf "$GAUTH_DIR/$user"
  ok "Kullanıcı $user silindi ve CRL güncellendi."
}

uninstall_all(){
  warn "Bu işlem tüm OpenVPN kurulumunu kaldırır!"
  read -rp "Emin misin? (y/N): " ans
  [[ "$ans" =~ ^[Yy]$ ]] || exit 0

  systemctl stop openvpn || true
  systemctl disable openvpn || true

  [[ -f "$VARS_FILE" ]] && source "$VARS_FILE" && \
    iptables -t nat -D POSTROUTING -s "$VPN_CIDR" -o "$IFACE" -j MASQUERADE || true
  netfilter-persistent save || true

  apt purge -y openvpn easy-rsa libpam-google-authenticator iptables-persistent
  apt autoremove -y
  rm -rf "$OVPN_DIR"
  ok "OpenVPN tamamen kaldırıldı."
}

install_flow(){
  detect_distro
  install_packages
  read -rp "Dış IP (ör: 1.2.3.4): " PUBLIC_IP
  read -rp "OpenVPN Port (ör: 1194): " PORT
  read -rp "NAT interface (ör: eth0): " IFACE
  mkdir -p "$OVPN_DIR" "$CLIENT_DIR" "$GAUTH_DIR"

  enable_ip_forward
  configure_nat_rule "$IFACE"
  bootstrap_easyrsa
  write_server_conf "$PORT"
  enable_pam_google
  start_service
  save_install_vars "$PUBLIC_IP" "$PORT" "$IFACE"
  ok "Kurulum tamamlandı. Artık 'Kullanıcı ekle' menüsünü kullanabilirsin."
}

menu(){
  echo "============================================"
  echo "   🧩 OpenVPN + Google Auth Manager"
  echo "============================================"
  echo "1) Kurulum yap"
  echo "2) Kullanıcı ekle"
  echo "3) Kullanıcı sil"
  echo "4) Kurulumu kaldır"
  echo "============================================"
  read -rp "Seçimin (1-4): " choice
  case "$choice" in
    1) install_flow ;;
    2) add_vpn_user ;;
    3) delete_vpn_user ;;
    4) uninstall_all ;;
    *) err "Geçersiz seçim." ;;
  esac
}

# ---------- MAIN ----------
need_root
menu
