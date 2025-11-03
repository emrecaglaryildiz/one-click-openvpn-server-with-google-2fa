#!/usr/bin/env bash
# OpenVPN + EasyRSA + Google Authenticator "All-in-One" Manager
# Author: Emre Caglar YILDIZ
# Tested on: Ubuntu/Debian family
# Modes: Install | Add User | Delete User | Uninstall
# Features:
#  - Asks Public IP, Port, and NAT Interface on install
#  - EasyRSA PKI bootstrap (CA, server cert, DH)
#  - tls-auth key
#  - PAM + Google Authenticator enforced (2FA)
#  - ip_forward + iptables NAT (persisted)
#  - Client .ovpn builder (inline certs + tls-auth, prompts for OTP via PAM)
#  - Shows TOTP QR in terminal AND saves PNG under /etc/openvpn/google-qrcode
#  - Keeps install vars in /etc/openvpn/.install-vars for later operations
#  - User revoke (CRL) and cleanup
#  - Full uninstall

set -euo pipefail

# ---------- Globals ----------
OVPN_DIR="/etc/openvpn"
EASYRSA_DIR="$OVPN_DIR/easy-rsa"
PKI_DIR="$EASYRSA_DIR/pki"
CLIENT_DIR="$OVPN_DIR/client-configs"
QR_DIR="$OVPN_DIR/google-qrcode"
VARS_FILE="$OVPN_DIR/.install-vars"
SERVER_CONF="$OVPN_DIR/server.conf"
TLS_AUTH_KEY="$OVPN_DIR/tls-auth.key"
CRL_FILE="$OVPN_DIR/crl.pem"

VPN_NET="10.10.0.0"
VPN_MASK="255.255.255.0"    # /24
VPN_CIDR="10.10.0.0/24"

DATA_CIPHER="AES-256-GCM"
AUTH_DIGEST="SHA256"

# ---------- Helpers ----------
info(){ echo -e "\e[1;34m[INFO]\e[0m $*"; }
ok(){   echo -e "\e[1;32m[ OK ]\e[0m $*"; }
warn(){ echo -e "\e[1;33m[WARN]\e[0m $*"; }
err(){  echo -e "\e[1;31m[ERR ]\e[0m $*"; }

need_root(){
  if [[ $EUID -ne 0 ]]; then
    err "Lütfen root olarak çalıştırın (sudo ile)."
    exit 1
  fi
}

detect_distro(){
  if command -v apt &>/dev/null; then
    PKG_MGR="apt"
  else
    err "Bu script apt tabanlı sistemler için yazıldı (Ubuntu/Debian)."
    exit 1
  fi
}

install_packages(){
  info "Paketler kuruluyor..."
  apt update -y
  DEBIAN_FRONTEND=noninteractive apt install -y \
    openvpn easy-rsa libpam-google-authenticator iptables-persistent qrencode
  ok "Paket kurulumu tamam."
}

enable_ip_forward(){
  info "IP forwarding etkinleştiriliyor..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  if ! grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf; then
    echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
  fi
  ok "IP forwarding aktif."
}

configure_nat_rule(){
  local iface="$1"
  info "NAT (POSTROUTING) kuralı ekleniyor: kaynak $VPN_CIDR -> arayüz $iface"
  # Avoid duplicate rule
  if ! iptables -t nat -C POSTROUTING -s "$VPN_CIDR" -o "$iface" -j MASQUERADE &>/dev/null; then
    iptables -t nat -A POSTROUTING -s "$VPN_CIDR" -o "$iface" -j MASQUERADE
    ok "NAT kuralı eklendi."
  else
    warn "NAT kuralı zaten mevcut, atlanıyor."
  fi
  info "iptables kuralları kalıcılaştırılıyor..."
  netfilter-persistent save || true
  ok "iptables kalıcı kaydedildi."
}

bootstrap_easyrsa(){
  info "Easy-RSA dizinleri hazırlanıyor..."
  mkdir -p "$EASYRSA_DIR" "$CLIENT_DIR" "$QR_DIR"
  if [[ ! -f "$EASYRSA_DIR/easyrsa" ]]; then
    cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"
  fi
  pushd "$EASYRSA_DIR" >/dev/null
  if [[ ! -d "$PKI_DIR" ]]; then
    ./easyrsa init-pki
  fi
  if [[ ! -f "$PKI_DIR/ca.crt" ]]; then
    info "CA oluşturuluyor..."
    ./easyrsa --batch build-ca nopass
  fi
  if [[ ! -f "$PKI_DIR/issued/server.crt" ]]; then
    info "Sunucu sertifikası oluşturuluyor..."
    ./easyrsa --batch build-server-full server nopass
  fi
  if [[ ! -f "$PKI_DIR/dh.pem" ]]; then
    info "DH parametresi oluşturuluyor (biraz sürebilir)..."
    ./easyrsa gen-dh
  fi
  # CRL initial
  if [[ ! -f "$PKI_DIR/crl.pem" ]]; then
    info "CRL oluşturuluyor..."
    ./easyrsa gen-crl
  fi
  popd >/dev/null

  # Copy artifacts
  install -m 0600 "$PKI_DIR/ca.crt"               "$OVPN_DIR/ca.crt"
  install -m 0600 "$PKI_DIR/issued/server.crt"    "$OVPN_DIR/server.crt"
  install -m 0600 "$PKI_DIR/private/server.key"   "$OVPN_DIR/server.key"
  install -m 0600 "$PKI_DIR/dh.pem"               "$OVPN_DIR/dh.pem"
  install -m 0644 "$PKI_DIR/crl.pem"              "$CRL_FILE"

  if [[ ! -f "$TLS_AUTH_KEY" ]]; then
    info "tls-auth key üretiliyor..."
    openvpn --genkey --secret "$TLS_AUTH_KEY"
    chmod 600 "$TLS_AUTH_KEY"
  fi
  ok "Easy-RSA/PKI hazır."
}

write_server_conf(){
  local port="$1"
  local proto="udp"
  info "OpenVPN server.conf yazılıyor..."

  # choose plugin path (Debian paths)
  local pam_plugin="/usr/lib/openvpn/openvpn-plugin-auth-pam.so"
  [[ -f "$pam_plugin" ]] || pam_plugin="/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so"

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

;push "redirect-gateway def1 bypass-dhcp"
;push "dhcp-option DNS 1.1.1.1"
;push "dhcp-option DNS 9.9.9.9"

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

# Revoke support
crl-verify $CRL_FILE

# PAM + Google Authenticator (combined with client certs = 2FA)
plugin $pam_plugin openvpn

# Hata ayıklama seviyesini gerekirse arttır:
verb 3
EOF
  ok "server.conf oluşturuldu."
}

enable_pam_google(){
  info "PAM (Google Authenticator) yapılandırılıyor..."
  # Minimal PAM policy for OpenVPN service
  cat > /etc/pam.d/openvpn <<'EOF'
# Enforce TOTP with google-authenticator
auth required pam_google_authenticator.so

# If you also want system password check, uncomment next line:
# auth include system-auth
# or on Debian/Ubuntu:
# auth include common-auth

account required pam_permit.so
EOF
  ok "PAM yapılandırması hazır."
}

start_service(){
  info "OpenVPN servisi etkinleştiriliyor..."
  systemctl enable openvpn || true
  systemctl restart openvpn
  systemctl status openvpn --no-pager || true
  ok "OpenVPN servis çalışıyor."
}

save_install_vars(){
  local pubip="$1" port="$2" iface="$3"
  cat > "$VARS_FILE" <<EOF
PUBLIC_IP="$pubip"
PORT="$port"
IFACE="$iface"
EOF
  ok "Kurulum değişkenleri $VARS_FILE içine kaydedildi."
}

load_install_vars(){
  if [[ -f "$VARS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$VARS_FILE"
  else
    err "Kurulum değişkenleri bulunamadı ($VARS_FILE). Önce kurulum yapmalısın."
    exit 1
  fi
}

build_client_ovpn(){
  local user="$1"
  local remote_ip="$2"
  local remote_port="$3"

  local ca crt key ta
  ca="$(awk 'BEGIN{print "<ca>"}{print}END{print "</ca>"}' "$OVPN_DIR/ca.crt")"
  crt="$(awk 'BEGIN{print "<cert>"}{print}END{print "</cert>"}' "$PKI_DIR/issued/$user.crt")"
  key="$(awk 'BEGIN{print "<key>"}{print}END{print "</key>"}' "$PKI_DIR/private/$user.key")"
  ta="$(awk 'BEGIN{print "<tls-auth>"}{print}END{print "</tls-auth>"}' "$TLS_AUTH_KEY")"

  local outfile="$CLIENT_DIR/${user}.ovpn"
  cat > "$outfile" <<EOF
client
dev tun
proto udp
remote $remote_ip $remote_port
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

$ca
$crt
$key
$ta
EOF
  chmod 600 "$outfile"
  echo "$outfile"
}

create_system_user_if_missing(){
  local user="$1"
  if ! id "$user" &>/dev/null; then
    info "Sistem kullanıcısı oluşturuluyor: $user"
    adduser --disabled-password --gecos "" "$user"
  else
    warn "Sistem kullanıcısı zaten var: $user"
  fi
}

setup_google_auth_for_user(){
  local user="$1"
  local homedir
  homedir="$(eval echo "~$user")"

  info "Google Authenticator yapılandırılıyor (kullanıcı: $user)..."
  mkdir -p "$QR_DIR"

  # Run google-authenticator as the target user; capture stdout to parse scratch codes
  local out tmpfile
  tmpfile="$(mktemp)"
  # Options:
  # -t TOTP, -d disallow-reuse, -f no-interactive confirm, -r 3 -R 30 rate-limit, -W allow time skew
  sudo -u "$user" -H bash -c 'google-authenticator -t -d -f -r 3 -R 30 -W' | tee "$tmpfile"

  # Extract secret (first line of ~/.google_authenticator)
  local secret
  secret="$(sudo -u "$user" -H head -n1 "$homedir/.google_authenticator" | tr -d ' \t\r\n')"
  if [[ -z "$secret" ]]; then
    err "Google Auth secret alınamadı!"
    exit 1
  fi

  # Build otpauth URL and print QR to terminal and save PNG
  local label="OpenVPN ($user)"
  local url="otpauth://totp/$(python3 -c "import urllib.parse; print(urllib.parse.quote('$label'))")?secret=$secret&issuer=OpenVPN"

  info "TOTP QR terminal çıktısı (telefon uygulaması ile okut):"
  qrencode -t ANSIUTF8 "$url" || true

  local png="$QR_DIR/${user}.png"
  qrencode -o "$png" "$url"
  ok "QR PNG kaydedildi: $png"

  # Try to extract any 8-digit scratch codes from the captured output
  local scratch="$QR_DIR/${user}.recovery-codes.txt"
  grep -Eo '\b[0-9]{8}\b' "$tmpfile" | sort -u > "$scratch" || true
  rm -f "$tmpfile"
  if [[ -s "$scratch" ]]; then
    ok "Kurtarma kodları kaydedildi: $scratch"
  else
    warn "Kurtarma kodları bulunamadı (google-authenticator çıktısı değişmiş olabilir)."
  fi
}

add_vpn_user(){
  load_install_vars
  local user
  read -rp "Eklemek istediğin VPN kullanıcı adı: " user
  [[ -n "${user:-}" ]] || { err "Kullanıcı adı boş olamaz."; exit 1; }

  create_system_user_if_missing "$user"

  pushd "$EASYRSA_DIR" >/dev/null
  if [[ ! -f "$PKI_DIR/issued/$user.crt" ]]; then
    info "Client sertifikası oluşturuluyor: $user"
    ./easyrsa --batch build-client-full "$user" nopass
  else
    warn "Client sertifikası zaten var: $user"
  fi
  popd >/dev/null

  setup_google_auth_for_user "$user"

  local ovpn
  ovpn="$(build_client_ovpn "$user" "$PUBLIC_IP" "$PORT")"
  ok "Kullanıcı .ovpn hazır: $ovpn"
  echo
  info "Not: Bağlantı sırasında kullanıcı adı ($user) + TOTP (Google Auth) istenecektir."
}

delete_vpn_user(){
  load_install_vars
  local user
  read -rp "Silmek/Revoke etmek istediğin VPN kullanıcı adı: " user
  [[ -n "${user:-}" ]] || { err "Kullanıcı adı boş olamaz."; exit 1; }

  pushd "$EASYRSA_DIR" >/dev/null
  if [[ -f "$PKI_DIR/issued/$user.crt" ]]; then
    info "Sertifika revoke ediliyor: $user"
    ./easyrsa --batch revoke "$user"
    ./easyrsa gen-crl
    install -m 0644 "$PKI_DIR/crl.pem" "$CRL_FILE"
    systemctl restart openvpn || true
    ok "Kullanıcı revoke edildi ve CRL güncellendi."
  else
    warn "Bu isimde sertifika bulunamadı: $user"
  fi
  popd >/dev/null

  # Cleanup client artifacts
  rm -f "$CLIENT_DIR/${user}.ovpn" || true
  rm -f "$QR_DIR/${user}.png" "$QR_DIR/${user}.recovery-codes.txt" || true

  # Optional: remove system user
  read -rp "Sistem kullanıcısını da silelim mi? (y/N): " yesno
  yesno="${yesno:-N}"
  if [[ "$yesno" =~ ^[Yy]$ ]]; then
    deluser --remove-home "$user" || true
    ok "Sistem kullanıcısı silindi: $user"
  fi
}

uninstall_all(){
  warn "Tüm OpenVPN kurulumu ve veriler KALDIRILACAK!"
  read -rp "Emin misin? (y/N): " ans
  [[ "${ans:-N}" =~ ^[Yy]$ ]] || { warn "İptal edildi."; exit 0; }

  systemctl stop openvpn || true
  systemctl disable openvpn || true

  # Try to remove NAT rule (best-effort)
  if [[ -f "$VARS_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$VARS_FILE"
    if [[ -n "${IFACE:-}" ]]; then
      if iptables -t nat -C POSTROUTING -s "$VPN_CIDR" -o "$IFACE" -j MASQUERADE &>/dev/null; then
        iptables -t nat -D POSTROUTING -s "$VPN_CIDR" -o "$IFACE" -j MASQUERADE || true
        netfilter-persistent save || true
      fi
    fi
  fi

  # Purge packages and remove dirs
  apt purge -y openvpn easy-rsa libpam-google-authenticator iptables-persistent || true
  apt autoremove -y || true

  rm -rf "$OVPN_DIR"
  ok "Kurulum tamamen kaldırıldı."
}

install_flow(){
  detect_distro
  install_packages

  read -rp "Dış (public) IP (örn: 1.2.3.4): " PUBLIC_IP
  read -rp "OpenVPN portu (örn: 1194): " PORT
  read -rp "NAT çıkış arayüzü (örn: eth0): " IFACE

  [[ -n "${PUBLIC_IP:-}" && -n "${PORT:-}" && -n "${IFACE:-}" ]] || { err "Gerekli bilgiler boş bırakılamaz."; exit 1; }

  mkdir -p "$OVPN_DIR" "$CLIENT_DIR" "$QR_DIR"

  enable_ip_forward
  configure_nat_rule "$IFACE"
  bootstrap_easyrsa
  write_server_conf "$PORT"
  enable_pam_google
  start_service
  save_install_vars "$PUBLIC_IP" "$PORT" "$IFACE"

  ok "Kurulum tamamlandı 🎉  Şimdi menüden 'Kullanıcı ekle' ile ilk kullanıcıyı oluşturabilirsin."
}

menu(){
  echo "---------------------------------------------"
  echo " OpenVPN Manager"
  echo "---------------------------------------------"
  echo "1) Kurulum yap (Install)"
  echo "2) Kullanıcı ekle (Add User)"
  echo "3) Kullanıcı sil (Revoke/Delete User)"
  echo "4) Kurulumu kaldır (Uninstall)"
  echo "---------------------------------------------"
  read -rp "Seçimin (1-4): " choice

  case "${choice:-}" in
    1) install_flow ;;
    2) add_vpn_user ;;
    3) delete_vpn_user ;;
    4) uninstall_all ;;
    *) err "Geçersiz seçim."; exit 1 ;;
  esac
}

# ---------- Main ----------
need_root
menu
