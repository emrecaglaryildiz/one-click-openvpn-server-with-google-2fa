 OpenVPN + EasyRSA + Google Authenticator "All-in-One" Manager
+ Author: Emre Caglar YILDIZ
+ Tested on: Ubuntu/Debian family
+ Modes: Install | Add User | Delete User | Uninstall
 Features:
  - Asks Public IP, Port, and NAT Interface on install
  - EasyRSA PKI bootstrap (CA, server cert, DH)
  - tls-auth key
  - PAM + Google Authenticator enforced (2FA)
  - ip_forward + iptables NAT (persisted)
  - Client .ovpn builder (inline certs + tls-auth, prompts for OTP via PAM)
  - Shows TOTP QR in terminal AND saves PNG under /etc/openvpn/google-qrcode
  - Keeps install vars in /etc/openvpn/.install-vars for later operations
  - User revoke (CRL) and cleanup
  - Full uninstall
