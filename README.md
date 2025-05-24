# OPENSOURCE-AUTOSCRIPT-XRAY
# 🚀 Xray Multi Port Auto Script

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-orange.svg)](https://ubuntu.com/)
[![Debian](https://img.shields.io/badge/Debian-10%2B-red.svg)](https://www.debian.org/)
[![Xray](https://img.shields.io/badge/Xray-Core-blue.svg)](https://github.com/XTLS/Xray-core)
[![Nginx](https://img.shields.io/badge/Nginx-Reverse%20Proxy-green.svg)](https://nginx.org/)

Autoscript untuk install dan konfigurasi Xray dengan multiple protocol, reverse proxy Nginx, dan management system lengkap. Mendukung TLS dan HTTP dengan WebSocket & gRPC transport.

## ✨ Features

### 🔐 Supported Protocols
- **Trojan** (WebSocket & gRPC)
- **Shadowsocks** (WebSocket & gRPC)  
- **VMess** (WebSocket & gRPC)
- **VLESS** (WebSocket & gRPC)

### 🌐 Multi Port Support
- **Port 443** (HTTPS/TLS) - Semua protokol
- **Port 80** (HTTP) - Semua protokol
- **Auto SSL** dengan Let's Encrypt
- **Wildcard Domain** support

### 🎛️ Management Features
- **Terminal Menu** interaktif
- **REST API** untuk automasi
- **User Database** dengan JSON
- **Bandwidth Monitoring** (vnstat)
- **System Information** lengkap
- **Auto Certificate** generation

### 🐛 Bug Host Support
- Support semua provider Indonesia
- Wildcard bug host
- Custom path untuk bypass DPI
- Multiple transport methods

## 📋 Requirements

- **OS**: Ubuntu 20.04+ atau Debian 10+
- **RAM**: Minimal 512MB
- **Storage**: Minimal 1GB free space
- **Network**: Public IP dengan domain
- **Access**: Root privileges

## 🚀 Quick Installation

### One-Line Install
```bash
bash <(curl -s https://raw.githubusercontent.com/FD-ZENN/OPENSOURCE-AUTOSCRIPT-XRAY/main/install-xray.sh)
```

### Manual Install
```bash
# Download script
wget -O xray-install.sh https://raw.githubusercontent.com/FD-ZENN/OPENSOURCE-AUTOSCRIPT-XRAY/main/install-xray.sh

# Make executable
chmod +x xray-install.sh

# Run as root
sudo ./xray-install.sh
```

## 🎯 Usage

### Terminal Menu
Setelah instalasi selesai, jalankan:
```bash
xray-menu
```

### Menu Options
```
1. Create User       - Buat akun baru
2. Check User        - Cek detail akun
3. Change Domain     - Ganti domain
4. Check Bandwidth   - Monitor penggunaan
5. Speedtest         - Test kecepatan
6. Generate SSL      - Generate certificate
7. List All Users    - Daftar semua user
8. Restart Services  - Restart layanan
9. System Info       - Info sistem
0. Exit              - Keluar
```

### API Usage

#### Create User
```bash
curl "http://YOUR_SERVER_IP:8080/?create=username"
```

#### Response Example
```json
{
  "success": true,
  "user": {
    "username": "testuser",
    "uuid": "12345678-1234-1234-1234-123456789012",
    "password": "randompassword123",
    "created_date": "2024-01-01T00:00:00.000Z",
    "expiry_date": "2024-01-31T00:00:00.000Z",
    "upload": 0,
    "download": 0
  },
  "configs": {
    "trojan_ws_tls": "trojan://password@domain.com:443?type=ws&path=/trojan-ws&security=tls&sni=domain.com#testuser_trojan_ws_tls",
    "trojan_grpc_tls": "trojan://password@domain.com:443?type=grpc&serviceName=trojan-grpc&security=tls&sni=domain.com#testuser_trojan_grpc_tls",
    "vmess_ws_tls": "vmess://base64encodedconfig",
    "vless_ws_tls": "vless://uuid@domain.com:443?type=ws&path=/vless-ws&security=tls&sni=domain.com#testuser_vless_ws_tls",
    "shadowsocks_ws_tls": "ss://base64pass@domain.com:443/?plugin=v2ray-plugin;tls;host=domain.com;path=/ss-ws#testuser_ss_ws_tls"
  }
}
```

## 📱 Client Configuration

### Trojan
```
Server: your-domain.com
Port: 443 (TLS) / 80 (HTTP)
Password: [generated-password]
Network: ws / grpc
Path: /trojan-ws (WebSocket) / trojan-grpc (gRPC)
TLS: Enable (443) / Disable (80)
SNI: your-domain.com
```

### VMess
```
Server: your-domain.com  
Port: 443 (TLS) / 80 (HTTP)
UUID: [generated-uuid]
AlterID: 0
Network: ws / grpc
Path: /vmess-ws (WebSocket) / vmess-grpc (gRPC)
TLS: Enable (443) / Disable (80)
SNI: your-domain.com
```

### VLESS  
```
Server: your-domain.com
Port: 443 (TLS) / 80 (HTTP)
UUID: [generated-uuid]
Network: ws / grpc
Path: /vless-ws (WebSocket) / vless-grpc (gRPC)
TLS: Enable (443) / Disable (80)
SNI: your-domain.com
```

### Shadowsocks
```
Server: your-domain.com
Port: 443 (TLS) / 80 (HTTP)
Method: aes-256-gcm
Password: [generated-password]
Plugin: v2ray-plugin
Plugin Options: tls;host=your-domain.com;path=/ss-ws (WebSocket)
Plugin Options: tls;host=your-domain.com;path=ss-grpc;mode=grpc (gRPC)
```

## 🔧 Advanced Configuration

### Custom Domain
```bash
# Ganti domain
echo "new-domain.com" > /etc/xray/domain.txt

# Update nginx config
sed -i 's/old-domain.com/new-domain.com/g' /etc/nginx/sites-available/xray

# Generate SSL baru
xray-menu
# Pilih option 6 (Generate SSL)
```

### Manual User Management
```bash
# Add user manual
/usr/local/bin/add-user username uuid password

# Check user database
cat /etc/xray/users.db | jq .

# Restart services
systemctl restart xray nginx xray-api
```

### Backup & Restore
```bash
# Backup user database
cp /etc/xray/users.db /root/users.db.backup

# Backup xray config
cp /usr/local/etc/xray/config.json /root/xray-config.backup

# Restore
cp /root/users.db.backup /etc/xray/users.db
cp /root/xray-config.backup /usr/local/etc/xray/config.json
systemctl restart xray
```

## 🛠️ Troubleshooting

### Check Service Status
```bash
# Check semua service
systemctl status xray nginx xray-api

# Check logs
journalctl -u xray -f
journalctl -u nginx -f
journalctl -u xray-api -f
```

### Port Issues
```bash
# Check port usage
ss -tuln | grep -E ':(80|443|8080)'

# Kill conflicting processes
fuser -k 80/tcp
fuser -k 443/tcp
fuser -k 8080/tcp
```

### SSL Certificate Issues
```bash
# Check certificate
certbot certificates

# Renew certificate
certbot renew

# Force renewal
certbot renew --force-renewal
```

### Nginx Configuration Test
```bash
# Test nginx config
nginx -t

# Reload nginx
systemctl reload nginx
```

## 📊 Monitoring & Logs

### Bandwidth Monitoring
```bash
# Install vnstat (sudah include di script)
vnstat -i eth0

# Real-time monitoring
vnstat -l -i eth0

# Monthly stats
vnstat -m -i eth0
```

### System Monitoring
```bash
# Check resources
htop
free -h
df -h

# Network connections
ss -tuln
netstat -tulpn
```

### Log Locations
```
Xray Logs: /var/log/xray/
Nginx Logs: /var/log/nginx/
API Logs: journalctl -u xray-api
SSL Logs: /var/log/letsencrypt/
```

## 🔄 Update & Maintenance

### Update Xray
```bash
# Update xray core
bash <(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)
systemctl restart xray
```

### Update Script
```bash
# Download latest script
wget -O /tmp/xray-update.sh https://raw.githubusercontent.com/yourusername/xray-multiport/main/update.sh
chmod +x /tmp/xray-update.sh
./tmp/xray-update.sh
```

### Certificate Renewal
```bash
# Auto renewal (crontab)
0 0 1 * * /usr/bin/certbot renew --quiet && /usr/bin/systemctl reload nginx
```

## 🐛 Bug Host Examples

### Telkomsel
```
Bug Host: www.vidio.com
SNI: your-domain.com
```

### Indosat
```  
Bug Host: support.apple.com
SNI: your-domain.com
```

### XL Axiata
```
Bug Host: m.xl.co.id
SNI: your-domain.com
```

### Tri/3
```
Bug Host: bima.tri.co.id  
SNI: your-domain.com
```

## 📖 FAQ

### Q: Apakah script ini gratis?
A: Ya, script ini sepenuhnya gratis dan open source.

### Q: Bisakah digunakan untuk komersial?
A: Ya, tetapi harap credit developer.

### Q: Support provider apa saja?
A: Semua provider Indonesia dengan bug host yang sesuai.

### Q: Berapa maksimal user?
A: Tergantung spesifikasi server, umumnya 100-500 user concurrent.

### Q: Apakah ada bandwidth limit?
A: Tidak ada limit dari script, tergantung server dan provider.

### Q: Bagaimana cara backup user?
A: Copy file `/etc/xray/users.db` dan config xray.

## 🤝 Contributing

Kontribusi sangat diterima! Silakan:

1. Fork repository ini
2. Buat branch fitur (`git checkout -b feature/AmazingFeature`)
3. Commit perubahan (`git commit -m 'Add some AmazingFeature'`)
4. Push ke branch (`git push origin feature/AmazingFeature`)
5. Buka Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## 👨‍💻 Author

**Your Name**


## ⭐ Support

Jika script ini membantu, berikan star ⭐ di repository ini!

### Donation

## 🔗 Links

- [Xray-core](https://github.com/XTLS/Xray-core)
- [Nginx](https://nginx.org/)
- [Let's Encrypt](https://letsencrypt.org/)
- [Node.js](https://nodejs.org/)

---

**⚠️ Disclaimer**: Script ini untuk keperluan edukasi dan penggunaan legal. Penggunaan untuk aktivitas ilegal adalah tanggung jawab pengguna.
