#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
  echo -e "${RED}Script ini harus dijalankan sebagai root!${NC}"
  exit 1
fi

# Check Ubuntu version
UBUNTU_VERSION=$(lsb_release -rs)
if [ "$UBUNTU_VERSION" != "24.04" ]; then
  echo -e "${YELLOW}Script ini diuji untuk Ubuntu 24.04. Versi Anda: $UBUNTU_VERSION${NC}"
  read -p "Lanjutkan instalasi? (y/n): " proceed
  if [ "$proceed" != "y" ]; then
    exit 1
  fi
fi

# Update system
echo -e "${BLUE}Memperbarui sistem...${NC}"
apt update && apt upgrade -y
apt install -y curl wget sudo nano git ufw vnstat speedtest-cli jq socat

# Install necessary tools
echo -e "${BLUE}Menginstal tools yang diperlukan...${NC}"
apt install -y qrencode net-tools cron

# Install Nginx
echo -e "${BLUE}Menginstal Nginx...${NC}"
apt install -y nginx
systemctl enable nginx

# Install Xray
echo -e "${BLUE}Menginstal Xray...${NC}"
bash -c "$(curl -L https://raw.githubusercontent.com/FD-ZENN/OPENSOURCE-AUTOSCRIPT-XRAY/main/xray-install.sh)" @ install

# Install acme.sh for SSL
echo -e "${BLUE}Menginstal acme.sh...${NC}"
curl https://get.acme.sh | sh -s email=admin@example.com
source ~/.bashrc

# Setup firewall
echo -e "${BLUE}Mengkonfigurasi firewall...${NC}"
ufw allow 22
ufw allow 80
ufw allow 443
ufw --force enable

# Setup vnstat
echo -e "${BLUE}Mengkonfigurasi vnstat...${NC}"
systemctl enable vnstat
systemctl start vnstat

# Create config directory
mkdir -p /etc/xray/config
mkdir -p /etc/xray/users
mkdir -p /var/log/xray

# Ask for domain
clear
echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}          AUTO INSTALL XRAY MULTI PORT            ${NC}"
echo -e "${GREEN}==================================================${NC}"
echo ""
read -p "Masukkan domain Anda (contoh: example.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
  echo -e "${RED}Domain tidak boleh kosong!${NC}"
  exit 1
fi

# Set domain to environment
echo "DOMAIN=$DOMAIN" > /etc/xray/config/domain.conf
echo "IP_ADDRESS=$(curl -s ifconfig.me)" >> /etc/xray/config/domain.conf

# Generate UUID
UUID=$(xray uuid)
echo "UUID=$UUID" > /etc/xray/config/uuid.conf

# Generate password for Trojan
TROJAN_PASSWORD=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 16)
echo "TROJAN_PASSWORD=$TROJAN_PASSWORD" >> /etc/xray/config/uuid.conf

# Generate SSL
echo -e "${BLUE}Membuat sertifikat SSL...${NC}"
/root/.acme.sh/acme.sh --issue -d $DOMAIN --standalone -k ec-256 --force
/root/.acme.sh/acme.sh --installcert -d $DOMAIN --fullchainpath /etc/xray/config/xray.crt --keypath /etc/xray/config/xray.key --ecc

# Create renewal script
echo -e "${BLUE}Membuat skrip pembaruan SSL...${NC}"
cat > /etc/xray/config/renew_ssl.sh << EOF
#!/bin/bash
/root/.acme.sh/acme.sh --issue -d $DOMAIN --standalone -k ec-256 --force
/root/.acme.sh/acme.sh --installcert -d $DOMAIN --fullchainpath /etc/xray/config/xray.crt --keypath /etc/xray/config/xray.key --ecc
systemctl restart xray
systemctl restart nginx
EOF
chmod +x /etc/xray/config/renew_ssl.sh

# Add to cron
(crontab -l 2>/dev/null; echo "0 0 * * * /etc/xray/config/renew_ssl.sh") | crontab -

# Create Xray config
echo -e "${BLUE}Membuat konfigurasi Xray...${NC}"
cat > /etc/xray/config.json << EOF
{
  "log": {
    "loglevel": "warning",
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log"
  },
  "inbounds": [
    {
      "port": 8443,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/config/xray.crt",
              "keyFile": "/etc/xray/config/xray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vless",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8080,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vless",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8443,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/config/xray.crt",
              "keyFile": "/etc/xray/config/xray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/vmess",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8080,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/vmess",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8443,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/config/xray.crt",
              "keyFile": "/etc/xray/config/xray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/trojan",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": 8080,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "/trojan",
          "headers": {
            "Host": "$DOMAIN"
          }
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  }
}
EOF

# Create Nginx config
echo -e "${BLUE}Membuat konfigurasi Nginx...${NC}"
cat > /etc/nginx/sites-available/xray << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    
    location / {
        return 301 https://\$host\$request_uri;
    }
    
    location /vless {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vmess {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /trojan {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/xray/config/xray.crt;
    ssl_certificate_key /etc/xray/config/xray.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    
    location / {
        root /var/www/html;
        index index.html;
    }
    
    location /vless {
        proxy_pass https://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /vmess {
        proxy_pass https://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /trojan {
        proxy_pass https://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

# Enable Nginx config
ln -s /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/
rm /etc/nginx/sites-enabled/default

# Create default web page
echo -e "${BLUE}Membuat halaman web default...${NC}"
mkdir -p /var/www/html
cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to $DOMAIN</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            text-align: center;
            margin-top: 50px;
            background-color: #f5f5f5;
        }
        h1 {
            color: #333;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Welcome to $DOMAIN</h1>
        <p>This server is running Xray with Nginx reverse proxy.</p>
        <p>If you see this page, the web server is successfully installed and working.</p>
    </div>
</body>
</html>
EOF

# Restart services
echo -e "${BLUE}Merestart layanan...${NC}"
systemctl restart nginx
systemctl restart xray

# Create menu script
echo -e "${BLUE}Membuat skrip menu...${NC}"
cat > /usr/local/bin/xray-menu << EOF
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Load config
source /etc/xray/config/domain.conf
source /etc/xray/config/uuid.conf

# Function to create user
create_user() {
    echo -e "\${BLUE}Membuat pengguna baru...\${NC}"
    read -p "Masukkan nama pengguna: " username
    
    if [ -z "\$username" ]; then
        echo -e "\${RED}Nama pengguna tidak boleh kosong!\${NC}"
        return 1
    fi
    
    if [ -f "/etc/xray/users/\$username.json" ]; then
        echo -e "\${RED}Pengguna sudah ada!\${NC}"
        return 1
    fi
    
    # Generate UUID for user
    user_uuid=\$(xray uuid)
    
    # Create user config
    cat > "/etc/xray/users/\$username.json" << EOL
{
    "username": "\$username",
    "uuid": "\$user_uuid",
    "password": "$TROJAN_PASSWORD",
    "created_at": "\$(date +'%Y-%m-%d %H:%M:%S')"
}
EOL
    
    # Add user to Xray config
    jq --arg uuid "\$user_uuid" '.inbounds[0].settings.clients += [{"id": \$uuid}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[1].settings.clients += [{"id": \$uuid}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[2].settings.clients += [{"id": \$uuid}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[3].settings.clients += [{"id": \$uuid}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[4].settings.clients += [{"password": "$TROJAN_PASSWORD"}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[5].settings.clients += [{"password": "$TROJAN_PASSWORD"}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    
    # Restart Xray
    systemctl restart xray
    
    # Show user info
    echo -e "\${GREEN}Pengguna berhasil dibuat!\${NC}"
    echo -e "\${BLUE}Informasi Pengguna:\${NC}"
    echo -e "Nama Pengguna: \${YELLOW}\$username\${NC}"
    echo -e "Domain: \${YELLOW}\$DOMAIN\${NC}"
    echo -e "Alamat IP: \${YELLOW}\$IP_ADDRESS\${NC}"
    echo ""
    echo -e "\${GREEN}Konfigurasi VLESS WS TLS:\${NC}"
    echo -e "Port: \${YELLOW}443\${NC}"
    echo -e "UUID: \${YELLOW}\$user_uuid\${NC}"
    echo -e "Path: \${YELLOW}/vless\${NC}"
    echo -e "SNI: \${YELLOW}\$DOMAIN\${NC}"
    echo ""
    echo -e "\${GREEN}Konfigurasi VLESS WS HTTP:\${NC}"
    echo -e "Port: \${YELLOW}80\${NC}"
    echo -e "UUID: \${YELLOW}\$user_uuid\${NC}"
    echo -e "Path: \${YELLOW}/vless\${NC}"
    echo -e "Host: \${YELLOW}\$DOMAIN\${NC}"
    echo ""
    echo -e "\${GREEN}Konfigurasi VMESS WS TLS:\${NC}"
    echo -e "Port: \${YELLOW}443\${NC}"
    echo -e "UUID: \${YELLOW}\$user_uuid\${NC}"
    echo -e "Path: \${YELLOW}/vmess\${NC}"
    echo -e "SNI: \${YELLOW}\$DOMAIN\${NC}"
    echo ""
    echo -e "\${GREEN}Konfigurasi VMESS WS HTTP:\${NC}"
    echo -e "Port: \${YELLOW}80\${NC}"
    echo -e "UUID: \${YELLOW}\$user_uuid\${NC}"
    echo -e "Path: \${YELLOW}/vmess\${NC}"
    echo -e "Host: \${YELLOW}\$DOMAIN\${NC}"
    echo ""
    echo -e "\${GREEN}Konfigurasi Trojan WS TLS:\${NC}"
    echo -e "Port: \${YELLOW}443\${NC}"
    echo -e "Password: \${YELLOW}$TROJAN_PASSWORD\${NC}"
    echo -e "Path: \${YELLOW}/trojan\${NC}"
    echo -e "SNI: \${YELLOW}\$DOMAIN\${NC}"
    echo ""
    echo -e "\${GREEN}Konfigurasi Trojan WS HTTP:\${NC}"
    echo -e "Port: \${YELLOW}80\${NC}"
    echo -e "Password: \${YELLOW}$TROJAN_PASSWORD\${NC}"
    echo -e "Path: \${YELLOW}/trojan\${NC}"
    echo -e "Host: \${YELLOW}\$DOMAIN\${NC}"
    
    # Generate QR codes
    echo ""
    echo -e "\${BLUE}QR Code VLESS WS TLS:\${NC}"
    vless_tls="vless://\$user_uuid@\$DOMAIN:443?path=%2Fvless&security=tls&encryption=none&type=ws&sni=\$DOMAIN#VLESS_WS_TLS_\$username"
    qrencode -t ANSIUTF8 "\$vless_tls"
    echo -e "\${YELLOW}\$vless_tls\${NC}"
    
    echo ""
    echo -e "\${BLUE}QR Code VLESS WS HTTP:\${NC}"
    vless_http="vless://\$user_uuid@\$DOMAIN:80?path=%2Fvless&security=none&encryption=none&type=ws&host=\$DOMAIN#VLESS_WS_HTTP_\$username"
    qrencode -t ANSIUTF8 "\$vless_http"
    echo -e "\${YELLOW}\$vless_http\${NC}"
    
    echo ""
    echo -e "\${BLUE}QR Code VMESS WS TLS:\${NC}"
    vmess_tls=\$(echo '{
        "v": "2",
        "ps": "VMESS_WS_TLS_'"\$username"'",
        "add": "'"\$DOMAIN"'",
        "port": "443",
        "id": "'"\$user_uuid"'",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "'"\$DOMAIN"'",
        "path": "/vmess",
        "tls": "tls",
        "sni": "'"\$DOMAIN"'",
        "alpn": ""
    }' | base64 -w 0)
    vmess_tls_link="vmess://\$vmess_tls"
    qrencode -t ANSIUTF8 "\$vmess_tls_link"
    echo -e "\${YELLOW}\$vmess_tls_link\${NC}"
    
    echo ""
    echo -e "\${BLUE}QR Code VMESS WS HTTP:\${NC}"
    vmess_http=\$(echo '{
        "v": "2",
        "ps": "VMESS_WS_HTTP_'"\$username"'",
        "add": "'"\$DOMAIN"'",
        "port": "80",
        "id": "'"\$user_uuid"'",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "'"\$DOMAIN"'",
        "path": "/vmess",
        "tls": "",
        "sni": "",
        "alpn": ""
    }' | base64 -w 0)
    vmess_http_link="vmess://\$vmess_http"
    qrencode -t ANSIUTF8 "\$vmess_http_link"
    echo -e "\${YELLOW}\$vmess_http_link\${NC}"
    
    echo ""
    echo -e "\${BLUE}QR Code Trojan WS TLS:\${NC}"
    trojan_tls="trojan://$TROJAN_PASSWORD@\$DOMAIN:443?path=%2Ftrojan&security=tls&type=ws&sni=\$DOMAIN#TROJAN_WS_TLS_\$username"
    qrencode -t ANSIUTF8 "\$trojan_tls"
    echo -e "\${YELLOW}\$trojan_tls\${NC}"
    
    echo ""
    echo -e "\${BLUE}QR Code Trojan WS HTTP:\${NC}"
    trojan_http="trojan://$TROJAN_PASSWORD@\$DOMAIN:80?path=%2Ftrojan&security=none&type=ws&host=\$DOMAIN#TROJAN_WS_HTTP_\$username"
    qrencode -t ANSIUTF8 "\$trojan_http"
    echo -e "\${YELLOW}\$trojan_http\${NC}"
}

# Function to check users
check_users() {
    echo -e "\${BLUE}Daftar Pengguna:\${NC}"
    echo -e "\${GREEN}==================================================\${NC}"
    for user_file in /etc/xray/users/*.json; do
        if [ -f "\$user_file" ]; then
            username=\$(jq -r '.username' \$user_file)
            uuid=\$(jq -r '.uuid' \$user_file)
            created_at=\$(jq -r '.created_at' \$user_file)
            
            echo -e "\${YELLOW}Nama Pengguna: \$username\${NC}"
            echo -e "UUID: \$uuid"
            echo -e "Dibuat pada: \$created_at"
            echo -e "\${GREEN}==================================================\${NC}"
        fi
    done
}

# Function to change domain
change_domain() {
    echo -e "\${BLUE}Mengubah domain...\${NC}"
    read -p "Masukkan domain baru: " new_domain
    
    if [ -z "\$new_domain" ]; then
        echo -e "\${RED}Domain tidak boleh kosong!\${NC}"
        return 1
    fi
    
    # Update domain config
    echo "DOMAIN=\$new_domain" > /etc/xray/config/domain.conf
    echo "IP_ADDRESS=\$(curl -s ifconfig.me)" >> /etc/xray/config/domain.conf
    
    # Generate new SSL
    echo -e "\${BLUE}Membuat sertifikat SSL baru...\${NC}"
    /root/.acme.sh/acme.sh --issue -d \$new_domain --standalone -k ec-256 --force
    /root/.acme.sh/acme.sh --installcert -d \$new_domain --fullchainpath /etc/xray/config/xray.crt --keypath /etc/xray/config/xray.key --ecc
    
    # Update Nginx config
    sed -i "s/\$DOMAIN/\$new_domain/g" /etc/nginx/sites-available/xray
    
    # Update Xray config
    sed -i "s/\$DOMAIN/\$new_domain/g" /etc/xray/config.json
    
    # Restart services
    systemctl restart nginx
    systemctl restart xray
    
    echo -e "\${GREEN}Domain berhasil diubah ke \$new_domain\${NC}"
}

# Function to check traffic usage
check_usage() {
    echo -e "\${BLUE}Pemakaian Bandwidth:\${NC}"
    vnstat
}

# Function to run speedtest
run_speedtest() {
    echo -e "\${BLUE}Menjalankan Speedtest...\${NC}"
    speedtest
}

# Function to generate SSL
generate_ssl() {
    echo -e "\${BLUE}Membuat ulang sertifikat SSL...\${NC}"
    /root/.acme.sh/acme.sh --issue -d \$DOMAIN --standalone -k ec-256 --force
    /root/.acme.sh/acme.sh --installcert -d \$DOMAIN --fullchainpath /etc/xray/config/xray.crt --keypath /etc/xray/config/xray.key --ecc
    systemctl restart xray
    systemctl restart nginx
    echo -e "\${GREEN}Sertifikat SSL berhasil diperbarui!\${NC}"
}

# Function to create user via API
api_create_user() {
    username=\$1
    if [ -z "\$username" ]; then
        echo -e "\${RED}Nama pengguna tidak boleh kosong!\${NC}"
        return 1
    fi
    
    if [ -f "/etc/xray/users/\$username.json" ]; then
        echo -e "\${RED}Pengguna sudah ada!\${NC}"
        return 1
    fi
    
    # Generate UUID for user
    user_uuid=\$(xray uuid)
    
    # Create user config
    cat > "/etc/xray/users/\$username.json" << EOL
{
    "username": "\$username",
    "uuid": "\$user_uuid",
    "password": "$TROJAN_PASSWORD",
    "created_at": "\$(date +'%Y-%m-%d %H:%M:%S')"
}
EOL
    
    # Add user to Xray config
    jq --arg uuid "\$user_uuid" '.inbounds[0].settings.clients += [{"id": \$uuid}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[1].settings.clients += [{"id": \$uuid}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[2].settings.clients += [{"id": \$uuid}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[3].settings.clients += [{"id": \$uuid}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[4].settings.clients += [{"password": "$TROJAN_PASSWORD"}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    jq --arg uuid "\$user_uuid" '.inbounds[5].settings.clients += [{"password": "$TROJAN_PASSWORD"}]' /etc/xray/config.json > /etc/xray/config.json.tmp && mv /etc/xray/config.json.tmp /etc/xray/config.json
    
    # Restart Xray
    systemctl restart xray
    
    # Return JSON response
    cat << EOL
{
    "status": "success",
    "message": "User created successfully",
    "data": {
        "username": "\$username",
        "uuid": "\$user_uuid",
        "password": "$TROJAN_PASSWORD",
        "domain": "$DOMAIN",
        "ip_address": "$IP_ADDRESS",
        "configurations": {
            "vless_ws_tls": {
                "port": 443,
                "uuid": "\$user_uuid",
                "path": "/vless",
                "sni": "$DOMAIN"
            },
            "vless_ws_http": {
                "port": 80,
                "uuid": "\$user_uuid",
                "path": "/vless",
                "host": "$DOMAIN"
            },
            "vmess_ws_tls": {
                "port": 443,
                "uuid": "\$user_uuid",
                "path": "/vmess",
                "sni": "$DOMAIN"
            },
            "vmess_ws_http": {
                "port": 80,
                "uuid": "\$user_uuid",
                "path": "/vmess",
                "host": "$DOMAIN"
            },
            "trojan_ws_tls": {
                "port": 443,
                "password": "$TROJAN_PASSWORD",
                "path": "/trojan",
                "sni": "$DOMAIN"
            },
            "trojan_ws_http": {
                "port": 80,
                "password": "$TROJAN_PASSWORD",
                "path": "/trojan",
                "host": "$DOMAIN"
            }
        }
    }
}
EOL
}

# Main menu
while true; do
    clear
    echo -e "\${GREEN}==================================================\${NC}"
    echo -e "\${GREEN}          XRAY MANAGER MENU - \${YELLOW}\$DOMAIN\${NC}"
    echo -e "\${GREEN}==================================================\${NC}"
    echo -e "\${BLUE}1. Buat Akun\${NC}"
    echo -e "\${BLUE}2. Cek Akun\${NC}"
    echo -e "\${BLUE}3. Ganti Domain\${NC}"
    echo -e "\${BLUE}4. Cek Pemakaian (vnstat)\${NC}"
    echo -e "\${BLUE}5. Speedtest\${NC}"
    echo -e "\${BLUE}6. Generate SSL\${NC}"
    echo -e "\${RED}0. Keluar\${NC}"
    echo -e "\${GREEN}==================================================\${NC}"
    read -p "Pilih opsi [0-6]: " option
    
    case \$option in
        1) create_user ;;
        2) check_users ;;
        3) change_domain ;;
        4) check_usage ;;
        5) run_speedtest ;;
        6) generate_ssl ;;
        0) echo -e "\${GREEN}Keluar...\${NC}"; exit 0 ;;
        *) echo -e "\${RED}Pilihan tidak valid!\${NC}"; sleep 1 ;;
    esac
    
    read -p "Tekan Enter untuk melanjutkan..." dummy
done
EOF

# Make menu executable
chmod +x /usr/local/bin/xray-menu

# Create API script
echo -e "${BLUE}Membuat skrip API...${NC}"
cat > /usr/local/bin/xray-api << EOF
#!/bin/bash

# Load config
source /etc/xray/config/domain.conf
source /etc/xray/config/uuid.conf

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "Script ini harus dijalankan sebagai root!"
  exit 1
fi

# Check for action parameter
if [ -z "\$1" ]; then
  echo "Usage: \$0 <action> [username]"
  exit 1
fi

ACTION=\$1
USERNAME=\$2

case "\$ACTION" in
  create)
    if [ -z "\$USERNAME" ]; then
      echo "Username harus disertakan!"
      exit 1
    fi
    
    # Call create user function from menu script
    /usr/local/bin/xray-menu api_create_user "\$USERNAME"
    ;;
  *)
    echo "Aksi tidak valid!"
    exit 1
    ;;
esac
EOF

# Make API script executable
chmod +x /usr/local/bin/xray-api

# Create systemd service file for auto start
echo -e "${BLUE}Membuat layanan systemd...${NC}"
cat > /etc/systemd/system/xray-autostart.service << EOF
[Unit]
Description=Xray Auto Start Service
After=network.target

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'systemctl start xray && systemctl start nginx'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Enable auto start service
systemctl daemon-reload
systemctl enable xray-autostart

# Create log rotation
echo -e "${BLUE}Mengkonfigurasi log rotation...${NC}"
cat > /etc/logrotate.d/xray << EOF
/var/log/xray/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 nobody nogroup
    postrotate
        systemctl reload xray > /dev/null 2>&1 || true
    endscript
}
EOF

# Create backup script
echo -e "${BLUE}Membuat skrip backup...${NC}"
cat > /etc/xray/backup.sh << EOF
#!/bin/bash

BACKUP_DIR="/root/xray-backup"
TIMESTAMP=\$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="\$BACKUP_DIR/xray_backup_\$TIMESTAMP.tar.gz"

# Create backup directory
mkdir -p \$BACKUP_DIR

# Create backup
tar -czf \$BACKUP_FILE /etc/xray/ /etc/nginx/sites-available/xray /var/www/html/

echo "Backup created: \$BACKUP_FILE"

# Keep only last 7 backups
find \$BACKUP_DIR -name "xray_backup_*.tar.gz" -mtime +7 -delete
EOF

chmod +x /etc/xray/backup.sh

# Add backup to cron (weekly backup)
(crontab -l 2>/dev/null; echo "0 2 * * 0 /etc/xray/backup.sh") | crontab -

# Create restore script
echo -e "${BLUE}Membuat skrip restore...${NC}"
cat > /etc/xray/restore.sh << EOF
#!/bin/bash

if [ -z "\$1" ]; then
    echo "Usage: \$0 <backup_file>"
    echo "Available backups:"
    ls -la /root/xray-backup/
    exit 1
fi

BACKUP_FILE=\$1

if [ ! -f "\$BACKUP_FILE" ]; then
    echo "Backup file not found: \$BACKUP_FILE"
    exit 1
fi

echo "Restoring from: \$BACKUP_FILE"
echo "This will overwrite current configuration!"
read -p "Continue? (y/n): " confirm

if [ "\$confirm" = "y" ]; then
    tar -xzf \$BACKUP_FILE -C /
    systemctl restart xray
    systemctl restart nginx
    echo "Restore completed!"
else
    echo "Restore cancelled."
fi
EOF

chmod +x /etc/xray/restore.sh

# Create status check script
echo -e "${BLUE}Membuat skrip status check...${NC}"
cat > /usr/local/bin/xray-status << EOF
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Load config
source /etc/xray/config/domain.conf 2>/dev/null || { echo "Config not found"; exit 1; }

echo -e "\${GREEN}==================================================\${NC}"
echo -e "\${GREEN}          XRAY SERVER STATUS CHECK               \${NC}"
echo -e "\${GREEN}==================================================\${NC}"

# Check Xray service status
if systemctl is-active --quiet xray; then
    echo -e "Xray Service: \${GREEN}Running\${NC}"
else
    echo -e "Xray Service: \${RED}Stopped\${NC}"
fi

# Check Nginx service status
if systemctl is-active --quiet nginx; then
    echo -e "Nginx Service: \${GREEN}Running\${NC}"
else
    echo -e "Nginx Service: \${RED}Stopped\${NC}"
fi

# Check SSL certificate
if [ -f "/etc/xray/config/xray.crt" ]; then
    CERT_EXPIRY=\$(openssl x509 -in /etc/xray/config/xray.crt -noout -enddate | cut -d= -f2)
    echo -e "SSL Certificate: \${GREEN}Available\${NC}"
    echo -e "Expires: \${YELLOW}\$CERT_EXPIRY\${NC}"
else
    echo -e "SSL Certificate: \${RED}Not Found\${NC}"
fi

# Check domain connectivity
echo -e "\${BLUE}Testing domain connectivity...\${NC}"
if curl -s --connect-timeout 5 http://\$DOMAIN > /dev/null; then
    echo -e "HTTP Connection: \${GREEN}OK\${NC}"
else
    echo -e "HTTP Connection: \${RED}Failed\${NC}"
fi

if curl -s --connect-timeout 5 https://\$DOMAIN > /dev/null; then
    echo -e "HTTPS Connection: \${GREEN}OK\${NC}"
else
    echo -e "HTTPS Connection: \${RED}Failed\${NC}"
fi

# Check ports
echo -e "\${BLUE}Checking ports...\${NC}"
if netstat -tlnp | grep -q ":80 "; then
    echo -e "Port 80: \${GREEN}Listening\${NC}"
else
    echo -e "Port 80: \${RED}Not Listening\${NC}"
fi

if netstat -tlnp | grep -q ":443 "; then
    echo -e "Port 443: \${GREEN}Listening\${NC}"
else
    echo -e "Port 443: \${RED}Not Listening\${NC}"
fi

if netstat -tlnp | grep -q ":8080 "; then
    echo -e "Port 8080: \${GREEN}Listening\${NC}"
else
    echo -e "Port 8080: \${RED}Not Listening\${NC}"
fi

if netstat -tlnp | grep -q ":8443 "; then
    echo -e "Port 8443: \${GREEN}Listening\${NC}"
else
    echo -e "Port 8443: \${RED}Not Listening\${NC}"
fi

# System resources
echo -e "\${BLUE}System Resources:\${NC}"
echo -e "Memory Usage: \${YELLOW}\$(free | grep Mem | awk '{printf \"%.1f%%\", \$3/\$2 * 100.0}')\${NC}"
echo -e "Disk Usage: \${YELLOW}\$(df -h / | awk 'NR==2{printf \"%s\", \$5}')\${NC}"
echo -e "Load Average: \${YELLOW}\$(uptime | awk -F'load average:' '{print \$2}')\${NC}"

# Count users
USER_COUNT=\$(find /etc/xray/users -name "*.json" -type f | wc -l)
echo -e "Total Users: \${YELLOW}\$USER_COUNT\${NC}"

echo -e "\${GREEN}==================================================\${NC}"
EOF

chmod +x /usr/local/bin/xray-status

# Create uninstall script
echo -e "${BLUE}Membuat skrip uninstall...${NC}"
cat > /usr/local/bin/xray-uninstall << EOF
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

echo -e "\${RED}==================================================\${NC}"
echo -e "\${RED}          XRAY UNINSTALL SCRIPT                   \${NC}"
echo -e "\${RED}==================================================\${NC}"
echo -e "\${YELLOW}WARNING: This will completely remove Xray and all configurations!\${NC}"
echo -e "\${YELLOW}Make sure you have backed up your data before proceeding.\${NC}"
echo ""
read -p "Are you sure you want to continue? (type 'YES' to confirm): " confirm

if [ "\$confirm" != "YES" ]; then
    echo -e "\${GREEN}Uninstall cancelled.\${NC}"
    exit 0
fi

echo -e "\${RED}Starting uninstall process...\${NC}"

# Stop services
echo -e "\${YELLOW}Stopping services...\${NC}"
systemctl stop xray 2>/dev/null
systemctl stop nginx 2>/dev/null
systemctl disable xray 2>/dev/null
systemctl disable nginx 2>/dev/null
systemctl disable xray-autostart 2>/dev/null

# Remove Xray
echo -e "\${YELLOW}Removing Xray...\${NC}"
bash -c "\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge 2>/dev/null

# Remove packages
echo -e "\${YELLOW}Removing packages...\${NC}"
apt remove --purge -y nginx qrencode 2>/dev/null

# Remove files and directories
echo -e "\${YELLOW}Removing configuration files...\${NC}"
rm -rf /etc/xray/
rm -rf /var/log/xray/
rm -f /etc/nginx/sites-available/xray
rm -f /etc/nginx/sites-enabled/xray
rm -f /etc/systemd/system/xray-autostart.service
rm -f /etc/logrotate.d/xray
rm -f /usr/local/bin/xray-menu
rm -f /usr/local/bin/xray-api
rm -f /usr/local/bin/xray-status
rm -f /usr/local/bin/xray-uninstall

# Remove acme.sh
echo -e "\${YELLOW}Removing acme.sh...\${NC}"
/root/.acme.sh/acme.sh --uninstall 2>/dev/null
rm -rf /root/.acme.sh/

# Remove cron jobs
echo -e "\${YELLOW}Removing cron jobs...\${NC}"
crontab -l 2>/dev/null | grep -v "xray\|acme" | crontab - 2>/dev/null

# Clean up
systemctl daemon-reload
apt autoremove -y 2>/dev/null
apt autoclean 2>/dev/null

echo -e "\${GREEN}==================================================\${NC}"
echo -e "\${GREEN}Xray has been completely uninstalled!\${NC}"
echo -e "\${GREEN}==================================================\${NC}"
EOF

chmod +x /usr/local/bin/xray-uninstall

# Create update script
echo -e "${BLUE}Membuat skrip update...${NC}"
cat > /usr/local/bin/xray-update << EOF
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "\${BLUE}==================================================\${NC}"
echo -e "\${BLUE}          XRAY UPDATE SCRIPT                      \${NC}"
echo -e "\${BLUE}==================================================\${NC}"

# Update Xray
echo -e "\${YELLOW}Updating Xray core...\${NC}"
bash -c "\$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# Update system packages
echo -e "\${YELLOW}Updating system packages...\${NC}"
apt update && apt upgrade -y

# Restart services
echo -e "\${YELLOW}Restarting services...\${NC}"
systemctl restart xray
systemctl restart nginx

echo -e "\${GREEN}Update completed!\${NC}"
xray-status
EOF

chmod +x /usr/local/bin/xray-update

# Final configuration check
echo -e "${BLUE}Melakukan pengecekan konfigurasi final...${NC}"
nginx -t
if [ $? -ne 0 ]; then
    echo -e "${RED}Nginx configuration error! Please check manually.${NC}"
    exit 1
fi

# Final service restart
echo -e "${BLUE}Restart layanan terakhir...${NC}"
systemctl restart nginx
systemctl restart xray
systemctl enable nginx
systemctl enable xray

# Wait for services to start
sleep 3

# Final status check
if ! systemctl is-active --quiet xray; then
    echo -e "${RED}Xray service failed to start!${NC}"
    exit 1
fi

if ! systemctl is-active --quiet nginx; then
    echo -e "${RED}Nginx service failed to start!${NC}"
    exit 1
fi

# Create alias for easy access
echo 'alias menu="xray-menu"' >> ~/.bashrc
echo 'alias status="xray-status"' >> ~/.bashrc

# Installation completed
clear
echo -e "${GREEN}===================================================${NC}"
echo -e "${GREEN}       INSTALASI XRAY BERHASIL DISELESAIKAN!      ${NC}"
echo -e "${GREEN}===================================================${NC}"
echo ""
echo -e "${BLUE}Informasi Server:${NC}"
echo -e "Domain: ${YELLOW}$DOMAIN${NC}"
echo -e "IP Address: ${YELLOW}$(curl -s ifconfig.me)${NC}"
echo -e "UUID: ${YELLOW}$UUID${NC}"
echo -e "Trojan Password: ${YELLOW}$TROJAN_PASSWORD${NC}"
echo ""
echo -e "${BLUE}Port yang digunakan:${NC}"
echo -e "HTTP: ${YELLOW}80${NC}"
echo -e "HTTPS: ${YELLOW}443${NC}"
echo -e "Xray HTTP: ${YELLOW}8080${NC}"
echo -e "Xray HTTPS: ${YELLOW}8443${NC}"
echo ""
echo -e "${BLUE}Protokol yang tersedia:${NC}"
echo -e "- ${YELLOW}VLESS WS TLS/HTTP${NC}"
echo -e "- ${YELLOW}VMESS WS TLS/HTTP${NC}"
echo -e "- ${YELLOW}Trojan WS TLS/HTTP${NC}"
echo ""
echo -e "${BLUE}Perintah yang tersedia:${NC}"
echo -e "- ${YELLOW}menu${NC} atau ${YELLOW}xray-menu${NC} - Menu utama"
echo -e "- ${YELLOW}xray-status${NC} - Cek status server"
echo -e "- ${YELLOW}xray-update${NC} - Update Xray"
echo -e "- ${YELLOW}xray-uninstall${NC} - Uninstall Xray"
echo ""
echo -e "${BLUE}File konfigurasi:${NC}"
echo -e "- Xray: ${YELLOW}/etc/xray/config.json${NC}"
echo -e "- Nginx: ${YELLOW}/etc/nginx/sites-available/xray${NC}"
echo -e "- SSL: ${YELLOW}/etc/xray/config/xray.crt & xray.key${NC}"
echo -e "- Users: ${YELLOW}/etc/xray/users/${NC}"
echo ""
echo -e "${BLUE}Log files:${NC}"
echo -e "- Xray Access: ${YELLOW}/var/log/xray/access.log${NC}"
echo -e "- Xray Error: ${YELLOW}/var/log/xray/error.log${NC}"
echo -e "- Nginx Access: ${YELLOW}/var/log/nginx/access.log${NC}"
echo -e "- Nginx Error: ${YELLOW}/var/log/nginx/error.log${NC}"
echo ""
echo -e "${GREEN}Ketik '${YELLOW}menu${GREEN}' untuk mulai membuat akun!${NC}"
echo -e "${GREEN}===================================================${NC}"
echo ""

# Show current status
xray-status

echo ""
echo -e "${YELLOW}Reboot server sekarang? (y/n):${NC}"
read -p "" reboot_choice
if [ "$reboot_choice" = "y" ]; then
    echo -e "${GREEN}Server akan reboot dalam 5 detik...${NC}"
    sleep 5
    reboot
fi

echo -e "${GREEN}Instalasi selesai! Silakan reboot server secara manual jika diperlukan.${NC}"
