#!/bin/bash

# Check root
if [ "$EUID" -ne 0 ]; then
  echo "Silakan jalankan sebagai root"
  exit
fi

# Install Dependencies
apt-get update
apt-get install -y curl socat nginx xray-core vnstat speedtest-cli jq uuid-runtime

# Initial Setup
clear
echo "XRAY MULTI PORT SETUP"
echo "====================="
read -p "Masukkan domain Anda (misal: example.com): " DOMAIN
read -p "Masukkan email untuk registrasi SSL: " EMAIL

# Install acme.sh
curl https://get.acme.sh | sh -s email=$EMAIL
~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
~/.acme.sh/acme.sh --register-account -m $EMAIL
~/.acme.sh/acme.sh --issue -d "*.$DOMAIN" -d "$DOMAIN" --dns --yes-I-know-dns-manual-mode-enough-go-ahead-please
~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
--key-file       /etc/xray/xray.key \
--fullchain-file /etc/xray/xray.crt

# Nginx Configuration
cat > /etc/nginx/conf.d/xray.conf <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    
    location /trojan-ws {
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    
    location /vmess-ws {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    
    location /vless-ws {
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;
    
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    
    location /trojan-ws {
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    
    location /vmess-ws {
        proxy_pass http://127.0.0.1:10004;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
    
    location /vless-ws {
        proxy_pass http://127.0.0.1:10005;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
    }
}
EOF

# Xray Configuration
mkdir -p /etc/xray
UUID=$(xray uuid)
cat > /etc/xray/config.json <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [
    {
      "port": 10000,
      "protocol": "trojan",
      "settings": {
        "clients": [{"password": ""}],
        "fallbacks": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/trojan-ws"}
      },
      "sniffing": {"enabled": true}
    },
    {
      "port": 10001,
      "protocol": "vmess",
      "settings": {
        "clients": [{"id": ""}]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/vmess-ws"}
      },
      "sniffing": {"enabled": true}
    },
    {
      "port": 10002,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": ""}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/vless-ws"}
      },
      "sniffing": {"enabled": true}
    },
    {
      "port": 10003,
      "protocol": "trojan",
      "settings": {
        "clients": [{"password": ""}],
        "fallbacks": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/trojan-ws"},
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        }
      },
      "sniffing": {"enabled": true}
    },
    {
      "port": 10004,
      "protocol": "vmess",
      "settings": {
        "clients": [{"id": ""}]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/vmess-ws"},
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        }
      },
      "sniffing": {"enabled": true}
    },
    {
      "port": 10005,
      "protocol": "vless",
      "settings": {
        "clients": [{"id": ""}],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {"path": "/vless-ws"},
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/xray.crt",
              "keyFile": "/etc/xray/xray.key"
            }
          ]
        }
      },
      "sniffing": {"enabled": true}
    }
  ],
  "outbounds": [
    {"protocol": "freedom"},
    {"protocol": "blackhole", "tag": "blocked"}
  ]
}
EOF

# User Database
touch /etc/xray/users.json
echo '{"users":[]}' > /etc/xray/users.json

# API Server
cat > /usr/local/bin/xray-api.sh <<'EOF'
#!/bin/bash
while true; do
  echo -e "HTTP/1.1 200 OK\nContent-Type: application/json\n\n$(cat /etc/xray/users.json)" | nc -l -p 80 -q 1 | while read line; do
    if [[ $line =~ "GET /?create=" ]]; then
      USERNAME=$(echo $line | grep -oP 'create=\K[^ ]+')
      UUID=$(xray uuid)
      sed -i "s/\"users\":\[/&{\"username\":\"$USERNAME\",\"uuid\":\"$UUID\"},/" /etc/xray/users.json
      echo "{\"status\":\"success\",\"username\":\"$USERNAME\",\"uuid\":\"$UUID\"}"
    fi
  done
done
EOF

chmod +x /usr/local/bin/xray-api.sh

# Menu System
while true; do
  clear
  echo "XRAY MANAGEMENT MENU"
  echo "===================="
  echo "1. Buat Akun Baru"
  echo "2. Cek Akun"
  echo "3. Ganti Domain"
  echo "4. Cek Pemakaian (vnstat)"
  echo "5. Speedtest"
  echo "6. Generate SSL"
  echo "7. Keluar"
  read -p "Pilih opsi [1-7]: " OPT
  
  case $OPT in
    1)
      read -p "Masukkan username: " USER
      UUID=$(xray uuid)
      jq ".users += [{\"username\":\"$USER\",\"uuid\":\"$UUID\"}]" /etc/xray/users.json > tmp.json
      mv tmp.json /etc/xray/users.json
      systemctl restart xray
      echo "User $USER berhasil dibuat"
      echo "UUID: $UUID"
      read -p "Tekan enter untuk lanjut..."
      ;;
    2)
      echo "Daftar User:"
      jq -r '.users[] | "\(.username) : \(.uuid)"' /etc/xray/users.json
      read -p "Tekan enter untuk lanjut..."
      ;;
    3)
      read -p "Masukkan domain baru: " NEWDOMAIN
      sed -i "s/$DOMAIN/$NEWDOMAIN/g" /etc/nginx/conf.d/xray.conf
      systemctl reload nginx
      DOMAIN=$NEWDOMAIN
      echo "Domain berhasil diubah"
      read -p "Tekan enter untuk lanjut..."
      ;;
    4)
      vnstat
      read -p "Tekan enter untuk lanjut..."
      ;;
    5)
      speedtest
      read -p "Tekan enter untuk lanjut..."
      ;;
    6)
      ~/.acme.sh/acme.sh --renew -d $DOMAIN --force
      systemctl restart nginx xray
      echo "SSL diperbarui"
      read -p "Tekan enter untuk lanjut..."
      ;;
    7)
      exit 0
      ;;
  esac
done

# Start Services
systemctl enable --now nginx xray
nohup /usr/local/bin/xray-api.sh > /dev/null 2>&1 &
