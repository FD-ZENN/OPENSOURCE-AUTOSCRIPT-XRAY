#!/bin/bash

# AutoScript X-UI Pro dengan Fitur API
# Versi: 1.0
# Penulis: Anonymous
# Sumber X-UI Pro: https://github.com/GFW4Fun/x-ui-pro

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Fungsi untuk memeriksa root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Script ini harus dijalankan sebagai root${NC}" >&2
        exit 1
    fi
}

# Fungsi untuk memeriksa OS
check_os() {
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
    elif grep -Eqi "debian" /etc/issue; then
        OS="debian"
    elif grep -Eqi "ubuntu" /etc/issue; then
        OS="ubuntu"
    elif grep -Eqi "centos|red hat|redhat" /etc/issue; then
        OS="centos"
    elif grep -Eqi "debian" /proc/version; then
        OS="debian"
    elif grep -Eqi "ubuntu" /proc/version; then
        OS="ubuntu"
    elif grep -Eqi "centos|red hat|redhat" /proc/version; then
        OS="centos"
    else
        echo -e "${RED}OS tidak dikenali. Script ini hanya support Debian, Ubuntu atau CentOS${NC}"
        exit 1
    fi
}

# Fungsi untuk memeriksa arch
check_arch() {
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then
        ARCH="amd64"
    elif [[ "$ARCH" == "aarch64" ]]; then
        ARCH="arm64"
    else
        echo -e "${RED}Architecture tidak didukung: $ARCH${NC}"
        exit 1
    fi
}

# Fungsi untuk install dependensi
install_dependencies() {
    echo -e "${YELLOW}Menginstall dependensi...${NC}"
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        apt-get update
        apt-get install -y curl wget socat bash-completion tar zip unzip jq
    elif [[ "$OS" == "centos" ]]; then
        yum install -y curl wget socat bash-completion tar zip unzip jq
    fi
    
    # Install certbot jika belum ada
    if ! command -v certbot &> /dev/null; then
        echo -e "${YELLOW}Menginstall certbot...${NC}"
        if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
            apt-get install -y certbot
        elif [[ "$OS" == "centos" ]]; then
            yum install -y certbot
        fi
    fi
}

# Fungsi untuk install X-UI Pro
install_xui_pro() {
    echo -e "${YELLOW}Menginstall X-UI Pro...${NC}"
    mkdir -p /usr/local/x-ui-pro
    cd /usr/local/x-ui-pro
    
    # Download binary terbaru
    LATEST_VERSION=$(curl -s https://api.github.com/repos/GFW4Fun/x-ui-pro/releases/latest | grep tag_name | cut -d '"' -f 4)
    wget -O x-ui-pro.tar.gz "https://github.com/GFW4Fun/x-ui-pro/releases/download/${LATEST_VERSION}/x-ui-pro-linux-${ARCH}.tar.gz"
    
    if [[ $? -ne 0 ]]; then
        echo -e "${RED}Gagal mendownload X-UI Pro${NC}"
        exit 1
    fi
    
    tar -xzf x-ui-pro.tar.gz
    rm -f x-ui-pro.tar.gz
    chmod +x x-ui-pro
    
    # Buat service
    cat > /etc/systemd/system/x-ui-pro.service <<EOF
[Unit]
Description=X-UI Pro Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/usr/local/x-ui-pro
ExecStart=/usr/local/x-ui-pro/x-ui-pro
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable x-ui-pro
    systemctl start x-ui-pro
    
    echo -e "${GREEN}X-UI Pro berhasil diinstall dan dijalankan${NC}"
}

# Fungsi untuk install API tambahan
install_api() {
    echo -e "${YELLOW}Menginstall API tambahan...${NC}"
    cd /usr/local/x-ui-pro
    
    # Buat direktori untuk API
    mkdir -p api
    cd api
    
    # Buat file konfigurasi API
    cat > config.json <<EOF
{
    "api_port": 54321,
    "api_secret": "$(openssl rand -hex 16)",
    "xui_path": "/usr/local/x-ui-pro",
    "xui_config": "/usr/local/x-ui-pro/config.json"
}
EOF

    # Buat script API
    cat > xui-api.sh <<'EOF'
#!/bin/bash

# API untuk X-UI Pro
# Endpoint untuk manajemen client dan kuota

CONFIG_FILE="/usr/local/x-ui-pro/api/config.json"
API_PORT=$(jq -r '.api_port' $CONFIG_FILE)
API_SECRET=$(jq -r '.api_secret' $CONFIG_FILE)
XUI_CONFIG=$(jq -r '.xui_config' $CONFIG_FILE)

# Fungsi untuk response JSON
json_response() {
    local status=$1
    local message=$2
    local data=$3
    
    jq -n \
        --arg status "$status" \
        --arg message "$message" \
        --argjson data "$data" \
        '{status: $status, message: $message, data: $data}'
}

# Fungsi untuk validasi secret
validate_secret() {
    local secret=$1
    if [[ "$secret" != "$API_SECRET" ]]; then
        json_response "error" "Invalid API secret" "null"
        exit 1
    fi
}

# Fungsi untuk menambahkan client
add_client() {
    local secret=$1
    local email=$2
    local quota=$3
    local inbound_tag=$4
    
    validate_secret "$secret"
    
    # Cek apakah client sudah ada
    if jq -e ".inbounds[] | select(.tag == \"$inbound_tag\") | .settings.clients[] | select(.email == \"$email\")" "$XUI_CONFIG" > /dev/null; then
        json_response "error" "Client already exists" "null"
        return
    fi
    
    # Tambahkan client
    UUID=$(uuidgen)
    jq --arg tag "$inbound_tag" \
       --arg email "$email" \
       --arg uuid "$UUID" \
       --arg quota "$quota" \
       '(.[] | select(.tag == $tag) | .settings.clients) += [{"id": $uuid, "email": $email, "quota": $quota|tonumber}]' \
       "$XUI_CONFIG" > "$XUI_CONFIG.tmp" && mv "$XUI_CONFIG.tmp" "$XUI_CONFIG"
    
    if [[ $? -eq 0 ]]; then
        json_response "success" "Client added successfully" "{\"email\":\"$email\",\"uuid\":\"$UUID\",\"quota\":$quota}"
        # Restart x-ui-pro untuk menerapkan perubahan
        systemctl restart x-ui-pro
    else
        json_response "error" "Failed to add client" "null"
    fi
}

# Fungsi untuk menghapus client
delete_client() {
    local secret=$1
    local email=$2
    local inbound_tag=$3
    
    validate_secret "$secret"
    
    # Hapus client
    jq --arg tag "$inbound_tag" \
       --arg email "$email" \
       '.[] | select(.tag == $tag) | .settings.clients |= map(select(.email != $email))' \
       "$XUI_CONFIG" > "$XUI_CONFIG.tmp" && mv "$XUI_CONFIG.tmp" "$XUI_CONFIG"
    
    if [[ $? -eq 0 ]]; then
        json_response "success" "Client deleted successfully" "{\"email\":\"$email\"}"
        # Restart x-ui-pro untuk menerapkan perubahan
        systemctl restart x-ui-pro
    else
        json_response "error" "Failed to delete client" "null"
    fi
}

# Fungsi untuk update kuota client
update_quota() {
    local secret=$1
    local email=$2
    local quota=$3
    local inbound_tag=$4
    
    validate_secret "$secret"
    
    # Update kuota
    jq --arg tag "$inbound_tag" \
       --arg email "$email" \
       --arg quota "$quota" \
       '(.[] | select(.tag == $tag) | .settings.clients[] | select(.email == $email)).quota = ($quota|tonumber)' \
       "$XUI_CONFIG" > "$XUI_CONFIG.tmp" && mv "$XUI_CONFIG.tmp" "$XUI_CONFIG"
    
    if [[ $? -eq 0 ]]; then
        json_response "success" "Quota updated successfully" "{\"email\":\"$email\",\"quota\":$quota}"
        # Restart x-ui-pro untuk menerapkan perubahan
        systemctl restart x-ui-pro
    else
        json_response "error" "Failed to update quota" "null"
    fi
}

# Fungsi untuk mendapatkan info client
get_client_info() {
    local secret=$1
    local email=$2
    local inbound_tag=$3
    
    validate_secret "$secret"
    
    # Dapatkan info client
    CLIENT_INFO=$(jq -c ".[] | select(.tag == \"$inbound_tag\") | .settings.clients[] | select(.email == \"$email\")" "$XUI_CONFIG")
    
    if [[ -n "$CLIENT_INFO" ]]; then
        json_response "success" "Client found" "$CLIENT_INFO"
    else
        json_response "error" "Client not found" "null"
    fi
}

# Main server
while true; do
    echo -e "HTTP/1.1 200 OK\nContent-Type: application/json\n\n" | nc -l -p $API_PORT | (
        read -r REQUEST
        
        # Parse request
        METHOD=$(echo "$REQUEST" | awk '{print $1}')
        PATH=$(echo "$REQUEST" | awk '{print $2}')
        
        # Baca body jika ada
        if [[ "$METHOD" == "POST" ]]; then
            while read -r line; do
                [ -z "$line" ] && break
            done
            read -r -t 1 -N $CONTENT_LENGTH BODY
        fi
        
        # Handle endpoint
        case "$PATH" in
            "/api/add_client")
                SECRET=$(echo "$BODY" | jq -r '.secret')
                EMAIL=$(echo "$BODY" | jq -r '.email')
                QUOTA=$(echo "$BODY" | jq -r '.quota')
                INBOUND_TAG=$(echo "$BODY" | jq -r '.inbound_tag')
                add_client "$SECRET" "$EMAIL" "$QUOTA" "$INBOUND_TAG"
                ;;
            "/api/delete_client")
                SECRET=$(echo "$BODY" | jq -r '.secret')
                EMAIL=$(echo "$BODY" | jq -r '.email')
                INBOUND_TAG=$(echo "$BODY" | jq -r '.inbound_tag')
                delete_client "$SECRET" "$EMAIL" "$INBOUND_TAG"
                ;;
            "/api/update_quota")
                SECRET=$(echo "$BODY" | jq -r '.secret')
                EMAIL=$(echo "$BODY" | jq -r '.email')
                QUOTA=$(echo "$BODY" | jq -r '.quota')
                INBOUND_TAG=$(echo "$BODY" | jq -r '.inbound_tag')
                update_quota "$SECRET" "$EMAIL" "$QUOTA" "$INBOUND_TAG"
                ;;
            "/api/get_client_info")
                SECRET=$(echo "$BODY" | jq -r '.secret')
                EMAIL=$(echo "$BODY" | jq -r '.email')
                INBOUND_TAG=$(echo "$BODY" | jq -r '.inbound_tag')
                get_client_info "$SECRET" "$EMAIL" "$INBOUND_TAG"
                ;;
            *)
                json_response "error" "Invalid endpoint" "null"
                ;;
        esac
    )
done
EOF

    chmod +x xui-api.sh
    
    # Buat service untuk API
    cat > /etc/systemd/system/xui-api.service <<EOF
[Unit]
Description=X-UI Pro API Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/usr/local/x-ui-pro/api
ExecStart=/usr/local/x-ui-pro/api/xui-api.sh
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable xui-api
    systemctl start xui-api
    
    # Dapatkan secret dari config
    API_SECRET=$(jq -r '.api_secret' /usr/local/x-ui-pro/api/config.json)
    
    echo -e "${GREEN}API berhasil diinstall${NC}"
    echo -e "${YELLOW}API Secret: $API_SECRET${NC}"
    echo -e "${YELLOW}API Port: 54321${NC}"
    echo -e "${YELLOW}Endpoint:${NC}"
    echo -e "  - POST /api/add_client"
    echo -e "  - POST /api/delete_client"
    echo -e "  - POST /api/update_quota"
    echo -e "  - POST /api/get_client_info"
}

# Fungsi utama
main() {
    check_root
    check_os
    check_arch
    
    echo -e "${GREEN}Memulai instalasi X-UI Pro dengan API${NC}"
    
    install_dependencies
    install_xui_pro
    install_api
    
    echo -e "${GREEN}Instalasi selesai!${NC}"
    echo -e "${YELLOW}Anda dapat mengakses X-UI Pro melalui browser:${NC}"
    echo -e "  - http://<IP_VPS>:54321 (X-UI Pro)"
    echo -e "  - http://<IP_VPS>:54321/api (API Endpoint)"
    echo -e "${YELLOW}Jangan lupa untuk mengubah password default dan port jika diperlukan${NC}"
}

# Jalankan fungsi utama
main
