#!/bin/bash

# Xray Multi Port Auto Script
# Support TLS & HTTP with WebSocket & gRPC
# Created for Ubuntu/Debian

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Global variables
DOMAIN=""
EMAIL="admin@example.com"
XRAY_CONFIG="/usr/local/etc/xray/config.json"
NGINX_CONFIG="/etc/nginx/sites-available/xray"
USER_DB="/etc/xray/users.db"
API_PORT="8080"

clear_screen() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              XRAY MULTI PORT MENU                    ║${NC}"
    echo -e "${BLUE}║                  Domain: $DOMAIN                     ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

generate_password() {
    tr -dc A-Za-z0-9 </dev/urandom | head -c 16
}

read_user_db() {
    if [[ -f "$USER_DB" ]]; then
        cat "$USER_DB"
    else
        echo "{}"
    fi
}

add_user_to_db() {
    local username="$1"
    local uuid="$2"
    local password="$3"
    local created_date="$(date)"
    local expiry_date="$(date -d '+30 days')"
    
    local user_data=$(jq -n \
        --arg username "$username" \
        --arg uuid "$uuid" \
        --arg password "$password" \
        --arg created "$created_date" \
        --arg expiry "$expiry_date" \
        '{
            username: $username,
            uuid: $uuid,
            password: $password,
            created_date: $created,
            expiry_date: $expiry,
            upload: 0,
            download: 0
        }')
    
    local current_db=$(read_user_db)
    echo "$current_db" | jq --arg username "$username" --argjson user_data "$user_data" \
        '.[$username] = $user_data' > "$USER_DB"
}

create_user() {
    clear_screen
    echo -e "${GREEN}=== CREATE NEW USER ===${NC}"
    echo ""
    
    read -p "Enter username: " username
    if [[ -z "$username" ]]; then
        echo -e "${RED}Username cannot be empty!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Check if user exists
    local existing_user=$(read_user_db | jq -r --arg username "$username" '.[$username] // empty')
    if [[ -n "$existing_user" ]]; then
        echo -e "${RED}User $username already exists!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    local uuid=$(generate_uuid)
    local password=$(generate_password)
    
    # Add to database
    add_user_to_db "$username" "$uuid" "$password"
    
    # Add to Xray config
    /usr/local/bin/add-user "$username" "$uuid" "$password"
    
    echo -e "${GREEN}User created successfully!${NC}"
    echo ""
    echo -e "${YELLOW}Username:${NC} $username"
    echo -e "${YELLOW}UUID:${NC} $uuid"
    echo -e "${YELLOW}Password:${NC} $password"
    echo ""
    
    # Generate configs
    generate_user_configs "$username" "$uuid" "$password"
    
    read -p "Press Enter to continue..."
}

generate_user_configs() {
    local username="$1"
    local uuid="$2"
    local password="$3"
    
    echo -e "${CYAN}=== USER CONFIGURATIONS ===${NC}"
    echo ""
    
    echo -e "${YELLOW}TROJAN WebSocket TLS (443):${NC}"
    echo "trojan://${password}@${DOMAIN}:443?type=ws&path=/trojan-ws&security=tls&sni=${DOMAIN}#${username}_trojan_ws_tls"
    echo ""
    
    echo -e "${YELLOW}TROJAN gRPC TLS (443):${NC}"
    echo "trojan://${password}@${DOMAIN}:443?type=grpc&serviceName=trojan-grpc&security=tls&sni=${DOMAIN}#${username}_trojan_grpc_tls"
    echo ""
    
    echo -e "${YELLOW}TROJAN WebSocket HTTP (80):${NC}"
    echo "trojan://${password}@${DOMAIN}:80?type=ws&path=/trojan-ws&security=none#${username}_trojan_ws_http"
    echo ""
    
    echo -e "${YELLOW}TROJAN gRPC HTTP (80):${NC}"
    echo "trojan://${password}@${DOMAIN}:80?type=grpc&serviceName=trojan-grpc&security=none#${username}_trojan_grpc_http"
    echo ""
    
    echo -e "${YELLOW}VMESS WebSocket TLS (443):${NC}"
    local vmess_ws_tls=$(echo -n "{\"v\":\"2\",\"ps\":\"${username}_vmess_ws_tls\",\"add\":\"${DOMAIN}\",\"port\":\"443\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DOMAIN}\",\"path\":\"/vmess-ws\",\"tls\":\"tls\",\"sni\":\"${DOMAIN}\"}" | base64 -w 0)
    echo "vmess://${vmess_ws_tls}"
    echo ""
    
    echo -e "${YELLOW}VMESS gRPC TLS (443):${NC}"
    local vmess_grpc_tls=$(echo -n "{\"v\":\"2\",\"ps\":\"${username}_vmess_grpc_tls\",\"add\":\"${DOMAIN}\",\"port\":\"443\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"grpc\",\"type\":\"none\",\"host\":\"${DOMAIN}\",\"path\":\"vmess-grpc\",\"tls\":\"tls\",\"sni\":\"${DOMAIN}\"}" | base64 -w 0)
    echo "vmess://${vmess_grpc_tls}"
    echo ""
    
    echo -e "${YELLOW}VMESS WebSocket HTTP (80):${NC}"
    local vmess_ws_http=$(echo -n "{\"v\":\"2\",\"ps\":\"${username}_vmess_ws_http\",\"add\":\"${DOMAIN}\",\"port\":\"80\",\"id\":\"${uuid}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"${DOMAIN}\",\"path\":\"/vmess-ws\",\"tls\":\"none\"}" | base64 -w 0)
    echo "vmess://${vmess_ws_http}"
    echo ""
    
    echo -e "${YELLOW}VLESS WebSocket TLS (443):${NC}"
    echo "vless://${uuid}@${DOMAIN}:443?type=ws&path=/vless-ws&security=tls&sni=${DOMAIN}#${username}_vless_ws_tls"
    echo ""
    
    echo -e "${YELLOW}VLESS gRPC TLS (443):${NC}"
    echo "vless://${uuid}@${DOMAIN}:443?type=grpc&serviceName=vless-grpc&security=tls&sni=${DOMAIN}#${username}_vless_grpc_tls"
    echo ""
    
    echo -e "${YELLOW}VLESS WebSocket HTTP (80):${NC}"
    echo "vless://${uuid}@${DOMAIN}:80?type=ws&path=/vless-ws&security=none#${username}_vless_ws_http"
    echo ""
    
    echo -e "${YELLOW}SHADOWSOCKS WebSocket TLS (443):${NC}"
    local ss_ws_tls=$(echo -n "aes-256-gcm:${password}" | base64 -w 0)
    echo "ss://${ss_ws_tls}@${DOMAIN}:443/?plugin=v2ray-plugin;tls;host=${DOMAIN};path=/ss-ws#${username}_ss_ws_tls"
    echo ""
    
    echo -e "${YELLOW}SHADOWSOCKS gRPC TLS (443):${NC}"
    local ss_grpc_tls=$(echo -n "aes-256-gcm:${password}" | base64 -w 0)
    echo "ss://${ss_grpc_tls}@${DOMAIN}:443/?plugin=v2ray-plugin;tls;host=${DOMAIN};path=ss-grpc;mode=grpc#${username}_ss_grpc_tls"
    echo ""
}

check_user() {
    clear_screen
    echo -e "${GREEN}=== CHECK USER ===${NC}"
    echo ""
    
    read -p "Enter username: " username
    if [[ -z "$username" ]]; then
        echo -e "${RED}Username cannot be empty!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    local user_data=$(read_user_db | jq -r --arg username "$username" '.[$username] // empty')
    if [[ -z "$user_data" || "$user_data" == "null" ]]; then
        echo -e "${RED}User $username not found!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    local user_info=$(read_user_db | jq -r --arg username "$username" '.[$username]')
    local uuid=$(echo "$user_info" | jq -r '.uuid')
    local password=$(echo "$user_info" | jq -r '.password')
    local created_date=$(echo "$user_info" | jq -r '.created_date')
    local expiry_date=$(echo "$user_info" | jq -r '.expiry_date')
    local upload=$(echo "$user_info" | jq -r '.upload')
    local download=$(echo "$user_info" | jq -r '.download')
    
    echo -e "${YELLOW}Username:${NC} $username"
    echo -e "${YELLOW}UUID:${NC} $uuid"
    echo -e "${YELLOW}Password:${NC} $password"
    echo -e "${YELLOW}Created:${NC} $created_date"
    echo -e "${YELLOW}Expiry:${NC} $expiry_date"
    echo -e "${YELLOW}Upload:${NC} $upload bytes"
    echo -e "${YELLOW}Download:${NC} $download bytes"
    echo ""
    
    read -p "Show configurations? (y/n): " show_configs
    if [[ "$show_configs" == "y" || "$show_configs" == "Y" ]]; then
        generate_user_configs "$username" "$uuid" "$password"
    fi
    
    read -p "Press Enter to continue..."
}

change_domain() {
    clear_screen
    echo -e "${GREEN}=== CHANGE DOMAIN ===${NC}"
    echo ""
    echo -e "${YELLOW}Current domain:${NC} $DOMAIN"
    echo ""
    
    read -p "Enter new domain: " new_domain
    if [[ -z "$new_domain" ]]; then
        echo -e "${RED}Domain cannot be empty!${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "$new_domain" > /etc/xray/domain.txt
    DOMAIN="$new_domain"
    
    # Update Nginx config
    sed -i "s/server_name .*/server_name $new_domain *.$new_domain;/g" /etc/nginx/sites-available/xray
    
    echo -e "${GREEN}Domain changed successfully!${NC}"
    echo -e "${YELLOW}Please regenerate SSL certificate using option 6${NC}"
    
    read -p "Press Enter to continue..."
}

check_bandwidth() {
    clear_screen
    echo -e "${GREEN}=== BANDWIDTH USAGE ===${NC}"
    echo ""
    
    vnstat -i eth0
    echo ""
    
    read -p "Press Enter to continue..."
}

run_speedtest() {
    clear_screen
    echo -e "${GREEN}=== SPEEDTEST ===${NC}"
    echo ""
    
    echo -e "${YELLOW}Running speedtest...${NC}"
    speedtest-cli
    echo ""
    
    read -p "Press Enter to continue..."
}

generate_ssl_cert() {
    clear_screen
    echo -e "${GREEN}=== GENERATE SSL CERTIFICATE ===${NC}"
    echo ""
    
    echo -e "${YELLOW}Stopping Nginx...${NC}"
    systemctl stop nginx
    
    echo -e "${YELLOW}Generating SSL certificate for $DOMAIN...${NC}"
    certbot certonly --standalone --agree-tos --register-unsafely-without-email -d "$DOMAIN" -d "*.$DOMAIN"
    
    if [[ $? -eq 0 ]]; then
        echo -e "${GREEN}SSL certificate generated successfully!${NC}"
        
        # Update Nginx config with new certificate paths
        sed -i "s|ssl_certificate .*|ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;|g" /etc/nginx/sites-available/xray
        sed -i "s|ssl_certificate_key .*|ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;|g" /etc/nginx/sites-available/xray
        
        systemctl start nginx
        systemctl restart nginx
        
        echo -e "${GREEN}Nginx restarted with new certificate!${NC}"
    else
        echo -e "${RED}Failed to generate SSL certificate!${NC}"
        systemctl start nginx
    fi
    
    read -p "Press Enter to continue..."
}

list_all_users() {
    clear_screen
    echo -e "${GREEN}=== ALL USERS ===${NC}"
    echo ""
    
    local users=$(read_user_db | jq -r 'keys[]' 2>/dev/null)
    if [[ -z "$users" ]]; then
        echo -e "${YELLOW}No users found${NC}"
    else
        echo -e "${YELLOW}Username${NC}        ${YELLOW}Created Date${NC}          ${YELLOW}Expiry Date${NC}"
        echo "================================================================"
        while IFS= read -r username; do
            local user_info=$(read_user_db | jq -r --arg username "$username" '.[$username]')
            local created=$(echo "$user_info" | jq -r '.created_date' | cut -d' ' -f1-3)
            local expiry=$(echo "$user_info" | jq -r '.expiry_date' | cut -d' ' -f1-3)
            printf "%-15s %-20s %-20s\n" "$username" "$created" "$expiry"
        done <<< "$users"
    fi
    echo ""
    
    read -p "Press Enter to continue..."
}

show_menu() {
    clear_screen
    echo -e "${CYAN}1.${NC} Create User"
    echo -e "${CYAN}2.${NC} Check User"
    echo -e "${CYAN}3.${NC} Change Domain"
    echo -e "${CYAN}4.${NC} Check Bandwidth (vnstat)"
    echo -e "${CYAN}5.${NC} Speedtest"
    echo -e "${CYAN}6.${NC} Generate SSL Certificate"
    echo -e "${CYAN}7.${NC} List All Users"
    echo -e "${CYAN}8.${NC} Restart Services"
    echo -e "${CYAN}9.${NC} System Info"
    echo -e "${CYAN}0.${NC} Exit"
    echo ""
    echo -e "${YELLOW}API Endpoint:${NC} http://$(curl -s ifconfig.me):8080/?create=username"
    echo ""
}

restart_services() {
    clear_screen
    echo -e "${GREEN}=== RESTART SERVICES ===${NC}"
    echo ""
    
    echo -e "${YELLOW}Restarting Xray...${NC}"
    systemctl restart xray
    
    echo -e "${YELLOW}Restarting Nginx...${NC}"
    systemctl restart nginx
    
    echo -e "${YELLOW}Restarting API Server...${NC}"
    systemctl restart xray-api
    
    echo -e "${GREEN}All services restarted successfully!${NC}"
    
    read -p "Press Enter to continue..."
}

show_system_info() {
    clear_screen
    echo -e "${GREEN}=== SYSTEM INFORMATION ===${NC}"
    echo ""
    
    echo -e "${YELLOW}Domain:${NC} $DOMAIN"
    echo -e "${YELLOW}Server IP:${NC} $(curl -s ifconfig.me)"
    echo -e "${YELLOW}OS:${NC} $(lsb_release -d | cut -f2)"
    echo -e "${YELLOW}Kernel:${NC} $(uname -r)"
    echo -e "${YELLOW}Uptime:${NC} $(uptime -p)"
    echo -e "${YELLOW}Memory Usage:${NC} $(free -h | awk '/^Mem:/ {print $3"/"$2}')"
    echo -e "${YELLOW}Disk Usage:${NC} $(df -h / | awk 'NR==2 {print $3"/"$2" ("$5")"}')"
    echo ""
    
    echo -e "${YELLOW}Service Status:${NC}"
    echo -e "Xray: $(systemctl is-active xray)"
    echo -e "Nginx: $(systemctl is-active nginx)"
    echo -e "API Server: $(systemctl is-active xray-api)"
    echo ""
    
    echo -e "${YELLOW}Port Status:${NC}"
    echo -e "443 (HTTPS): $(ss -tuln | grep ':443 ' && echo 'Open' || echo 'Closed')"
    echo -e "80 (HTTP): $(ss -tuln | grep ':80 ' && echo 'Open' || echo 'Closed')"
    echo -e "8080 (API): $(ss -tuln | grep ':8080 ' && echo 'Open' || echo 'Closed')"
    echo ""
    
    read -p "Press Enter to continue..."
}

# Main menu loop
while true; do
    show_menu
    read -p "Select option [0-9]: " choice
    
    case $choice in
        1) create_user ;;
        2) check_user ;;
        3) change_domain ;;
        4) check_bandwidth ;;
        5) run_speedtest ;;
        6) generate_ssl_cert ;;
        7) list_all_users ;;
        8) restart_services ;;
        9) show_system_info ;;
        0) echo -e "${GREEN}Goodbye!${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option!${NC}"; sleep 1 ;;
    esac
done
EOF

    chmod +x /usr/local/bin/xray-menu
}

install_complete() {
    log_info "Installation completed!"
    
    systemctl restart xray
    systemctl restart nginx
    systemctl start xray-api
    
    clear_screen
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            INSTALLATION COMPLETED!                   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Domain:${NC} $DOMAIN"
    echo -e "${YELLOW}SSL Status:${NC} $(systemctl is-active certbot && echo 'Active' || echo 'Inactive')"
    echo -e "${YELLOW}Xray Status:${NC} $(systemctl is-active xray)"
    echo -e "${YELLOW}Nginx Status:${NC} $(systemctl is-active nginx)"
    echo -e "${YELLOW}API Status:${NC} $(systemctl is-active xray-api)"
    echo ""
    echo -e "${CYAN}Commands:${NC}"
    echo -e "  ${YELLOW}xray-menu${NC} - Open management menu"
    echo ""
    echo -e "${CYAN}API Endpoint:${NC}"
    echo -e "  ${YELLOW}http://$(curl -s ifconfig.me):8080/?create=username${NC}"
    echo ""
    echo -e "${CYAN}Supported Protocols:${NC}"
    echo -e "  • Trojan (WebSocket & gRPC) - Port 443/80"
    echo -e "  • Shadowsocks (WebSocket & gRPC) - Port 443/80"
    echo -e "  • VMess (WebSocket & gRPC) - Port 443/80"
    echo -e "  • VLESS (WebSocket & gRPC) - Port 443/80"
    echo ""
    echo -e "${GREEN}Run 'xray-menu' to start managing users!${NC}"
}

# Main installation function
main() {
    check_root
    get_domain
    
    log_info "Starting Xray Multi Port installation..."
    
    update_system
    install_dependencies
    create_user_db
    create_xray_config
    create_nginx_config
    create_default_page
    create_api_server
    create_user_management
    create_menu
    
    log_info "Generating SSL certificate..."
    generate_ssl
    
    install_complete
}

# Run installation
main "$@"() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              XRAY MULTI PORT SCRIPT                  ║${NC}"
    echo -e "${BLUE}║                  BY: ZENXRAY                         ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

get_domain() {
    if [[ -f "/etc/xray/domain.txt" ]]; then
        DOMAIN=$(cat /etc/xray/domain.txt)
    else
        clear_screen
        echo -e "${YELLOW}Please enter your domain:${NC}"
        read -p "Domain: " DOMAIN
        if [[ -z "$DOMAIN" ]]; then
            log_error "Domain cannot be empty!"
            exit 1
        fi
        mkdir -p /etc/xray
        echo "$DOMAIN" > /etc/xray/domain.txt
    fi
}

update_system() {
    log_info "Updating system packages..."
    apt update -y && apt upgrade -y
    apt install -y curl wget gnupg2 software-properties-common apt-transport-https ca-certificates lsb-release
}

install_dependencies() {
    log_info "Installing dependencies..."
    
    # Install basic tools
    apt install -y nginx certbot python3-certbot-nginx vnstat speedtest-cli jq uuid-runtime
    
    # Install Node.js for API
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt install -y nodejs
    
    # Install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    systemctl enable xray
    systemctl enable nginx
    systemctl enable vnstat
}

generate_uuid() {
    uuidgen
}

generate_password() {
    tr -dc A-Za-z0-9 </dev/urandom | head -c 16
}

create_user_db() {
    if [[ ! -f "$USER_DB" ]]; then
        log_info "Creating user database..."
        mkdir -p /etc/xray
        cat > "$USER_DB" << EOF
{}
EOF
    fi
}

add_user_to_db() {
    local username="$1"
    local uuid="$2"
    local password="$3"
    local created_date="$(date)"
    local expiry_date="$(date -d '+30 days')"
    
    local user_data=$(jq -n \
        --arg username "$username" \
        --arg uuid "$uuid" \
        --arg password "$password" \
        --arg created "$created_date" \
        --arg expiry "$expiry_date" \
        '{
            username: $username,
            uuid: $uuid,
            password: $password,
            created_date: $created,
            expiry_date: $expiry,
            upload: 0,
            download: 0
        }')
    
    jq --arg username "$username" --argjson user_data "$user_data" \
        '.[$username] = $user_data' "$USER_DB" > /tmp/users.db && mv /tmp/users.db "$USER_DB"
}

get_user_from_db() {
    local username="$1"
    jq -r --arg username "$username" '.[$username] // empty' "$USER_DB"
}

list_users_from_db() {
    jq -r 'keys[]' "$USER_DB" 2>/dev/null || echo ""
}

create_xray_config() {
    log_info "Creating Xray configuration..."
    
    mkdir -p /usr/local/etc/xray
    
    cat > "$XRAY_CONFIG" << EOF
{
    "log": {
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "port": 10001,
            "protocol": "trojan",
            "settings": {
                "clients": [],
                "fallbacks": [
                    {
                        "dest": 80
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/trojan-ws"
                }
            }
        },
        {
            "port": 10002,
            "protocol": "trojan",
            "settings": {
                "clients": [],
                "fallbacks": [
                    {
                        "dest": 80
                    }
                ]
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": "trojan-grpc"
                }
            }
        },
        {
            "port": 10003,
            "protocol": "shadowsocks",
            "settings": {
                "method": "aes-256-gcm",
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/ss-ws"
                }
            }
        },
        {
            "port": 10004,
            "protocol": "shadowsocks",
            "settings": {
                "method": "aes-256-gcm",
                "clients": []
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": "ss-grpc"
                }
            }
        },
        {
            "port": 10005,
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/vmess-ws"
                }
            }
        },
        {
            "port": 10006,
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": "vmess-grpc"
                }
            }
        },
        {
            "port": 10007,
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "none",
                "wsSettings": {
                    "path": "/vless-ws"
                }
            }
        },
        {
            "port": 10008,
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "grpc",
                "security": "none",
                "grpcSettings": {
                    "serviceName": "vless-grpc"
                }
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
}

create_nginx_config() {
    log_info "Creating Nginx configuration..."
    
    cat > "$NGINX_CONFIG" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN *.$DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN *.$DOMAIN;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    
    root /var/www/html;
    index index.html;
    
    # Trojan WebSocket
    location /trojan-ws {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Trojan gRPC
    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:10002;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Shadowsocks WebSocket
    location /ss-ws {
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # Shadowsocks gRPC
    location /ss-grpc {
        grpc_pass grpc://127.0.0.1:10004;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto \$scheme;
    }
    
    # VMess WebSocket
    location /vmess-ws {
        proxy_pass http://127.0.0.1:10005;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # VMess gRPC
    location /vmess-grpc {
        grpc_pass grpc://127.0.0.1:10006;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto \$scheme;
    }
    
    # VLESS WebSocket
    location /vless-ws {
        proxy_pass http://127.0.0.1:10007;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
    
    # VLESS gRPC
    location /vless-grpc {
        grpc_pass grpc://127.0.0.1:10008;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        grpc_set_header X-Forwarded-Proto \$scheme;
    }
}

# HTTP Version (Port 80 after SSL redirect)
server {
    listen 8080;
    server_name $DOMAIN *.$DOMAIN;
    
    root /var/www/html;
    index index.html;
    
    # HTTP Trojan WebSocket
    location /trojan-ws {
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # HTTP Trojan gRPC
    location /trojan-grpc {
        grpc_pass grpc://127.0.0.1:10002;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # HTTP Shadowsocks WebSocket
    location /ss-ws {
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # HTTP Shadowsocks gRPC
    location /ss-grpc {
        grpc_pass grpc://127.0.0.1:10004;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # HTTP VMess WebSocket
    location /vmess-ws {
        proxy_pass http://127.0.0.1:10005;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # HTTP VMess gRPC
    location /vmess-grpc {
        grpc_pass grpc://127.0.0.1:10006;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # HTTP VLESS WebSocket
    location /vless-ws {
        proxy_pass http://127.0.0.1:10007;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # HTTP VLESS gRPC
    location /vless-grpc {
        grpc_pass grpc://127.0.0.1:10008;
        grpc_set_header Host \$host;
        grpc_set_header X-Real-IP \$remote_addr;
        grpc_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF

    ln -sf "$NGINX_CONFIG" /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
}

generate_ssl() {
    log_info "Generating SSL certificate..."
    
    systemctl stop nginx
    certbot certonly --standalone --agree-tos --register-unsafely-without-email -d "$DOMAIN" -d "*.$DOMAIN"
    
    if [[ $? -eq 0 ]]; then
        log_info "SSL certificate generated successfully"
        systemctl start nginx
        return 0
    else
        log_error "Failed to generate SSL certificate"
        systemctl start nginx
        return 1
    fi
}

create_default_page() {
    log_info "Creating default web page..."
    
    mkdir -p /var/www/html
    cat > /var/www/html/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Xray Multi Port Server</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 50px; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .status { padding: 20px; background: #e8f5e8; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Xray Multi Port Server</h1>
        <div class="status">
            <h3>Server Status: Online</h3>
            <p>Domain: $DOMAIN</p>
            <p>Protocols: Trojan, Shadowsocks, VMess, VLESS</p>
            <p>Transport: WebSocket, gRPC</p>
            <p>Ports: 443 (TLS), 80 (HTTP)</p>
        </div>
    </div>
</body>
</html>
EOF
}

create_api_server() {
    log_info "Creating API server..."
    
    mkdir -p /etc/xray/api
    cat > /etc/xray/api/server.js << 'EOF'
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 8080;
const USER_DB = '/etc/xray/users.db';

app.use(express.json());

// CORS middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
});

// Generate UUID
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

// Generate password
function generatePassword() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let password = '';
    for (let i = 0; i < 16; i++) {
        password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
}

// Read user database
function readUserDB() {
    try {
        if (fs.existsSync(USER_DB)) {
            const data = fs.readFileSync(USER_DB, 'utf8');
            return JSON.parse(data);
        }
        return {};
    } catch (error) {
        return {};
    }
}

// Write user database
function writeUserDB(data) {
    try {
        fs.writeFileSync(USER_DB, JSON.stringify(data, null, 2));
        return true;
    } catch (error) {
        return false;
    }
}

// Create user endpoint
app.get('/', (req, res) => {
    const { create } = req.query;
    
    if (!create) {
        return res.json({ error: 'Missing create parameter' });
    }
    
    const username = create;
    const uuid = generateUUID();
    const password = generatePassword();
    const createdDate = new Date().toISOString();
    const expiryDate = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    
    // Read existing users
    const users = readUserDB();
    
    // Check if user already exists
    if (users[username]) {
        return res.json({ error: 'User already exists' });
    }
    
    // Add new user
    users[username] = {
        username: username,
        uuid: uuid,
        password: password,
        created_date: createdDate,
        expiry_date: expiryDate,
        upload: 0,
        download: 0
    };
    
    // Save to database
    if (!writeUserDB(users)) {
        return res.json({ error: 'Failed to save user' });
    }
    
    // Add user to Xray config
    exec(`/usr/local/bin/add-user "${username}" "${uuid}" "${password}"`, (error) => {
        if (error) {
            console.error('Error adding user to Xray:', error);
        }
    });
    
    // Return user data
    res.json({
        success: true,
        user: users[username],
        configs: generateConfigs(username, uuid, password)
    });
});

// Generate configs for all protocols
function generateConfigs(username, uuid, password) {
    const domain = fs.readFileSync('/etc/xray/domain.txt', 'utf8').trim();
    
    return {
        trojan_ws_tls: `trojan://${password}@${domain}:443?type=ws&path=/trojan-ws&security=tls&sni=${domain}#${username}_trojan_ws_tls`,
        trojan_grpc_tls: `trojan://${password}@${domain}:443?type=grpc&serviceName=trojan-grpc&security=tls&sni=${domain}#${username}_trojan_grpc_tls`,
        trojan_ws_http: `trojan://${password}@${domain}:80?type=ws&path=/trojan-ws&security=none#${username}_trojan_ws_http`,
        trojan_grpc_http: `trojan://${password}@${domain}:80?type=grpc&serviceName=trojan-grpc&security=none#${username}_trojan_grpc_http`,
        vmess_ws_tls: `vmess://${Buffer.from(JSON.stringify({
            v: "2",
            ps: `${username}_vmess_ws_tls`,
            add: domain,
            port: "443",
            id: uuid,
            aid: "0",
            net: "ws",
            type: "none",
            host: domain,
            path: "/vmess-ws",
            tls: "tls",
            sni: domain
        })).toString('base64')}`,
        vmess_grpc_tls: `vmess://${Buffer.from(JSON.stringify({
            v: "2",
            ps: `${username}_vmess_grpc_tls`,
            add: domain,
            port: "443",
            id: uuid,
            aid: "0",
            net: "grpc",
            type: "none",
            host: domain,
            path: "vmess-grpc",
            tls: "tls",
            sni: domain
        })).toString('base64')}`,
        vless_ws_tls: `vless://${uuid}@${domain}:443?type=ws&path=/vless-ws&security=tls&sni=${domain}#${username}_vless_ws_tls`,
        vless_grpc_tls: `vless://${uuid}@${domain}:443?type=grpc&serviceName=vless-grpc&security=tls&sni=${domain}#${username}_vless_grpc_tls`,
        shadowsocks_ws_tls: `ss://${Buffer.from(`aes-256-gcm:${password}`).toString('base64')}@${domain}:443/?plugin=v2ray-plugin;tls;host=${domain};path=/ss-ws#${username}_ss_ws_tls`,
        shadowsocks_grpc_tls: `ss://${Buffer.from(`aes-256-gcm:${password}`).toString('base64')}@${domain}:443/?plugin=v2ray-plugin;tls;host=${domain};path=ss-grpc;mode=grpc#${username}_ss_grpc_tls`
    };
}

app.listen(PORT, () => {
    console.log(`API Server running on port ${PORT}`);
});
EOF

    # Create systemd service for API
    cat > /etc/systemd/system/xray-api.service << EOF
[Unit]
Description=Xray API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/xray/api
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable xray-api
}

create_user_management() {
    log_info "Creating user management scripts..."
    
    # Add user script
    cat > /usr/local/bin/add-user << 'EOF'
#!/bin/bash

USERNAME="$1"
UUID="$2"
PASSWORD="$3"

if [[ -z "$USERNAME" || -z "$UUID" || -z "$PASSWORD" ]]; then
    echo "Usage: add-user <username> <uuid> <password>"
    exit 1
fi

XRAY_CONFIG="/usr/local/etc/xray/config.json"

# Add to Trojan
jq --arg password "$PASSWORD" \
   '.inbounds[0].settings.clients += [{"password": $password}] | 
    .inbounds[1].settings.clients += [{"password": $password}]' \
   "$XRAY_CONFIG" > /tmp/config.json && mv /tmp/config.json "$XRAY_CONFIG"

# Add to Shadowsocks
jq --arg password "$PASSWORD" \
   '.inbounds[2].settings.clients += [{"password": $password, "method": "aes-256-gcm"}] | 
    .inbounds[3].settings.clients += [{"password": $password, "method": "aes-256-gcm"}]' \
   "$XRAY_CONFIG" > /tmp/config.json && mv /tmp/config.json "$XRAY_CONFIG"

# Add to VMess
jq --arg uuid "$UUID" \
   '.inbounds[4].settings.clients += [{"id": $uuid, "alterId": 0}] | 
    .inbounds[5].settings.clients += [{"id": $uuid, "alterId": 0}]' \
   "$XRAY_CONFIG" > /tmp/config.json && mv /tmp/config.json "$XRAY_CONFIG"

# Add to VLESS
jq --arg uuid "$UUID" \
   '.inbounds[6].settings.clients += [{"id": $uuid}] | 
    .inbounds[7].settings.clients += [{"id": $uuid}]' \
   "$XRAY_CONFIG" > /tmp/config.json && mv /tmp/config.json "$XRAY_CONFIG"

systemctl restart xray
echo "User $USERNAME added successfully"
EOF

    chmod +x /usr/local/bin/add-user
}

create_menu() {
    log_info "Creating menu script..."
    
    cat > /usr/local/bin/xray-menu << 'EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

USER_DB="/etc/xray/users.db"
DOMAIN=$(cat /etc/xray/domain.txt 2>/dev/null || echo "")

clear_screen
