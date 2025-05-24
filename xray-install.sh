#!/bin/bash

# Xray Multi-Port AutoScript with Nginx Reverse Proxy
# Support TLS & HTTP, Multi Protocol (TROJAN, VMESS, VLESS)
# Created for VPS Management

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="/opt/xray-script"
CONFIG_DIR="/usr/local/etc/xray"
LOG_DIR="/var/log/xray"
WEB_DIR="/var/www/html"
DOMAIN_FILE="$SCRIPT_DIR/domain.txt"
USER_DB="$SCRIPT_DIR/users.json"

# Ensure script directory exists
mkdir -p $SCRIPT_DIR
mkdir -p $LOG_DIR
mkdir -p $WEB_DIR

# Function to print colored output
print_msg() {
    case $1 in
        "error") echo -e "${RED}[ERROR] $2${NC}" ;;
        "success") echo -e "${GREEN}[SUCCESS] $2${NC}" ;;
        "warning") echo -e "${YELLOW}[WARNING] $2${NC}" ;;
        "info") echo -e "${BLUE}[INFO] $2${NC}" ;;
        *) echo -e "$1" ;;
    esac
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_msg "error" "This script must be run as root!"
        exit 1
    fi
}

# Function to detect OS
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_msg "error" "Cannot detect OS version"
        exit 1
    fi
}

# Function to install dependencies
install_dependencies() {
    print_msg "info" "Installing dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt update -y
            apt install -y curl wget unzip socat cron bash-completion ntpdate
            apt install -y nginx certbot python3-certbot-nginx
            apt install -y vnstat speedtest-cli jq bc
            systemctl enable vnstat
            systemctl start vnstat
            ;;
        centos|rhel|fedora)
            yum update -y
            yum install -y curl wget unzip socat cronie bash-completion ntpdate
            yum install -y nginx certbot python3-certbot-nginx
            yum install -y vnstat jq bc
            # Install speedtest for CentOS
            curl -s https://install.speedtest.net/app/cli/install.rpm.sh | bash
            yum install -y speedtest
            systemctl enable vnstat
            systemctl start vnstat
            ;;
        *)
            print_msg "error" "Unsupported OS: $OS"
            exit 1
            ;;
    esac
    
    print_msg "success" "Dependencies installed successfully"
}

# Function to install Xray
install_xray() {
    print_msg "info" "Installing Xray..."
    
    # Download and install Xray
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    
    # Enable and start Xray service
    systemctl enable xray
    
    print_msg "success" "Xray installed successfully"
}

# Function to setup domain
setup_domain() {
    if [[ -f $DOMAIN_FILE ]]; then
        DOMAIN=$(cat $DOMAIN_FILE)
        print_msg "info" "Current domain: $DOMAIN"
        read -p "Do you want to change domain? (y/n): " change_domain
        if [[ $change_domain == "y" || $change_domain == "Y" ]]; then
            read -p "Enter your domain: " DOMAIN
            echo $DOMAIN > $DOMAIN_FILE
        fi
    else
        read -p "Enter your domain: " DOMAIN
        echo $DOMAIN > $DOMAIN_FILE
    fi
    
    # Set domain to hosts
    echo "127.0.0.1 $DOMAIN" >> /etc/hosts
    
    print_msg "success" "Domain setup completed: $DOMAIN"
}

# Function to generate SSL certificate
generate_ssl() {
    DOMAIN=$(cat $DOMAIN_FILE 2>/dev/null || echo "")
    if [[ -z $DOMAIN ]]; then
        print_msg "error" "Domain not configured"
        return 1
    fi
    
    print_msg "info" "Generating SSL certificate for $DOMAIN..."
    
    # Stop nginx temporarily
    systemctl stop nginx
    
    # Generate certificate using certbot standalone mode
    certbot certonly --standalone --agree-tos --register-unsafely-without-email -d $DOMAIN
    
    if [[ $? -eq 0 ]]; then
        print_msg "success" "SSL certificate generated successfully"
        
        # Setup auto renewal
        echo "0 3 * * * /usr/bin/certbot renew --quiet --post-hook 'systemctl reload nginx'" | crontab -
        
        # Start nginx
        systemctl start nginx
        return 0
    else
        print_msg "error" "Failed to generate SSL certificate"
        systemctl start nginx
        return 1
    fi
}

# Function to configure Xray
configure_xray() {
    DOMAIN=$(cat $DOMAIN_FILE)
    
    cat > $CONFIG_DIR/config.json << EOF
{
    "log": {
        "access": "$LOG_DIR/access.log",
        "error": "$LOG_DIR/error.log",
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "tag": "trojan-tls",
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
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/trojan-ws"
                }
            }
        },
        {
            "tag": "vmess-tls",
            "port": 8444,
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
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vmess-ws"
                }
            }
        },
        {
            "tag": "vless-tls",
            "port": 8445,
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
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vless-ws"
                }
            }
        },
        {
            "tag": "trojan-http",
            "port": 8080,
            "protocol": "trojan",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/trojan-http"
                }
            }
        },
        {
            "tag": "vmess-http",
            "port": 8081,
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vmess-http"
                }
            }
        },
        {
            "tag": "vless-http",
            "port": 8082,
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vless-http"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
EOF

    # Initialize empty users database
    echo '{"users": []}' > $USER_DB
    
    print_msg "success" "Xray configuration created"
}

# Function to configure Nginx
configure_nginx() {
    DOMAIN=$(cat $DOMAIN_FILE)
    
    # Remove default nginx config
    rm -f /etc/nginx/sites-enabled/default
    rm -f /etc/nginx/sites-available/default
    
    # Create new nginx config
    cat > /etc/nginx/sites-available/xray << EOF
server {
    listen 80;
    server_name $DOMAIN *.$DOMAIN;
    
    # Support wildcard bugs
    if (\$host ~* ^(.+\\.)?(.*\\.)?(.*)\$) {
        set \$bug_host \$3;
    }
    
    location /trojan-http {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
    
    location /vmess-http {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
    
    location /vless-http {
        proxy_pass http://127.0.0.1:8082;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
    
    location / {
        root $WEB_DIR;
        index index.html index.htm;
        try_files \$uri \$uri/ =404;
    }
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN *.$DOMAIN;
    
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # Support wildcard bugs
    if (\$host ~* ^(.+\\.)?(.*\\.)?(.*)\$) {
        set \$bug_host \$3;
    }
    
    location /trojan-ws {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
    
    location /vmess-ws {
        proxy_pass http://127.0.0.1:8444;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
    
    location /vless-ws {
        proxy_pass http://127.0.0.1:8445;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
    }
    
    location / {
        root $WEB_DIR;
        index index.html index.htm;
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # Enable site
    ln -sf /etc/nginx/sites-available/xray /etc/nginx/sites-enabled/
    
    # Create simple index page
    cat > $WEB_DIR/index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>Xray Multi-Port Server</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f4f4f4; }
        .container { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .status { text-align: center; color: #28a745; font-size: 18px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚀 Xray Multi-Port Server</h1>
        <div class="status">✅ Server is running properly</div>
        <p>This server supports multiple protocols:</p>
        <ul>
            <li>TROJAN WebSocket (TLS: 443, HTTP: 80)</li>
            <li>VMESS WebSocket (TLS: 443, HTTP: 80)</li>
            <li>VLESS WebSocket (TLS: 443, HTTP: 80)</li>
        </ul>
        <p>Support wildcard bug for flexible connection.</p>
    </div>
</body>
</html>
EOF
    
    # Test nginx configuration
    nginx -t
    if [[ $? -eq 0 ]]; then
        systemctl reload nginx
        print_msg "success" "Nginx configured successfully"
    else
        print_msg "error" "Nginx configuration error"
        return 1
    fi
}

# Function to create API endpoint
create_api() {
    cat > $WEB_DIR/api.php << 'EOF'
<?php
header('Content-Type: application/json');

$script_dir = '/opt/xray-script';
$user_db = $script_dir . '/users.json';

function generate_uuid() {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

function create_user($username) {
    global $user_db, $script_dir;
    
    if (empty($username)) {
        return ['error' => 'Username is required'];
    }
    
    // Load existing users
    $users_data = json_decode(file_get_contents($user_db), true);
    if (!$users_data) {
        $users_data = ['users' => []];
    }
    
    // Check if user exists
    foreach ($users_data['users'] as $user) {
        if ($user['username'] === $username) {
            return ['error' => 'User already exists'];
        }
    }
    
    // Generate user data
    $uuid = generate_uuid();
    $password = bin2hex(random_bytes(16));
    $domain = trim(file_get_contents($script_dir . '/domain.txt'));
    
    $user_data = [
        'username' => $username,
        'uuid' => $uuid,
        'password' => $password,
        'created_at' => date('Y-m-d H:i:s'),
        'expiry' => date('Y-m-d H:i:s', strtotime('+30 days'))
    ];
    
    // Add user to database
    $users_data['users'][] = $user_data;
    file_put_contents($user_db, json_encode($users_data, JSON_PRETTY_PRINT));
    
    // Update Xray config
    exec("bash $script_dir/update_xray_config.sh");
    
    // Generate config links
    $configs = [
        'trojan_tls' => "trojan://$password@$domain:443?security=tls&type=ws&path=%2Ftrojan-ws&host=$domain#TROJAN-TLS-$username",
        'trojan_http' => "trojan://$password@$domain:80?type=ws&path=%2Ftrojan-http&host=$domain#TROJAN-HTTP-$username",
        'vmess_tls' => base64_encode(json_encode([
            'v' => '2',
            'ps' => "VMESS-TLS-$username",
            'add' => $domain,
            'port' => '443',
            'id' => $uuid,
            'aid' => '0',
            'net' => 'ws',
            'type' => 'none',
            'host' => $domain,
            'path' => '/vmess-ws',
            'tls' => 'tls'
        ])),
        'vmess_http' => base64_encode(json_encode([
            'v' => '2',
            'ps' => "VMESS-HTTP-$username",
            'add' => $domain,
            'port' => '80',
            'id' => $uuid,
            'aid' => '0',
            'net' => 'ws',
            'type' => 'none',
            'host' => $domain,
            'path' => '/vmess-http',
            'tls' => ''
        ])),
        'vless_tls' => "vless://$uuid@$domain:443?security=tls&type=ws&path=%2Fvless-ws&host=$domain#VLESS-TLS-$username",
        'vless_http' => "vless://$uuid@$domain:80?type=ws&path=%2Fvless-http&host=$domain#VLESS-HTTP-$username"
    ];
    
    return [
        'success' => true,
        'user' => $user_data,
        'configs' => $configs,
        'vmess_tls_link' => 'vmess://' . $configs['vmess_tls'],
        'vmess_http_link' => 'vmess://' . $configs['vmess_http']
    ];
}

// Handle API requests
if (isset($_GET['create']) && !empty($_GET['create'])) {
    $result = create_user($_GET['create']);
    echo json_encode($result, JSON_PRETTY_PRINT);
} else {
    echo json_encode(['error' => 'Invalid request. Use ?create=username']);
}
?>
EOF

    # Install PHP if not installed
    if ! command -v php &> /dev/null; then
        case $OS in
            ubuntu|debian)
                apt install -y php-fpm php-cli php-json
                ;;
            centos|rhel|fedora)
                yum install -y php-fpm php-cli php-json
                ;;
        esac
        
        # Configure nginx to handle PHP
        sed -i '/location \/ {/i\    location ~ \\.php$ {\n        fastcgi_pass unix:/var/run/php/php-fpm.sock;\n        fastcgi_index index.php;\n        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n        include fastcgi_params;\n    }\n' /etc/nginx/sites-available/xray
        
        systemctl enable php*-fpm
        systemctl start php*-fpm
        systemctl reload nginx
    fi
    
    print_msg "success" "API endpoint created at http://$DOMAIN/api.php"
}

# Function to update Xray configuration with users
create_update_script() {
    cat > $SCRIPT_DIR/update_xray_config.sh << 'EOF'
#!/bin/bash

CONFIG_DIR="/usr/local/etc/xray"
USER_DB="/opt/xray-script/users.json"
DOMAIN_FILE="/opt/xray-script/domain.txt"

DOMAIN=$(cat $DOMAIN_FILE)

# Read users from database
USERS=$(jq -r '.users[] | @base64' $USER_DB 2>/dev/null || echo "")

# Generate client configurations for each protocol
TROJAN_CLIENTS=""
VMESS_CLIENTS=""
VLESS_CLIENTS=""

while read -r user_data; do
    if [[ ! -z "$user_data" ]]; then
        USER_JSON=$(echo $user_data | base64 -d)
        USERNAME=$(echo $USER_JSON | jq -r '.username')
        UUID=$(echo $USER_JSON | jq -r '.uuid')
        PASSWORD=$(echo $USER_JSON | jq -r '.password')
        
        # Add to Trojan clients
        if [[ ! -z "$TROJAN_CLIENTS" ]]; then
            TROJAN_CLIENTS="$TROJAN_CLIENTS,"
        fi
        TROJAN_CLIENTS="$TROJAN_CLIENTS{\"password\":\"$PASSWORD\",\"email\":\"$USERNAME\"}"
        
        # Add to VMess clients
        if [[ ! -z "$VMESS_CLIENTS" ]]; then
            VMESS_CLIENTS="$VMESS_CLIENTS,"
        fi
        VMESS_CLIENTS="$VMESS_CLIENTS{\"id\":\"$UUID\",\"email\":\"$USERNAME\"}"
        
        # Add to VLess clients
        if [[ ! -z "$VLESS_CLIENTS" ]]; then
            VLESS_CLIENTS="$VLESS_CLIENTS,"
        fi
        VLESS_CLIENTS="$VLESS_CLIENTS{\"id\":\"$UUID\",\"email\":\"$USERNAME\"}"
    fi
done <<< "$USERS"

# Update Xray configuration
cat > $CONFIG_DIR/config.json << XRAYEOF
{
    "log": {
        "access": "/var/log/xray/access.log",
        "error": "/var/log/xray/error.log",
        "loglevel": "warning"
    },
    "inbounds": [
        {
            "tag": "trojan-tls",
            "port": 8443,
            "protocol": "trojan",
            "settings": {
                "clients": [$TROJAN_CLIENTS]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/trojan-ws"
                }
            }
        },
        {
            "tag": "vmess-tls",
            "port": 8444,
            "protocol": "vmess",
            "settings": {
                "clients": [$VMESS_CLIENTS]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vmess-ws"
                }
            }
        },
        {
            "tag": "vless-tls",
            "port": 8445,
            "protocol": "vless",
            "settings": {
                "clients": [$VLESS_CLIENTS],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/letsencrypt/live/$DOMAIN/fullchain.pem",
                            "keyFile": "/etc/letsencrypt/live/$DOMAIN/privkey.pem"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/vless-ws"
                }
            }
        },
        {
            "tag": "trojan-http",
            "port": 8080,
            "protocol": "trojan",
            "settings": {
                "clients": [$TROJAN_CLIENTS]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/trojan-http"
                }
            }
        },
        {
            "tag": "vmess-http",
            "port": 8081,
            "protocol": "vmess",
            "settings": {
                "clients": [$VMESS_CLIENTS]
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vmess-http"
                }
            }
        },
        {
            "tag": "vless-http",
            "port": 8082,
            "protocol": "vless",
            "settings": {
                "clients": [$VLESS_CLIENTS],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vless-http"
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        }
    ]
}
XRAYEOF

# Restart Xray service
systemctl restart xray
EOF

    chmod +x $SCRIPT_DIR/update_xray_config.sh
}

# Function to create user management functions
create_user_functions() {
    cat > $SCRIPT_DIR/user_manager.sh << 'EOF'
#!/bin/bash

USER_DB="/opt/xray-script/users.json"
SCRIPT_DIR="/opt/xray-script"
DOMAIN=$(cat $SCRIPT_DIR/domain.txt)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_msg() {
    case $1 in
        "error") echo -e "${RED}[ERROR] $2${NC}" ;;
        "success") echo -e "${GREEN}[SUCCESS] $2${NC}" ;;
        "warning") echo -e "${YELLOW}[WARNING] $2${NC}" ;;
        "info") echo -e "${BLUE}[INFO] $2${NC}" ;;
    esac
}

generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

generate_password() {
    openssl rand -hex 16
}

create_user() {
    echo -e "${BLUE}=== CREATE NEW USER ===${NC}"
    read -p "Enter username: " username
    
    if [[ -z "$username" ]]; then
        print_msg "error" "Username cannot be empty"
        return 1
    fi
    
    # Check if user exists
    if jq -e ".users[] | select(.username == \"$username\")" $USER_DB >/dev/null 2>&1; then
        print_msg "error" "User $username already exists"
        return 1
    fi
    
    # Generate user data
    uuid=$(generate_uuid)
    password=$(generate_password)
    created_at=$(date '+%Y-%m-%d %H:%M:%S')
    expiry=$(date -d '+30 days' '+%Y-%m-%d %H:%M:%S')
    
    # Add user to database
    jq ".users += [{\"username\":\"$username\",\"uuid\":\"$uuid\",\"password\":\"$password\",\"created_at\":\"$created_at\",\"expiry\":\"$expiry\"}]" $USER_DB > /tmp/users.json && mv /tmp/users.json $USER_DB
    
    # Update Xray configuration
    bash $SCRIPT_DIR/update_xray_config.sh
    
    print_msg "success" "User $username created successfully"
    echo
    echo -e "${YELLOW}=== USER DETAILS ===${NC}"
    echo "Username: $username"
    echo "UUID: $uuid"
    echo "Password: $password"
    echo "Created: $created_at"
    echo "Expires: $expiry"
    echo
    echo -e "${YELLOW}=== CONNECTION LINKS ===${NC}"
    echo
    echo -e "${GREEN}TROJAN TLS (Port 443):${NC}"
    echo "trojan://$password@$DOMAIN:443?security=tls&type=ws&path=%2Ftrojan-ws&host=$DOMAIN#TROJAN-TLS-$username"
    echo
    echo -e "${GREEN}TROJAN HTTP (Port 80):${NC}"
    echo "trojan://$password@$DOMAIN:80?type=ws&path=%2Ftrojan-http&host=$DOMAIN#TROJAN-HTTP-$username"
    echo
    echo -e "${GREEN}VMESS TLS (Port 443):${NC}"
    vmess_tls_json="{\"v\":\"2\",\"ps\":\"VMESS-TLS-$username\",\"add\":\"$DOMAIN\",\"port\":\"443\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"/vmess-ws\",\"tls\":\"tls\"}"
    echo "vmess://$(echo $vmess_tls_json | base64 -w 0)"
    echo
    echo -e "${GREEN}VMESS HTTP (Port 80):${NC}"
    vmess_http_json="{\"v\":\"2\",\"ps\":\"VMESS-HTTP-$username\",\"add\":\"$DOMAIN\",\"port\":\"80\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"/vmess-http\",\"tls\":\"\"}"
    echo "vmess://$(echo $vmess_http_json | base64 -w 0)"
    echo
    echo -e "${GREEN}VLESS TLS (Port 443):${NC}"
    echo "vless://$uuid@$DOMAIN:443?security=tls&type=ws&path=%2Fvless-ws&host=$DOMAIN#VLESS-TLS-$username"
    echo
    echo -e "${GREEN}VLESS HTTP (Port 80):${NC}"
    echo "vless://$uuid@$DOMAIN:80?type=ws&path=%2Fvless-http&host=$DOMAIN#VLESS-HTTP-$username"
    echo
}

list_users() {
    echo -e "${BLUE}=== ALL USERS ===${NC}"
    echo
    if [[ ! -f $USER_DB ]] || [[ $(jq '.users | length' $USER_DB) -eq 0 ]]; then
        print_msg "warning" "No users found"
        return
    fi
    
    printf "%-15s %-38s %-20s %-20s\n" "USERNAME" "UUID" "CREATED" "EXPIRES"
    echo "$(printf '%.0s-' {1..100})"
    
    jq -r '.users[] | "\(.username)|\(.uuid)|\(.created_at)|\(.expiry)"' $USER_DB | while IFS='|' read -r username uuid created expiry; do
        printf "%-15s %-38s %-20s %-20s\n" "$username" "$uuid" "$created" "$expiry"
    done
    echo
}

delete_user() {
    echo -e "${BLUE}=== DELETE USER ===${NC}"
    read -p "Enter username to delete: " username
    
    if [[ -z "$username" ]]; then
        print_msg "error" "Username cannot be empty"
        return 1
    fi
    
    # Check if user exists
    if ! jq -e ".users[] | select(.username == \"$username\")" $USER_DB >/dev/null 2>&1; then
        print_msg "error" "User $username not found"
        return 1
    fi
    
    # Remove user from database
    jq ".users |= map(select(.username != \"$username\"))" $USER_DB > /tmp/users.json && mv /tmp/users.json $USER_DB
    
    # Update Xray configuration
    bash $SCRIPT_DIR/update_xray_config.sh
    
    print_msg "success" "User $username deleted successfully"
}

show_user_config() {
    echo -e "${BLUE}=== SHOW USER CONFIG ===${NC}"
    read -p "Enter username: " username
    
    if [[ -z "$username" ]]; then
        print_msg "error" "Username cannot be empty"
        return 1
    fi
    
    # Get user data
    user_data=$(jq -r ".users[] | select(.username == \"$username\")" $USER_DB 2>/dev/null)
    
    if [[ -z "$user_data" ]]; then
        print_msg "error" "User $username not found"
        return 1
    fi
    
    uuid=$(echo $user_data | jq -r '.uuid')
    password=$(echo $user_data | jq -r '.password')
    created_at=$(echo $user_data | jq -r '.created_at')
    expiry=$(echo $user_data | jq -r '.expiry')
    
    echo
    echo -e "${YELLOW}=== USER DETAILS ===${NC}"
    echo "Username: $username"
    echo "UUID: $uuid"
    echo "Password: $password"
    echo "Created: $created_at"
    echo "Expires: $expiry"
    echo
    echo -e "${YELLOW}=== CONNECTION LINKS ===${NC}"
    echo
    echo -e "${GREEN}TROJAN TLS (Port 443):${NC}"
    echo "trojan://$password@$DOMAIN:443?security=tls&type=ws&path=%2Ftrojan-ws&host=$DOMAIN#TROJAN-TLS-$username"
    echo
    echo -e "${GREEN}TROJAN HTTP (Port 80):${NC}"
    echo "trojan://$password@$DOMAIN:80?type=ws&path=%2Ftrojan-http&host=$DOMAIN#TROJAN-HTTP-$username"
    echo
    echo -e "${GREEN}VMESS TLS (Port 443):${NC}"
    vmess_tls_json="{\"v\":\"2\",\"ps\":\"VMESS-TLS-$username\",\"add\":\"$DOMAIN\",\"port\":\"443\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"/vmess-ws\",\"tls\":\"tls\"}"
    echo "vmess://$(echo $vmess_tls_json | base64 -w 0)"
    echo
    echo -e "${GREEN}VMESS HTTP (Port 80):${NC}"
    vmess_http_json="{\"v\":\"2\",\"ps\":\"VMESS-HTTP-$username\",\"add\":\"$DOMAIN\",\"port\":\"80\",\"id\":\"$uuid\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"$DOMAIN\",\"path\":\"/vmess-http\",\"tls\":\"\"}"
    echo "vmess://$(echo $vmess_http_json | base64 -w 0)"
    echo
    echo -e "${GREEN}VLESS TLS (Port 443):${NC}"
    echo "vless://$uuid@$DOMAIN:443?security=tls&type=ws&path=%2Fvless-ws&host=$DOMAIN#VLESS-TLS-$username"
    echo
    echo -e "${GREEN}VLESS HTTP (Port 80):${NC}"
    echo "vless://$uuid@$DOMAIN:80?type=ws&path=%2Fvless-http&host=$DOMAIN#VLESS-HTTP-$username"
    echo
}

case $1 in
    "create") create_user ;;
    "list") list_users ;;
    "delete") delete_user ;;
    "show") show_user_config ;;
    *) 
        echo "Usage: $0 {create|list|delete|show}"
        exit 1
        ;;
esac
EOF

    chmod +x $SCRIPT_DIR/user_manager.sh
}

# Function to create main menu
create_main_menu() {
    cat > $SCRIPT_DIR/menu.sh << 'EOF'
#!/bin/bash

SCRIPT_DIR="/opt/xray-script"
DOMAIN_FILE="$SCRIPT_DIR/domain.txt"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                                                      ║${NC}"
    echo -e "${CYAN}║             ${YELLOW}🚀 XRAY MULTI-PORT MANAGER 🚀${CYAN}             ║${NC}"
    echo -e "${CYAN}║                                                      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
    echo
    if [[ -f $DOMAIN_FILE ]]; then
        DOMAIN=$(cat $DOMAIN_FILE)
        echo -e "${GREEN}Current Domain: ${YELLOW}$DOMAIN${NC}"
    else
        echo -e "${RED}Domain not configured${NC}"
    fi
    echo
}

show_system_info() {
    echo -e "${BLUE}=== SYSTEM INFORMATION ===${NC}"
    echo -e "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo -e "Kernel: $(uname -r)"
    echo -e "Uptime: $(uptime -p)"
    echo -e "CPU: $(nproc) cores"
    echo -e "Memory: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
    echo -e "Disk: $(df -h / | awk 'NR==2 {print $3 "/" $2 " (" $5 " used)"}')"
    echo
    echo -e "${BLUE}=== SERVICE STATUS ===${NC}"
    echo -e "Xray: $(systemctl is-active xray)"
    echo -e "Nginx: $(systemctl is-active nginx)"
    echo -e "VnStat: $(systemctl is-active vnstat)"
    echo
}

change_domain() {
    echo -e "${BLUE}=== CHANGE DOMAIN ===${NC}"
    if [[ -f $DOMAIN_FILE ]]; then
        current_domain=$(cat $DOMAIN_FILE)
        echo -e "Current domain: ${YELLOW}$current_domain${NC}"
    fi
    
    read -p "Enter new domain: " new_domain
    
    if [[ -z "$new_domain" ]]; then
        echo -e "${RED}Domain cannot be empty${NC}"
        return 1
    fi
    
    echo $new_domain > $DOMAIN_FILE
    
    # Update nginx configuration
    sed -i "s/server_name .*/server_name $new_domain *.$new_domain;/g" /etc/nginx/sites-available/xray
    
    echo -e "${GREEN}Domain changed to: $new_domain${NC}"
    echo -e "${YELLOW}Please regenerate SSL certificate for the new domain${NC}"
    
    read -p "Press Enter to continue..."
}

check_usage() {
    echo -e "${BLUE}=== BANDWIDTH USAGE ===${NC}"
    
    if command -v vnstat &> /dev/null; then
        echo -e "${GREEN}Daily Usage:${NC}"
        vnstat -d
        echo
        echo -e "${GREEN}Monthly Usage:${NC}"
        vnstat -m
        echo
        echo -e "${GREEN}Real-time Usage:${NC}"
        vnstat -l -i 1 &
        sleep 5
        kill $!
    else
        echo -e "${RED}VnStat not installed${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

run_speedtest() {
    echo -e "${BLUE}=== SPEEDTEST ===${NC}"
    
    if command -v speedtest &> /dev/null; then
        echo -e "${GREEN}Running speedtest...${NC}"
        speedtest
    elif command -v speedtest-cli &> /dev/null; then
        echo -e "${GREEN}Running speedtest...${NC}"
        speedtest-cli
    else
        echo -e "${RED}Speedtest not installed${NC}"
    fi
    
    read -p "Press Enter to continue..."
}

generate_ssl_menu() {
    echo -e "${BLUE}=== GENERATE SSL CERTIFICATE ===${NC}"
    
    if [[ ! -f $DOMAIN_FILE ]]; then
        echo -e "${RED}Domain not configured. Please configure domain first.${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    
    DOMAIN=$(cat $DOMAIN_FILE)
    echo -e "Generating SSL certificate for: ${YELLOW}$DOMAIN${NC}"
    echo -e "${YELLOW}This will temporarily stop nginx service${NC}"
    
    read -p "Continue? (y/n): " confirm
    if [[ $confirm == "y" || $confirm == "Y" ]]; then
        systemctl stop nginx
        certbot certonly --standalone --agree-tos --register-unsafely-without-email -d $DOMAIN
        
        if [[ $? -eq 0 ]]; then
            echo -e "${GREEN}SSL certificate generated successfully${NC}"
            
            # Update nginx config with SSL
            sed -i "s|ssl_certificate .*|ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;|" /etc/nginx/sites-available/xray
            sed -i "s|ssl_certificate_key .*|ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;|" /etc/nginx/sites-available/xray
            
            # Update Xray config
            bash $SCRIPT_DIR/update_xray_config.sh
            
            systemctl start nginx
            systemctl restart xray
        else
            echo -e "${RED}Failed to generate SSL certificate${NC}"
            systemctl start nginx
        fi
    fi
    
    read -p "Press Enter to continue..."
}

show_menu() {
    print_header
    show_system_info
    
    echo -e "${YELLOW}╔════════════════════ MENU ════════════════════════╗${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}1.${NC} Create Account                                 ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}2.${NC} Check Account                                  ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}3.${NC} Change Domain                                  ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}4.${NC} Check Usage (VnStat)                          ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}5.${NC} Speedtest                                      ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}6.${NC} Generate SSL                                   ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}7.${NC} List All Users                                ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}8.${NC} Delete User                                    ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}9.${NC} Restart Services                              ${YELLOW}║${NC}"
    echo -e "${YELLOW}║${NC}  ${GREEN}0.${NC} Exit                                           ${YELLOW}║${NC}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════════════╝${NC}"
    echo
    
    read -p "Choose option [0-9]: " choice
    
    case $choice in
        1) bash $SCRIPT_DIR/user_manager.sh create ;;
        2) bash $SCRIPT_DIR/user_manager.sh show ;;
        3) change_domain ;;
        4) check_usage ;;
        5) run_speedtest ;;
        6) generate_ssl_menu ;;
        7) bash $SCRIPT_DIR/user_manager.sh list ;;
        8) bash $SCRIPT_DIR/user_manager.sh delete ;;
        9) 
            echo -e "${BLUE}Restarting services...${NC}"
            systemctl restart xray nginx
            echo -e "${GREEN}Services restarted${NC}"
            read -p "Press Enter to continue..."
            ;;
        0) 
            echo -e "${GREEN}Thank you for using Xray Multi-Port Manager!${NC}"
            exit 0 
            ;;
        *) 
            echo -e "${RED}Invalid option${NC}"
            read -p "Press Enter to continue..."
            ;;
    esac
}

# Main loop
while true; do
    show_menu
done
EOF

    chmod +x $SCRIPT_DIR/menu.sh
    
    # Create shortcut command
    echo "bash $SCRIPT_DIR/menu.sh" > /usr/local/bin/xray-menu
    chmod +x /usr/local/bin/xray-menu
}

# Function to start services
start_services() {
    print_msg "info" "Starting services..."
    
    systemctl enable nginx
    systemctl enable xray
    systemctl start nginx
    systemctl start xray
    
    # Check services status
    if systemctl is-active --quiet nginx && systemctl is-active --quiet xray; then
        print_msg "success" "All services started successfully"
    else
        print_msg "error" "Some services failed to start"
        systemctl status nginx
        systemctl status xray
    fi
}

# Function to show completion message
show_completion() {
    DOMAIN=$(cat $DOMAIN_FILE)
    clear
    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                      ║${NC}"
    echo -e "${GREEN}║           ${YELLOW}🎉 INSTALLATION COMPLETED! 🎉${GREEN}            ║${NC}"
    echo -e "${GREEN}║                                                      ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${BLUE}=== INSTALLATION SUMMARY ===${NC}"
    echo -e "Domain: ${YELLOW}$DOMAIN${NC}"
    echo -e "Xray Status: ${GREEN}$(systemctl is-active xray)${NC}"
    echo -e "Nginx Status: ${GREEN}$(systemctl is-active nginx)${NC}"
    echo
    echo -e "${BLUE}=== SUPPORTED PROTOCOLS ===${NC}"
    echo -e "${GREEN}• TROJAN WebSocket${NC} (TLS: 443, HTTP: 80)"
    echo -e "${GREEN}• VMESS WebSocket${NC} (TLS: 443, HTTP: 80)" 
    echo -e "${GREEN}• VLESS WebSocket${NC} (TLS: 443, HTTP: 80)"
    echo
    echo -e "${BLUE}=== HOW TO USE ===${NC}"
    echo -e "1. Run: ${YELLOW}xray-menu${NC} to open management menu"
    echo -e "2. Generate SSL certificate first (option 6)"
    echo -e "3. Create user accounts (option 1)"
    echo -e "4. API endpoint: ${YELLOW}http://$DOMAIN/api.php?create=username${NC}"
    echo
    echo -e "${BLUE}=== PATHS ===${NC}"
    echo -e "Script Directory: ${YELLOW}$SCRIPT_DIR${NC}"
    echo -e "Xray Config: ${YELLOW}$CONFIG_DIR/config.json${NC}"
    echo -e "User Database: ${YELLOW}$USER_DB${NC}"
    echo -e "Logs: ${YELLOW}$LOG_DIR/${NC}"
    echo
    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo -e "${YELLOW}Run 'xray-menu' to start managing your server${NC}"
    echo
}

# Main installation function
main_install() {
    check_root
    detect_os
    
    print_msg "info" "Starting Xray Multi-Port AutoScript installation..."
    
    install_dependencies
    install_xray
    setup_domain
    generate_ssl
    
    if [[ $? -eq 0 ]]; then
        configure_xray
        configure_nginx
        create_api
        create_update_script
        create_user_functions
        create_main_menu
        start_services
        show_completion
    else
        print_msg "error" "SSL generation failed. You can generate it later using the menu."
        configure_xray
        configure_nginx
        create_api
        create_update_script
        create_user_functions
        create_main_menu
        start_services
        show_completion
    fi
}

# Check if running as installation or menu
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    if [[ -f "$SCRIPT_DIR/menu.sh" ]] && [[ "$1" == "menu" ]]; then
        bash $SCRIPT_DIR/menu.sh
    else
        main_install
    fi
fi
