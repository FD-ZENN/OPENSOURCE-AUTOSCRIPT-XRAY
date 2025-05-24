#!/bin/bash

# X-UI Pro AutoScript dengan API Client Management
# Support limit kuota per client
# Version: 1.0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variables
XUI_PORT=2053
API_PORT=8080
DOMAIN=""
EMAIL=""
CERT_PATH="/root/cert"
LOG_FILE="/var/log/xui-install.log"

# Function untuk logging
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

# Function untuk print colored text
print_colored() {
    printf "${2}${1}${NC}\n"
}

# Function untuk check system requirements
check_system() {
    print_colored "Checking system requirements..." $BLUE
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        print_colored "Error: Cannot detect OS" $RED
        exit 1
    fi
    
    source /etc/os-release
    if [[ "$ID" != "ubuntu" && "$ID" != "debian" && "$ID" != "centos" ]]; then
        print_colored "Error: This script only supports Ubuntu, Debian, and CentOS" $RED
        exit 1
    fi
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_colored "Error: This script must be run as root" $RED
        exit 1
    fi
    
    print_colored "System check passed!" $GREEN
}

# Function untuk install dependencies
install_dependencies() {
    print_colored "Installing dependencies..." $BLUE
    
    if command -v apt &> /dev/null; then
        apt update
        apt install -y curl wget unzip socat cron nginx python3 python3-pip sqlite3
    elif command -v yum &> /dev/null; then
        yum update -y
        yum install -y curl wget unzip socat crontabs nginx python3 python3-pip sqlite
    fi
    
    # Install Python packages
    pip3 install flask flask-cors requests
    
    print_colored "Dependencies installed!" $GREEN
}

# Function untuk install x-ui-pro
install_xui() {
    print_colored "Installing X-UI Pro..." $BLUE
    
    # Download dan install x-ui-pro
    bash <(curl -Ls https://raw.githubusercontent.com/GFW4Fun/x-ui-pro/main/install.sh)
    
    # Configure x-ui
    /usr/local/x-ui/x-ui setting -port $XUI_PORT
    /usr/local/x-ui/x-ui setting -username admin
    /usr/local/x-ui/x-ui setting -password admin123
    
    # Start x-ui service
    systemctl enable x-ui
    systemctl start x-ui
    
    print_colored "X-UI Pro installed successfully!" $GREEN
}

# Function untuk setup SSL certificate
setup_ssl() {
    if [[ -z "$DOMAIN" ]]; then
        print_colored "Domain not provided, skipping SSL setup" $YELLOW
        return
    fi
    
    print_colored "Setting up SSL certificate..." $BLUE
    
    # Install acme.sh
    curl https://get.acme.sh | sh
    source ~/.bashrc
    
    # Create cert directory
    mkdir -p $CERT_PATH
    
    # Get certificate
    ~/.acme.sh/acme.sh --register-account -m $EMAIL
    ~/.acme.sh/acme.sh --issue -d $DOMAIN --standalone
    ~/.acme.sh/acme.sh --installcert -d $DOMAIN --key-file $CERT_PATH/private.key --fullchain-file $CERT_PATH/cert.crt
    
    print_colored "SSL certificate installed!" $GREEN
}

# Function untuk create API server
create_api_server() {
    print_colored "Creating API server..." $BLUE
    
    cat > /opt/xui-api.py << 'EOF'
#!/usr/bin/env python3
import json
import sqlite3
import requests
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import os

app = Flask(__name__)
CORS(app)

# Database setup
DB_PATH = '/opt/xui_clients.db'
XUI_DB_PATH = '/etc/x-ui/x-ui.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            quota_gb INTEGER DEFAULT 0,
            used_gb REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            xui_inbound_id INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def get_client_usage(client_id):
    """Get client traffic usage from x-ui database"""
    try:
        conn = sqlite3.connect(XUI_DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT up, down FROM client_traffics WHERE inbound_id = ?', (client_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            up_bytes, down_bytes = result
            total_gb = (up_bytes + down_bytes) / (1024**3)  # Convert to GB
            return total_gb
        return 0
    except:
        return 0

@app.route('/api/clients', methods=['GET'])
def get_clients():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM clients')
    clients = cursor.fetchall()
    conn.close()
    
    result = []
    for client in clients:
        client_dict = {
            'id': client[0],
            'username': client[1],
            'email': client[2],
            'quota_gb': client[3],
            'used_gb': get_client_usage(client[8]) if client[8] else 0,
            'created_at': client[5],
            'expires_at': client[6],
            'is_active': bool(client[7]),
            'xui_inbound_id': client[8]
        }
        result.append(client_dict)
    
    return jsonify({'success': True, 'data': result})

@app.route('/api/clients', methods=['POST'])
def create_client():
    data = request.json
    username = data.get('username')
    email = data.get('email', '')
    quota_gb = data.get('quota_gb', 10)
    expires_days = data.get('expires_days', 30)
    
    if not username:
        return jsonify({'success': False, 'message': 'Username required'})
    
    expires_at = datetime.now() + timedelta(days=expires_days)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO clients (username, email, quota_gb, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (username, email, quota_gb, expires_at))
        client_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Client created successfully',
            'client_id': client_id
        })
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Username already exists'})

@app.route('/api/clients/<int:client_id>', methods=['PUT'])
def update_client(client_id):
    data = request.json
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Update fields
    if 'quota_gb' in data:
        cursor.execute('UPDATE clients SET quota_gb = ? WHERE id = ?', 
                      (data['quota_gb'], client_id))
    
    if 'is_active' in data:
        cursor.execute('UPDATE clients SET is_active = ? WHERE id = ?', 
                      (data['is_active'], client_id))
    
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Client updated successfully'})

@app.route('/api/clients/<int:client_id>', methods=['DELETE'])
def delete_client(client_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM clients WHERE id = ?', (client_id,))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'Client deleted successfully'})

@app.route('/api/clients/<int:client_id>/reset-usage', methods=['POST'])
def reset_client_usage(client_id):
    """Reset client traffic usage"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT xui_inbound_id FROM clients WHERE id = ?', (client_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result and result[0]:
            xui_inbound_id = result[0]
            # Reset traffic in x-ui database
            conn = sqlite3.connect(XUI_DB_PATH)
            cursor = conn.cursor()
            cursor.execute('UPDATE client_traffics SET up = 0, down = 0 WHERE inbound_id = ?', 
                          (xui_inbound_id,))
            conn.commit()
            conn.close()
            
            return jsonify({'success': True, 'message': 'Client usage reset successfully'})
        else:
            return jsonify({'success': False, 'message': 'Client not found or not linked to x-ui'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/system/status', methods=['GET'])
def system_status():
    # Get system information
    try:
        # Get disk usage
        disk_usage = subprocess.check_output(['df', '-h', '/']).decode().split('\n')[1].split()
        
        # Get memory usage
        mem_info = subprocess.check_output(['free', '-h']).decode().split('\n')[1].split()
        
        # Get x-ui status
        xui_status = subprocess.run(['systemctl', 'is-active', 'x-ui'], 
                                   capture_output=True, text=True).stdout.strip()
        
        return jsonify({
            'success': True,
            'data': {
                'disk_usage': {
                    'total': disk_usage[1],
                    'used': disk_usage[2],
                    'available': disk_usage[3],
                    'percentage': disk_usage[4]
                },
                'memory': {
                    'total': mem_info[1],
                    'used': mem_info[2],
                    'free': mem_info[3]
                },
                'xui_status': xui_status,
                'timestamp': datetime.now().isoformat()
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080, debug=False)
EOF

    chmod +x /opt/xui-api.py
    
    # Create systemd service for API
    cat > /etc/systemd/system/xui-api.service << EOF
[Unit]
Description=X-UI API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt
ExecStart=/usr/bin/python3 /opt/xui-api.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable xui-api
    systemctl start xui-api
    
    print_colored "API server created and started!" $GREEN
}

# Function untuk create monitoring script
create_monitoring() {
    print_colored "Creating monitoring script..." $BLUE
    
    cat > /opt/quota-monitor.py << 'EOF'
#!/usr/bin/env python3
import sqlite3
import subprocess
from datetime import datetime

DB_PATH = '/opt/xui_clients.db'
XUI_DB_PATH = '/etc/x-ui/x-ui.db'

def check_quota_limits():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, quota_gb, xui_inbound_id FROM clients WHERE is_active = 1')
    clients = cursor.fetchall()
    conn.close()
    
    for client in clients:
        client_id, username, quota_gb, xui_inbound_id = client
        
        if not xui_inbound_id:
            continue
            
        # Get current usage
        try:
            xui_conn = sqlite3.connect(XUI_DB_PATH)
            xui_cursor = xui_conn.cursor()
            xui_cursor.execute('SELECT up, down FROM client_traffics WHERE inbound_id = ?', (xui_inbound_id,))
            result = xui_cursor.fetchone()
            xui_conn.close()
            
            if result:
                up_bytes, down_bytes = result
                used_gb = (up_bytes + down_bytes) / (1024**3)
                
                # Check if quota exceeded
                if used_gb >= quota_gb:
                    print(f"Client {username} exceeded quota: {used_gb:.2f}GB / {quota_gb}GB")
                    
                    # Disable client in x-ui (you can implement this based on x-ui API)
                    # For now, just mark as inactive in our database
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute('UPDATE clients SET is_active = 0 WHERE id = ?', (client_id,))
                    conn.commit()
                    conn.close()
                    
        except Exception as e:
            print(f"Error checking client {username}: {e}")

if __name__ == '__main__':
    check_quota_limits()
EOF

    chmod +x /opt/quota-monitor.py
    
    # Add to crontab (check every 10 minutes)
    (crontab -l 2>/dev/null; echo "*/10 * * * * /usr/bin/python3 /opt/quota-monitor.py") | crontab -
    
    print_colored "Monitoring script created!" $GREEN
}

# Function untuk setup firewall
setup_firewall() {
    print_colored "Configuring firewall..." $BLUE
    
    # Install ufw if not present
    if ! command -v ufw &> /dev/null; then
        if command -v apt &> /dev/null; then
            apt install -y ufw
        else
            yum install -y ufw
        fi
    fi
    
    # Configure firewall rules
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw allow $XUI_PORT
    ufw allow $API_PORT
    ufw allow 80
    ufw allow 443
    ufw --force enable
    
    print_colored "Firewall configured!" $GREEN
}

# Function untuk show installation summary
show_summary() {
    print_colored "\n=== Installation Summary ===" $CYAN
    print_colored "X-UI Pro Panel:" $GREEN
    print_colored "URL: http://$(curl -s ipinfo.io/ip):$XUI_PORT" $WHITE
    print_colored "Username: admin" $WHITE
    print_colored "Password: admin123" $WHITE
    print_colored "" $WHITE
    print_colored "API Server:" $GREEN
    print_colored "URL: http://$(curl -s ipinfo.io/ip):$API_PORT" $WHITE
    print_colored "" $WHITE
    print_colored "API Endpoints:" $YELLOW
    print_colored "GET  /api/clients - List all clients" $WHITE
    print_colored "POST /api/clients - Create new client" $WHITE
    print_colored "PUT  /api/clients/<id> - Update client" $WHITE
    print_colored "DELETE /api/clients/<id> - Delete client" $WHITE
    print_colored "POST /api/clients/<id>/reset-usage - Reset client usage" $WHITE
    print_colored "GET  /api/system/status - System status" $WHITE
    print_colored "" $WHITE
    print_colored "Log file: $LOG_FILE" $WHITE
    print_colored "==============================\n" $CYAN
}

# Main installation function
main() {
    print_colored "Starting X-UI Pro AutoScript Installation..." $BLUE
    
    # Get domain and email from user
    read -p "Enter domain (optional, press enter to skip): " DOMAIN
    if [[ -n "$DOMAIN" ]]; then
        read -p "Enter email for SSL certificate: " EMAIL
    fi
    
    check_system
    install_dependencies
    install_xui
    
    if [[ -n "$DOMAIN" && -n "$EMAIL" ]]; then
        setup_ssl
    fi
    
    create_api_server
    create_monitoring
    setup_firewall
    
    log "Installation completed successfully"
    show_summary
}

# Check if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
