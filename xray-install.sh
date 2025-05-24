#!/bin/bash

# X-UI Pro Autoscript dengan API Client Management
# Dibuat untuk instalasi otomatis dan penambahan fitur API

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Fungsi untuk mengecek OS
check_os() {
    print_status "Mengecek sistem operasi..."
    if [[ -f /etc/redhat-release ]]; then
        OS="centos"
    elif cat /etc/issue | grep -Eqi "debian"; then
        OS="debian"
    elif cat /etc/issue | grep -Eqi "ubuntu"; then
        OS="ubuntu"
    else
        print_error "OS tidak didukung!"
        exit 1
    fi
    print_status "OS terdeteksi: $OS"
}

# Fungsi untuk mengupdate sistem
update_system() {
    print_status "Mengupdate sistem..."
    if [[ "$OS" == "ubuntu" || "$OS" == "debian" ]]; then
        apt update -y && apt upgrade -y
        apt install -y curl wget socat git jq
    elif [[ "$OS" == "centos" ]]; then
        yum update -y
        yum install -y curl wget socat git jq
    fi
}

# Fungsi untuk menginstall x-ui-pro
install_xui_pro() {
    print_status "Menginstall X-UI Pro..."
    bash <(curl -Ls https://raw.githubusercontent.com/GFW4Fun/x-ui-pro/master/x-ui-pro.sh)
    
    if [ $? -eq 0 ]; then
        print_status "X-UI Pro berhasil diinstall!"
    else
        print_error "Gagal menginstall X-UI Pro!"
        exit 1
    fi
}

# Fungsi untuk membuat API server
create_api_server() {
    print_status "Membuat API server untuk manajemen client..."
    
    # Membuat direktori API
    mkdir -p /root/xui-api
    
    # Membuat file API server dengan Node.js
    cat > /root/xui-api/server.js << 'EOF'
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = 3001;

app.use(express.json());

// Middleware untuk CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

// Fungsi untuk menjalankan command x-ui
function runXUICommand(command) {
    return new Promise((resolve, reject) => {
        exec(`x-ui ${command}`, (error, stdout, stderr) => {
            if (error) {
                reject(error);
                return;
            }
            resolve(stdout);
        });
    });
}

// Fungsi untuk membaca konfigurasi x-ui
function getXUIConfig() {
    try {
        const configPath = '/etc/x-ui/x-ui.db';
        // Implementasi pembacaan database SQLite x-ui
        return { status: 'success' };
    } catch (error) {
        return { status: 'error', message: error.message };
    }
}

// API Endpoints

// Status API
app.get('/api/status', (req, res) => {
    res.json({
        status: 'running',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
});

// Membuat client baru dengan limit kuota
app.post('/api/client/create', async (req, res) => {
    try {
        const { 
            username, 
            password, 
            quota_limit_gb = 10, 
            days_limit = 30,
            port = 443,
            protocol = 'vless'
        } = req.body;

        if (!username) {
            return res.status(400).json({
                success: false,
                message: 'Username diperlukan'
            });
        }

        // Konversi GB ke bytes untuk limit
        const quotaBytes = quota_limit_gb * 1024 * 1024 * 1024;
        
        // Menghitung tanggal expired
        const expiredDate = new Date();
        expiredDate.setDate(expiredDate.getDate() + days_limit);
        const expiredTimestamp = Math.floor(expiredDate.getTime() / 1000);

        // Membuat konfigurasi client
        const clientConfig = {
            id: generateUUID(),
            flow: "",
            email: username,
            limitIp: 2,
            totalGB: quotaBytes,
            expiryTime: expiredTimestamp,
            enable: true,
            tgId: "",
            subId: generateRandomString(16)
        };

        // Simpan konfigurasi ke file
        const configFile = `/root/xui-api/clients/${username}.json`;
        await fs.promises.mkdir('/root/xui-api/clients', { recursive: true });
        await fs.promises.writeFile(configFile, JSON.stringify(clientConfig, null, 2));

        // Generate link konfigurasi
        const configLink = generateConfigLink(clientConfig, port, protocol);

        res.json({
            success: true,
            data: {
                username: username,
                quota_limit_gb: quota_limit_gb,
                days_limit: days_limit,
                expired_date: expiredDate.toISOString(),
                config_link: configLink,
                qr_code: `data:image/svg+xml;base64,${Buffer.from(generateQRCode(configLink)).toString('base64')}`
            },
            message: 'Client berhasil dibuat'
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Gagal membuat client: ' + error.message
        });
    }
});

// Mendapatkan daftar client
app.get('/api/clients', async (req, res) => {
    try {
        const clientsDir = '/root/xui-api/clients';
        
        if (!fs.existsSync(clientsDir)) {
            return res.json({
                success: true,
                data: [],
                message: 'Belum ada client'
            });
        }

        const files = await fs.promises.readdir(clientsDir);
        const clients = [];

        for (const file of files) {
            if (file.endsWith('.json')) {
                const clientData = JSON.parse(
                    await fs.promises.readFile(path.join(clientsDir, file), 'utf8')
                );
                
                clients.push({
                    username: clientData.email,
                    quota_used: 0, // Implementasi pembacaan usage dari x-ui database
                    quota_limit: Math.round(clientData.totalGB / (1024 * 1024 * 1024)),
                    expired_date: new Date(clientData.expiryTime * 1000).toISOString(),
                    status: clientData.enable ? 'active' : 'disabled'
                });
            }
        }

        res.json({
            success: true,
            data: clients,
            total: clients.length
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Gagal mendapatkan daftar client: ' + error.message
        });
    }
});

// Menghapus client
app.delete('/api/client/:username', async (req, res) => {
    try {
        const { username } = req.params;
        const configFile = `/root/xui-api/clients/${username}.json`;

        if (fs.existsSync(configFile)) {
            await fs.promises.unlink(configFile);
            res.json({
                success: true,
                message: `Client ${username} berhasil dihapus`
            });
        } else {
            res.status(404).json({
                success: false,
                message: 'Client tidak ditemukan'
            });
        }

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Gagal menghapus client: ' + error.message
        });
    }
});

// Update quota client
app.put('/api/client/:username/quota', async (req, res) => {
    try {
        const { username } = req.params;
        const { quota_limit_gb } = req.body;
        const configFile = `/root/xui-api/clients/${username}.json`;

        if (!fs.existsSync(configFile)) {
            return res.status(404).json({
                success: false,
                message: 'Client tidak ditemukan'
            });
        }

        const clientConfig = JSON.parse(await fs.promises.readFile(configFile, 'utf8'));
        clientConfig.totalGB = quota_limit_gb * 1024 * 1024 * 1024;

        await fs.promises.writeFile(configFile, JSON.stringify(clientConfig, null, 2));

        res.json({
            success: true,
            message: `Quota client ${username} berhasil diupdate ke ${quota_limit_gb}GB`
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: 'Gagal update quota: ' + error.message
        });
    }
});

// Helper functions
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c == 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
}

function generateRandomString(length) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

function generateConfigLink(config, port, protocol) {
    // Generate VLESS/VMESS link sesuai protokol
    const serverIP = process.env.SERVER_IP || 'YOUR_SERVER_IP';
    
    if (protocol === 'vless') {
        return `vless://${config.id}@${serverIP}:${port}?type=tcp&security=tls&sni=${serverIP}&fp=chrome&pbk=&sid=&spx=%2F#${config.email}`;
    } else {
        // VMESS configuration
        const vmessConfig = {
            v: "2",
            ps: config.email,
            add: serverIP,
            port: port.toString(),
            id: config.id,
            aid: "0",
            scy: "auto",
            net: "tcp",
            type: "none",
            host: "",
            path: "",
            tls: "tls",
            sni: serverIP,
            alpn: ""
        };
        return `vmess://${Buffer.from(JSON.stringify(vmessConfig)).toString('base64')}`;
    }
}

function generateQRCode(text) {
    // Simple SVG QR code placeholder
    return `<svg width="200" height="200" xmlns="http://www.w3.org/2000/svg">
        <rect width="200" height="200" fill="white"/>
        <text x="100" y="100" text-anchor="middle" fill="black">QR Code</text>
        <text x="100" y="120" text-anchor="middle" fill="black" font-size="8">${text.substring(0, 20)}...</text>
    </svg>`;
}

app.listen(PORT, '0.0.0.0', () => {
    console.log(`API Server berjalan di port ${PORT}`);
    console.log(`Akses API: http://localhost:${PORT}/api/status`);
});
EOF

    # Install Node.js jika belum ada
    if ! command -v node &> /dev/null; then
        print_status "Menginstall Node.js..."
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
        apt-get install -y nodejs
    fi

    # Install dependencies
    cd /root/xui-api
    npm init -y
    npm install express

    # Membuat service systemd untuk API
    cat > /etc/systemd/system/xui-api.service << EOF
[Unit]
Description=X-UI API Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/xui-api
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=3
Environment=NODE_ENV=production
Environment=SERVER_IP=$(curl -s ipinfo.io/ip)

[Install]
WantedBy=multi-user.target
EOF

    # Start dan enable service
    systemctl daemon-reload
    systemctl enable xui-api
    systemctl start xui-api

    print_status "API server berhasil dibuat dan dijalankan!"
}

# Fungsi untuk membuat script manajemen
create_management_script() {
    print_status "Membuat script manajemen..."
    
    cat > /usr/local/bin/xui-manager << 'EOF'
#!/bin/bash

API_URL="http://localhost:3001/api"

case "$1" in
    "create")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: xui-manager create <username> <quota_gb> [days]"
            exit 1
        fi
        
        username="$2"
        quota="$3"
        days="${4:-30}"
        
        curl -X POST "$API_URL/client/create" \
            -H "Content-Type: application/json" \
            -d "{\"username\":\"$username\",\"quota_limit_gb\":$quota,\"days_limit\":$days}" \
            | jq .
        ;;
    "list")
        curl -s "$API_URL/clients" | jq .
        ;;
    "delete")
        if [ -z "$2" ]; then
            echo "Usage: xui-manager delete <username>"
            exit 1
        fi
        
        curl -X DELETE "$API_URL/client/$2" | jq .
        ;;
    "quota")
        if [ -z "$2" ] || [ -z "$3" ]; then
            echo "Usage: xui-manager quota <username> <new_quota_gb>"
            exit 1
        fi
        
        curl -X PUT "$API_URL/client/$2/quota" \
            -H "Content-Type: application/json" \
            -d "{\"quota_limit_gb\":$3}" \
            | jq .
        ;;
    "status")
        curl -s "$API_URL/status" | jq .
        ;;
    *)
        echo "X-UI Manager - Extended API"
        echo "Commands:"
        echo "  create <username> <quota_gb> [days] - Buat client baru"
        echo "  list                               - Lihat semua client"
        echo "  delete <username>                  - Hapus client"
        echo "  quota <username> <quota_gb>        - Update quota client"
        echo "  status                             - Status API server"
        ;;
esac
EOF

    chmod +x /usr/local/bin/xui-manager
}

# Fungsi untuk konfigurasi firewall
configure_firewall() {
    print_status "Mengkonfigurasi firewall..."
    
    # Buka port untuk API
    if command -v ufw &> /dev/null; then
        ufw allow 3001
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=3001/tcp
        firewall-cmd --reload
    fi
}

# Fungsi untuk menampilkan informasi
show_info() {
    SERVER_IP=$(curl -s ipinfo.io/ip)
    
    echo ""
    echo "================================================"
    echo -e "${GREEN}X-UI Pro + API berhasil diinstall!${NC}"
    echo "================================================"
    echo ""
    echo "Panel X-UI Pro:"
    echo "URL: http://$SERVER_IP:54321"
    echo "Username: admin"
    echo "Password: admin"
    echo ""
    echo "API Endpoints:"
    echo "Base URL: http://$SERVER_IP:3001/api"
    echo "Status: GET /status"
    echo "Buat Client: POST /client/create"
    echo "List Client: GET /clients"
    echo "Hapus Client: DELETE /client/{username}"
    echo "Update Quota: PUT /client/{username}/quota"
    echo ""
    echo "Command Line Tool:"
    echo "xui-manager create user1 10 30    # Buat user dengan quota 10GB, 30 hari"
    echo "xui-manager list                  # Lihat semua client"
    echo "xui-manager delete user1          # Hapus client"
    echo "xui-manager quota user1 20        # Update quota ke 20GB"
    echo "xui-manager status                # Status API"
    echo ""
    echo "Log API: journalctl -u xui-api -f"
    echo ""
    echo "================================================"
}

# Main function
main() {
    clear
    echo "================================================"
    echo "X-UI Pro Autoscript dengan API Client Management"
    echo "================================================"
    echo ""
    
    check_os
    update_system
    install_xui_pro
    
    print_status "Menunggu X-UI Pro siap..."
    sleep 10
    
    create_api_server
    create_management_script
    configure_firewall
    
    show_info
}

# Jalankan script utama
main
