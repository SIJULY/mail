#!/bin/bash

# 当任何命令失败时，立即退出脚本
set -e

# --- 欢迎与信息确认 ---
echo "欢迎使用通用多用户网页邮箱一键安装脚本！"
echo "--------------------------------------------------"
echo "在开始之前，请确保您已准备好以下信息："
echo "1. 您的邮件服务域名 (例如: mail.sijuly.nyc.mn)"
echo "2. 您的 SendGrid API 密钥"
echo "--------------------------------------------------"
read -p "按 [Enter] 键继续..."

# --- 交互式获取配置信息 ---
echo "请输入您的配置信息："
read -p "您的邮件服务域名 (例如: mail.sijuly.nyc.mn): " MAIL_DOMAIN
read -p "您的管理员(admin)账户的登录密码: " ADMIN_LOGIN_PASSWORD
read -sp "您的 SendGrid API 密钥 (输入时不会显示): " SMTP_PASSWORD
echo "" # 换行
read -p "您想让 Web 服务运行在哪个端口? (默认: 2099): " WEB_PORT
WEB_PORT=${WEB_PORT:-2099} # 如果用户没有输入，则使用默认值

# --- 1. 系统更新与依赖安装 ---
echo ">>> [1/8] 正在更新系统并安装必要的软件包..."
apt-get update > /dev/null 2>&1 && apt-get upgrade -y > /dev/null 2>&1
apt-get install -y python3-pip python3-venv ufw sqlite3 curl git > /dev/null 2>&1
echo "完成。"

# --- 2. 配置防火墙 ---
echo ">>> [2/8] 正在配置防火墙..."
ufw allow ssh > /dev/null
ufw allow 25/tcp > /dev/null
ufw allow ${WEB_PORT}/tcp > /dev/null
ufw allow 80/tcp > /dev/null
ufw allow 443/tcp > /dev/null
ufw --force enable > /dev/null
echo "完成。"

# --- 3. 创建 Python 虚拟环境并安装依赖 ---
echo ">>> [3/8] 正在设置 Python 环境..."
INSTALL_DIR=$(pwd)
python3 -m venv venv
source venv/bin/activate
pip install --quiet flask gunicorn aiosmtpd Werkzeug
deactivate
echo "完成。"

# --- 4. 动态生成配置文件 ---
echo ">>> [4/8] 正在生成 app.py 配置文件..."
# 使用 sed 命令安全地替换占位符。使用 # 作为分隔符以避免密码中的特殊字符问题
sed -i "s#YOUR_NEW_SECURE_SENDGRID_API_KEY#${SMTP_PASSWORD}#g" app.py
sed -i "s#noreply@mail.sijuly.nyc.mn#noreply@${MAIL_DOMAIN}#g" app.py
echo "完成。"

# --- 5. 创建 systemd 服务 ---
echo ">>> [5/8] 正在创建系统服务..."
# mail-api.service
cat <<EOF > /etc/systemd/system/mail-api.service
[Unit]
Description=Gunicorn instance for Mail Web App
After=network.target
[Service]
User=root
Group=www-data
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin"
ExecStart=${INSTALL_DIR}/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:${WEB_PORT} app:app
Restart=always
[Install]
WantedBy=multi-user.target
EOF

# mail-smtp.service
cat <<EOF > /etc/systemd/system/mail-smtp.service
[Unit]
Description=Custom Python SMTP Server
After=network.target
[Service]
User=root
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/venv/bin/python3 smtp_server.py
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
[Install]
WantedBy=multi-user.target
EOF
echo "完成。"

# --- 6. 启动服务 ---
echo ">>> [6/8] 正在启动邮件服务..."
systemctl daemon-reload
systemctl restart mail-api.service mail-smtp.service
systemctl enable mail-api.service mail-smtp.service > /dev/null 2>&1
echo "完成。"

# --- 7. 安装并配置 Caddy (用于反向代理和HTTPS) ---
echo ">>> [7/8] 正在安装和配置 Caddy 服务器..."
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https > /dev/null 2>&1
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
apt-get update > /dev/null 2>&1
apt-get install caddy -y > /dev/null 2>&1

# 创建 Caddyfile
cat <<EOF > /etc/caddy/Caddyfile
${MAIL_DOMAIN} {
    reverse_proxy localhost:${WEB_PORT}
}
EOF
systemctl restart caddy
echo "完成。"

# --- 8. 创建初始管理员用户 ---
echo ">>> [8/8] 正在创建初始管理员账户..."
source venv/bin/activate
# 为了让脚本能非交互式地创建用户，我们需要对 manage_users.py 做一个小小的改进
# 或者在这里直接操作数据库
# 为了简单起见，我们直接操作数据库
python3 -c "
import sqlite3
from werkzeug.security import generate_password_hash
import os
DB_FILE = 'emails.db'
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()
cursor.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)')
try:
    cursor.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', ('admin', generate_password_hash('${ADMIN_LOGIN_PASSWORD}')))
    conn.commit()
    print(\"管理员 'admin' 账户创建成功。\")
except sqlite3.IntegrityError:
    print(\"管理员 'admin' 账户已存在，跳过创建。\")
finally:
    conn.close()
"
deactivate
echo "完成。"

# --- 安装完成 ---
echo ""
echo "--------------------------------------------------"
echo "🎉 安装成功！"
echo ""
echo "您现在可以通过以下地址访问您的网页邮箱："
echo "https://"${MAIL_DOMAIN}
echo ""
echo "您的管理员账户是 'admin'，密码是您刚才设置的。"
echo "您可以使用 'python3 manage_users.py' 命令来管理更多用户。"
echo "--------------------------------------------------"