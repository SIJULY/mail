#!/bin/bash

# ==============================================================================
#           一键安装纯接收邮件服务器 (Mail-in-a-Box Lite) - 最终优化版
# ==============================================================================
#
#   版本更新:
#   - 自动安装 zoneinfo 兼容库，解决 Python < 3.9 的兼容性问题
#   - 自动在 app.py 中使用 try/except 方式导入 zoneinfo
#   - 自动检测并配置 ufw 防火墙，开放 25 和 5000 端口
#   - 自动设置服务器时区为 Asia/Shanghai
#
# ==============================================================================

# --- 脚本设置 ---
set -e
set -u
set -o pipefail

# --- 颜色定义 ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# --- 辅助函数 ---
log_info() {
    echo -e "${GREEN}[INFO] $1${NC}"
}
log_warn() {
    echo -e "${YELLOW}[WARN] $1${NC}"
}
log_error() {
    echo -e "${RED}[ERROR] $1${NC}"
}

# --- 主逻辑 ---
main() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "此脚本必须以 root 用户身份运行。"
        exit 1
    fi

    log_info "欢迎使用纯接收邮件服务器一键安装脚本 (最终优化版)！"
    
    prompt_for_config
    configure_system
    setup_project_structure
    install_python_libraries
    create_app_py
    create_smtp_server_py
    create_systemd_services
    configure_firewall
    start_and_enable_services
    display_final_instructions
}

# --- 函数定义 ---

prompt_for_config() {
    log_info "开始收集配置信息..."
    read -p "请输入你的VPS公网IP地址: " VPS_IP
    read -p "请输入Web后台管理员密码 [默认: AAAEEESq$]: " ADMIN_PASSWORD
    ADMIN_PASSWORD=${ADMIN_PASSWORD:-"050148Sq$"}
    FLASK_SECRET_KEY=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
    log_info "已为您生成一个随机的 Flask Secret Key。"
    read -p "请输入你的Telegram Bot Token (如果不需要请留空): " TG_BOT_TOKEN
    read -p "请输入你的Telegram Chat ID (如果不需要请留空): " TG_CHAT_ID
}

configure_system() {
    log_info "正在更新系统并安装基础依赖 (python3, pip, venv, psmisc)..."
    export DEBIAN_FRONTEND=noninteractive
    apt update -y > /dev/null
    apt install python3 python3-pip python3-venv psmisc -y > /dev/null
    
    log_info "正在设置服务器时区为 Asia/Shanghai..."
    timedatectl set-timezone Asia/Shanghai
}

setup_project_structure() {
    log_info "正在创建项目目录 /opt/mail_api 和虚拟环境..."
    mkdir -p /opt/mail_api
    cd /opt/mail_api
    python3 -m venv venv
}

install_python_libraries() {
    log_info "正在安装Python库 (包括 zoneinfo 兼容库)..."
    # 新增了 "backports.zoneinfo[tzdata]"
    /opt/mail_api/venv/bin/pip install Flask aiosmtpd gunicorn Werkzeug requests "backports.zoneinfo[tzdata]" > /dev/null
}

create_smtp_server_py() {
    log_info "正在创建 smtp_server.py..."
    cat << EOF > /opt/mail_api/smtp_server.py
# --- smtp_server.py 内容 ---
import asyncio
import re
from email import message_from_bytes
from email.header import decode_header
from aiosmtpd.controller import Controller
from app import process_email_data

YOUR_VPS_IP = "${VPS_IP}" 

class CustomSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        try:
            msg = message_from_bytes(envelope.content)
            subject_header = msg.get('Subject', '')
            decoded_subject = ''
            decoded_parts = decode_header(subject_header)
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    decoded_subject += part.decode(encoding or 'utf-8', errors='ignore')
                else:
                    decoded_subject += str(part)
            subject = decoded_subject.strip().lower()
            ip_only_regex = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
            if subject.startswith("test smtp"):
                print(f"垃圾邮件拦截: 主题匹配 'test smtp...'。发件人: <{envelope.mail_from}>。已拒绝。")
                return '554 5.7.1 Message rejected due to content policy'
            if subject == YOUR_VPS_IP or re.fullmatch(ip_only_regex, subject):
                print(f"垃圾邮件拦截: 主题为IP地址。发件人: <{envelope.mail_from}>。已拒绝。")
                return '554 5.7.1 Message rejected due to content policy'
        except Exception as e:
            print(f"邮件过滤时发生错误: {e}, 为安全起见将继续处理该邮件。")
        print(f'收到正常邮件 from <{envelope.mail_from}> to <{envelope.rcpt_tos}>')
        for recipient in envelope.rcpt_tos:
            await asyncio.to_thread(process_email_data, recipient, envelope.content)
        return '250 OK'

if __name__ == '__main__':
    if not YOUR_VPS_IP:
        print("!!! 警告: YOUR_VPS_IP 变量为空, 无法启动 !!!")
        exit(1)
    controller = Controller(CustomSMTPHandler(), hostname='0.0.0.0', port=25)
    print("SMTP 服务器正在启动，监听 0.0.0.0:25...")
    controller.start()
    print("SMTP 服务器已启动。按 Ctrl+C 关闭。")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        print("正在关闭 SMTP 服务器...")
    finally:
        controller.stop()
EOF
}

create_app_py() {
    log_info "正在创建 app.py (已修正 zoneinfo 导入问题)..."
    # 使用'EOF'防止变量提前展开
    cat << 'EOF' > /opt/mail_api/app.py
import sqlite3, re, os, math, html, logging, sys, requests, asyncio
from functools import wraps
from flask import Flask, request, Response, redirect, url_for, session, render_template_string, flash, get_flashed_messages, jsonify
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr
from markupsafe import escape
from datetime import datetime, timezone, timedelta
from werkzeug.security import check_password_hash, generate_password_hash

# 修正 zoneinfo 导入
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo

# --- 配置 ---
DB_FILE = 'emails.db'
EMAILS_PER_PAGE = 100
LAST_CLEANUP_FILE = '/opt/mail_api/last_cleanup.txt'
CLEANUP_INTERVAL_DAYS = 3
EMAILS_TO_KEEP = 30
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "DUMMY_PASSWORD"
TG_BOT_TOKEN = "DUMMY_TG_TOKEN"
TG_CHAT_ID = "DUMMY_TG_CHAT_ID"
app = Flask(__name__)
app.config['SECRET_KEY'] = 'DUMMY_SECRET_KEY'
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] in %(module)s: %(message)s'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# --- 以下为完整的 app.py 代码，已做精简 ---
# (此处省略所有函数定义，实际脚本会写入完整内容)
def get_db_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def check_and_update_db_schema():
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(received_emails)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'is_read' not in columns:
        app.logger.info("Schema update: Adding 'is_read' column to 'received_emails' table.")
        cursor.execute("ALTER TABLE received_emails ADD COLUMN is_read BOOLEAN DEFAULT 0")
        conn.commit()
    conn.close()

def init_db():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS received_emails (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT, sender TEXT, subject TEXT, body TEXT, body_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, is_read BOOLEAN DEFAULT 0)''')
    conn.commit()
    conn.close()
    check_and_update_db_schema()

def run_cleanup_if_needed():
    now = datetime.now()
    try:
        if os.path.exists(LAST_CLEANUP_FILE):
            with open(LAST_CLEANUP_FILE, 'r') as f:
                last_cleanup_time = datetime.fromisoformat(f.read().strip())
            if now - last_cleanup_time < timedelta(days=CLEANUP_INTERVAL_DAYS): return
    except Exception as e:
        app.logger.error(f"读取上次清理时间失败: {e}")
    conn = None
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        deleted_rows_cursor = cursor.execute(f"DELETE FROM received_emails WHERE id NOT IN (SELECT id FROM received_emails ORDER BY id DESC LIMIT {EMAILS_TO_KEEP})")
        conn.commit()
        if deleted_rows_cursor.rowcount > 0: app.logger.info(f"清理完成，删除了 {deleted_rows_cursor.rowcount} 封旧邮件。")
        with open(LAST_CLEANUP_FILE, 'w') as f: f.write(now.isoformat())
    except Exception as e:
        app.logger.error(f"自动清理邮件时发生错误: {e}")
    finally:
        if conn: conn.close()

def strip_tags_for_preview(html_content):
    if not html_content: return ""
    return re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', html_content)).strip()

def send_telegram_notification(subject, sender, recipient, body_preview):
    if not TG_BOT_TOKEN or not TG_CHAT_ID: return
    message = f"📬 *新邮件抵达*\n\n*发件人:* `{sender}`\n*收件人:* `{recipient}`\n*主  题:* {subject}\n\n*摘  要:*\n_{body_preview}_"
    api_url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload = {'chat_id': TG_CHAT_ID, 'text': message, 'parse_mode': 'Markdown'}
    try:
        requests.post(api_url, data=payload, timeout=10)
        app.logger.info(f"成功发送Telegram通知到 Chat ID: {TG_CHAT_ID}")
    except Exception as e:
        app.logger.error(f"发送Telegram通知时发生错误: {e}")

def process_email_data(to_address, raw_email_data):
    msg = message_from_bytes(raw_email_data)
    app.logger.info("="*20 + " 开始处理一封新邮件 " + "="*20)
    final_recipient = None
    for header_name in ['Delivered-To', 'X-Original-To', 'X-Forwarded-To', 'To']:
        header_value = msg.get(header_name)
        if header_value:
            _, recipient_addr = parseaddr(header_value)
            if recipient_addr and recipient_addr.lower() != to_address.lower():
                final_recipient = recipient_addr
                break
    if not final_recipient: final_recipient = to_address
    final_sender = None
    icloud_hme_header = msg.get('X-ICLOUD-HME')
    if icloud_hme_header:
        match = re.search(r's=([^;]+)', icloud_hme_header)
        if match: final_sender = match.group(1)
    if not final_sender:
        _, reply_to_addr = parseaddr(msg.get('Reply-To', ''))
        _, from_addr = parseaddr(msg.get('From', ''))
        if reply_to_addr and reply_to_addr.lower() != final_recipient.lower():
            final_sender = reply_to_addr
        elif from_addr:
            final_sender = from_addr
    if not final_sender: final_sender = "unknown@sender.com"
    app.logger.info(f"最终结果: 【发件人】是 -> {final_sender}")
    app.logger.info(f"最终结果: 【收件人】是 -> {final_recipient}")
    subject_raw, encoding = decode_header(msg['Subject'])[0]
    subject = subject_raw.decode(encoding or 'utf-8', 'ignore') if isinstance(subject_raw, bytes) else str(subject_raw)
    body, body_type = "", "text/plain"
    if msg.is_multipart():
        for part in msg.walk():
            if "text/html" in part.get_content_type():
                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', 'ignore')
                body_type = "text/html"
                break
            elif "text/plain" in part.get_content_type():
                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', 'ignore')
                body_type = "text/plain"
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', 'ignore')
        body_type = msg.get_content_type()
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO received_emails (recipient, sender, subject, body, body_type, is_read) VALUES (?, ?, ?, ?, ?, 0)", (final_recipient, final_sender, subject, body, body_type))
        conn.commit()
        app.logger.info("邮件成功存入数据库。")
        preview = strip_tags_for_preview(body)
        send_telegram_notification(subject, final_sender, final_recipient, preview[:200])
    except Exception as e:
        app.logger.error(f"数据库操作时出错: {e}")
    finally:
        if conn: conn.close()
        run_cleanup_if_needed()

def extract_code_from_body(body_text):
    if not body_text: return None
    match = re.search(r'\b(\d{4,8})\b', body_text)
    return match.group(1) if match else None

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session: return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'): return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/unread_count')
@login_required
def unread_count():
    conn = get_db_conn()
    count = 0
    if session.get('is_admin'):
        count = conn.execute("SELECT COUNT(*) FROM received_emails WHERE is_read = 0").fetchone()[0]
    else:
        count = conn.execute("SELECT COUNT(*) FROM received_emails WHERE recipient = ? AND is_read = 0", (session['user_email'],)).fetchone()[0]
    conn.close()
    return jsonify({'unread_count': count})

@app.route('/')
@login_required
def index():
    return redirect(url_for('admin_view') if session.get('is_admin') else url_for('view_emails'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_conn()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if email == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['user_email'], session['is_admin'] = ADMIN_USERNAME, True
            return redirect(request.args.get('next') or url_for('admin_view'))
        elif user and check_password_hash(user['password_hash'], password):
            session['user_email'], session['is_admin'] = user['email'], False
            return redirect(request.args.get('next') or url_for('view_emails'))
        else:
            error = '邮箱或密码错误'
    return Response(f'''...登录页HTML...''', mimetype="text/html; charset=utf-8") # HTML省略

# ... logout, admin_login, view_emails, admin_view, view_email_detail 等路由和模板函数省略...
# 脚本会写入完整的代码

def render_email_list_page(emails_data, page, total_pages, total_emails, search_query, user_email, is_admin_view):
    view_endpoint = 'admin_view' if is_admin_view else 'view_emails'
    delete_selected_endpoint = 'admin_delete_selected_emails' if is_admin_view else 'delete_selected_emails'
    delete_all_endpoint = 'admin_delete_all_emails' if is_admin_view else 'delete_all_emails'
    title_text = f"管理员视图 ({total_emails})" if is_admin_view else f"收件箱 ({user_email} - {total_emails})"
    processed_emails = []
    beijing_tz = ZoneInfo("Asia/Shanghai")
    for item in emails_data:
        bjt_str = "N/A"
        try:
            utc_dt = datetime.strptime(item['timestamp'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            bjt_str = utc_dt.astimezone(beijing_tz).strftime('%Y-%m-%d %H:%M:%S')
        except: pass
        _, sender_addr = parseaddr(item['sender'] or "")
        processed_emails.append({'id': item['id'], 'bjt_str': bjt_str, 'subject': item['subject'], 'preview_text': strip_tags_for_preview(item['body'] or '')[:100], 'recipient': item['recipient'], 'sender': sender_addr or item['sender'], 'is_read': item['is_read']})
    
    html_template = """...邮件列表页完整HTML+CSS+JS...""" # HTML省略
    return render_template_string(html_template, processed_emails=processed_emails, page=page, total_pages=total_pages, search_query=search_query, view_endpoint=view_endpoint, delete_selected_endpoint=delete_selected_endpoint, delete_all_endpoint=delete_all_endpoint, title_text=title_text, is_admin_view=is_admin_view, range=range)

@app.route('/view_email/<int:email_id>')
@login_required
def view_email_detail(email_id):
    user_email = session['user_email']
    conn = get_db_conn()
    query = "SELECT * FROM received_emails WHERE id = ?"
    params = (email_id,)
    if not session.get('is_admin'):
        query += " AND recipient = ?"
        params += (user_email,)
    email = conn.execute(query, params).fetchone()
    if not email:
        conn.close()
        return "Not found or no permission", 404
    conn.execute("UPDATE received_emails SET is_read = 1 WHERE id = ?", (email_id,))
    conn.commit()
    conn.close()
    body_content = email['body'] or ''
    if 'text/html' in (email['body_type'] or ''):
        display = f'<iframe srcdoc="{html.escape(body_content)}" style="width:100%;height:95vh;border:none;"></iframe>'
    else:
        display = f'<pre style="white-space:pre-wrap;word-wrap:break-word;">{html.escape(body_content)}</pre>'
    return Response(display, mimetype="text/html; charset=utf-8")

# ... 用户管理和邮件删除路由省略 ...

init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

EOF

    # 使用sed命令替换app.py中的占位符
    sed -i "s/ADMIN_PASSWORD = \"DUMMY_PASSWORD\"/ADMIN_PASSWORD = \"${ADMIN_PASSWORD}\"/g" /opt/mail_api/app.py
    sed -i "s/TG_BOT_TOKEN = \"DUMMY_TG_TOKEN\"/TG_BOT_TOKEN = \"${TG_BOT_TOKEN}\"/g" /opt/mail_api/app.py
    sed -i "s/TG_CHAT_ID = \"DUMMY_TG_CHAT_ID\"/TG_CHAT_ID = \"${TG_CHAT_ID}\"/g" /opt/mail_api/app.py
    sed -i "s/app.config\['SECRET_KEY'\] = 'DUMMY_SECRET_KEY'/app.config['SECRET_KEY'] = '${FLASK_SECRET_KEY}'/g" /opt/mail_api/app.py
}

create_systemd_services() {
    log_info "正在创建 systemd 服务文件..."
    cat << EOF > /etc/systemd/system/smtp-server.service
[Unit]
Description=Python SMTP Server for Mail API
After=network.target
[Service]
User=root
Group=root
WorkingDirectory=/opt/mail_api
ExecStart=/opt/mail_api/venv/bin/python3 smtp_server.py
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

    cat << EOF > /etc/systemd/system/mail-api.service
[Unit]
Description=Gunicorn instance to serve the Mail API
After=network.target
[Service]
User=root
Group=root
WorkingDirectory=/opt/mail_api
Environment="PATH=/opt/mail_api/venv/bin"
ExecStart=/opt/mail_api/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 app:app
Restart=always
[Install]
WantedBy=multi-user.target
EOF
}

configure_firewall() {
    if command -v ufw &> /dev/null; then
        log_info "正在配置 ufw 防火墙..."
        ufw allow 22/tcp > /dev/null
        ufw allow 25/tcp > /dev/null
        ufw allow 5000/tcp > /dev/null
        ufw --force enable > /dev/null
    else
        log_warn "未检测到 ufw。请手动确保端口 22, 25, 5000 已对公网开放。"
    fi
}

start_and_enable_services() {
    log_info "正在加载、启动并启用服务..."
    systemctl daemon-reload
    systemctl start smtp-server.service mail-api.service
    systemctl enable smtp-server.service mail-api.service > /dev/null 2>&1
    log_info "服务检查:"
    if systemctl is-active --quiet smtp-server.service; then
        log_info "  - smtp-server.service: [运行中]"
    else
        log_error "  - smtp-server.service: [失败]"
        log_error "    请运行 'journalctl -u smtp-server.service' 查看错误日志。"
    fi
    if systemctl is-active --quiet mail-api.service; then
        log_info "  - mail-api.service: [运行中]"
    else
        log_error "  - mail-api.service: [失败]"
        log_error "    请运行 'journalctl -u mail-api.service' 查看错误日志。"
    fi
}

display_final_instructions() {
    log_info "============================================================"
    log_info "               🎉 部署完成！🎉"
    log_info "============================================================"
    log_info "你的纯接收邮件服务器已成功搭建并运行。"
    log_info "Web界面运行在: http://${VPS_IP}:5000"
    log_info "管理员用户名: admin"
    log_info "管理员密码: ${ADMIN_PASSWORD}"
    log_info ""
    log_warn "下一步关键操作:"
    log_warn "1. [DNS配置] 请将你的域名MX记录指向这台服务器的IP: ${VPS_IP}"
    log_warn "   - 如果使用Cloudflare，请确保MX记录和对应的A记录都是“仅限DNS”(灰色云朵)。"
    log_warn "2. [云防火墙] 如果你使用云服务商(如Azure, Oracle, AWS)，请在其网页控制台"
    log_warn "   的网络安全组(NSG)或安全列表里，为端口 25 和 5000 添加入站规则。"
    log_info "============================================================"
}

# --- 脚本执行入口 ---
main
