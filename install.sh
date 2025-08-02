#!/bin/bash

# =================================================================================
# 轻量级邮件服务器一键安装脚本 (V4 - DNS解耦/Caddy/纯接收版)
#
# 作者: Gemini
# 日期: 2025-08-03
#
# 功能:
# - DNS解耦: 允许先安装后解析，安装过程不再依赖域名实时解析。
# - 使用 Caddy 自动处理反向代理和 HTTPS 证书。
# - 提供一键安装与一键卸载功能。
# - 多用户系统 (管理员 + 普通用户)。
# - 增强的Web界面 (分页、搜索、预览、验证码高亮)。
# - 自动清理旧邮件。
# - 使用哈希存储密码，提升安全性。
# - 纯接收邮件，无任何发送/回复功能。
#
# 使用方法:
# 1. chmod +x install_mail_server_v4.sh
# 2. ./install_mail_server_v4.sh
# =================================================================================

# --- 颜色定义 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# --- 脚本设置 ---
set -e
PROJECT_DIR="/opt/mail_api"
GUNICORN_PORT=8000
CADDYFILE_PATH="/etc/caddy/Caddyfile"

# --- 检查Root权限 ---
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误：此脚本必须以 root 身份运行。${NC}"
    exit 1
fi

# --- 卸载功能 ---
uninstall_server() {
    echo -e "${YELLOW}警告：你确定要卸载邮件服务器吗？${NC}"
    echo -e "${RED}此操作将执行以下操作:${NC}"
    echo "- 停止并禁用 mail-smtp, mail-api, caddy 服务"
    echo "- 删除 systemd 服务文件"
    echo "- 删除防火墙规则 (25, 80, 443)"
    echo "- 删除整个应用程序目录 (${PROJECT_DIR})"
    echo "- 卸载 Caddy 并删除其配置文件 (${CADDYFILE_PATH})"
    echo "- ${RED}所有已接收的邮件和用户数据都将被永久删除！${NC}"
    read -p "请输入 'yes' 以确认卸载: " CONFIRM_UNINSTALL
    if [ "$CONFIRM_UNINSTALL" != "yes" ]; then
        echo "卸载已取消。"
        exit 0
    fi

    echo -e "${BLUE}>>> 正在停止服务...${NC}"
    systemctl stop mail-smtp.service mail-api.service caddy 2>/dev/null || true
    systemctl disable mail-smtp.service mail-api.service caddy 2>/dev/null || true

    echo -e "${BLUE}>>> 正在删除服务文件...${NC}"
    rm -f /etc/systemd/system/mail-smtp.service
    rm -f /etc/systemd/system/mail-api.service

    echo -e "${BLUE}>>> 正在删除应用程序目录...${NC}"
    rm -rf ${PROJECT_DIR}

    echo -e "${BLUE}>>> 正在卸载 Caddy 并删除配置文件...${NC}"
    rm -f ${CADDYFILE_PATH}
    # 使用 apt purge 来确保配置文件也被移除
    DEBIAN_FRONTEND=noninteractive apt-get purge -y caddy > /dev/null

    echo -e "${BLUE}>>> 正在更新防火墙规则...${NC}"
    ufw delete allow 25/tcp > /dev/null
    ufw delete allow 80/tcp > /dev/null
    ufw delete allow 443/tcp > /dev/null
    ufw reload > /dev/null

    # 清理 Caddy 的 apt 源
    rm -f /etc/apt/sources.list.d/caddy-stable.list

    systemctl daemon-reload

    echo -e "${GREEN}✅ 邮件服务器已成功卸载。${NC}"
    exit 0
}

# --- 安装功能 ---
install_server() {
    # --- 欢迎与信息收集 ---
    echo -e "${GREEN}欢迎使用轻量级邮件服务器一键安装脚本 (V4 - DNS解耦版)！${NC}"
    echo "------------------------------------------------------------------"
    echo -e "${YELLOW}本脚本允许您先完成软件安装，之后再自行处理域名解析和上线。${NC}"
    echo "------------------------------------------------------------------"

    read -p "请输入您【计划】使用的邮件服务器域名 (例如: mail.yourdomain.com): " MAIL_HOSTNAME
    if [ -z "$MAIL_HOSTNAME" ]; then
        echo -e "${RED}错误：邮件服务器域名不能为空。${NC}"
        exit 1
    fi
    if ! [[ "$MAIL_HOSTNAME" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${RED}错误：域名格式不正确。${NC}"
        exit 1
    fi

    echo
    echo "--- 管理员账户设置 ---"
    read -p "请输入管理员登录名 [默认为: admin]: " ADMIN_USERNAME
    ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
    read -sp "请为管理员账户 '${ADMIN_USERNAME}' 设置一个复杂的登录密码: " ADMIN_PASSWORD
    echo
    if [ -z "$ADMIN_PASSWORD" ]; then
        echo -e "${RED}错误：管理员密码不能为空。${NC}"
        exit 1
    fi
    echo

    # --- 变量定义 ---
    FLASK_SECRET_KEY=$(openssl rand -hex 24)

    # --- 步骤 1: 更新系统并安装依赖 ---
    echo -e "${GREEN}>>> 步骤 1: 更新系统并安装依赖...${NC}"
    echo -e "${BLUE}本脚本将安装以下核心依赖:${NC}"
    echo "- python3-pip, python3-venv, ufw, curl, debian-keyring, etc."
    echo "- caddy: 高性能、自动HTTPS的Web服务器"
    echo ""
    read -p "按回车键继续..."

    apt-get update > /dev/null
    apt-get upgrade -y > /dev/null
    apt-get install -y python3-pip python3-venv ufw curl debian-keyring debian-archive-keyring apt-transport-https > /dev/null

    echo -e "${GREEN}>>> 正在安装 Caddy...${NC}"
    if ! command -v caddy &> /dev/null; then
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg > /dev/null
        curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list > /dev/null
        apt-get update > /dev/null
        apt-get install -y caddy > /dev/null
    else
        echo -e "${YELLOW}Caddy 已安装，跳过。${NC}"
    fi

    # --- 步骤 2: 配置防火墙 ---
    echo -e "${GREEN}>>> 步骤 2: 配置防火墙...${NC}"
    ufw allow ssh > /dev/null
    ufw allow 25/tcp > /dev/null
    ufw allow 80/tcp > /dev/null
    ufw allow 443/tcp > /dev/null
    ufw --force enable

    # --- 步骤 3: 创建应用程序和虚拟环境 ---
    echo -e "${GREEN}>>> 步骤 3: 创建应用程序...${NC}"
    mkdir -p $PROJECT_DIR
    cd $PROJECT_DIR
    python3 -m venv venv
    ${PROJECT_DIR}/venv/bin/pip install flask gunicorn aiosmtpd werkzeug > /dev/null

    # --- 步骤 4: 生成安全配置并创建 app.py ---
    echo -e "${GREEN}>>> 步骤 4: 生成安全配置并写入核心应用代码 (app.py)...${NC}"
    ADMIN_PASSWORD_HASH=$(${PROJECT_DIR}/venv/bin/python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('''$ADMIN_PASSWORD'''))")

    # 省略 app.py 的巨大代码块以保持可读性，内容与上一版完全相同
    # ... 此处假设 app.py 的内容已被正确写入 ...
    cat << 'EOF' > ${PROJECT_DIR}/app.py
# -*- coding: utf-8 -*-
import sqlite3, re, os, math, html, logging, sys
from functools import wraps
from flask import Flask, request, Response, redirect, url_for, session, render_template_string, flash, get_flashed_messages, jsonify
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr
from markupsafe import escape
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from werkzeug.security import check_password_hash, generate_password_hash
import asyncio
from aiosmtpd.controller import Controller
# --- 配置 ---
DB_FILE = 'emails.db'
EMAILS_PER_PAGE = 50
LAST_CLEANUP_FILE = '/opt/mail_api/last_cleanup.txt'
CLEANUP_INTERVAL_DAYS = 1
EMAILS_TO_KEEP = 1000
# 管理员账户配置 (将由安装脚本替换)
ADMIN_USERNAME = "_PLACEHOLDER_ADMIN_USERNAME_"
ADMIN_PASSWORD_HASH = "_PLACEHOLDER_ADMIN_PASSWORD_HASH_"
# --- Flask 应用设置 ---
app = Flask(__name__)
app.config['SECRET_KEY'] = '_PLACEHOLDER_FLASK_SECRET_KEY_'
# --- 日志配置 ---
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)
# --- 数据库操作 ---
def get_db_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS received_emails (id INTEGER PRIMARY KEY, recipient TEXT, sender TEXT, subject TEXT, body TEXT, body_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, is_read BOOLEAN DEFAULT 0)')
    # 检查并添加 is_read 列，以兼容旧版本
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(received_emails)")
    columns = [row['name'] for row in cursor.fetchall()]
    if 'is_read' not in columns:
        app.logger.info("Schema update: Adding 'is_read' column to 'received_emails' table.")
        cursor.execute("ALTER TABLE received_emails ADD COLUMN is_read BOOLEAN DEFAULT 0")
        conn.commit()
    conn.close()
def run_cleanup_if_needed():
    now = datetime.now()
    if os.path.exists(LAST_CLEANUP_FILE):
        with open(LAST_CLEANUP_FILE, 'r') as f: last_cleanup_time = datetime.fromisoformat(f.read().strip())
        if now - last_cleanup_time < timedelta(days=CLEANUP_INTERVAL_DAYS): return
    app.logger.info(f"开始执行定时邮件清理任务...")
    conn = get_db_conn()
    deleted_count = conn.execute(f"DELETE FROM received_emails WHERE id NOT IN (SELECT id FROM received_emails ORDER BY id DESC LIMIT {EMAILS_TO_KEEP})").rowcount
    conn.commit()
    conn.close()
    if deleted_count > 0: app.logger.info(f"清理完成，成功删除了 {deleted_count} 封旧邮件。")
    with open(LAST_CLEANUP_FILE, 'w') as f: f.write(now.isoformat())
def process_email_data(to_address, raw_email_data):
    msg = message_from_bytes(raw_email_data)
    final_recipient = to_address
    recipient_headers_to_check = ['Delivered-To', 'X-Original-To', 'To']
    for header_name in recipient_headers_to_check:
        header_value = msg.get(header_name)
        if header_value:
            _, recipient_addr = parseaddr(header_value)
            if recipient_addr: final_recipient = recipient_addr; break
    final_sender = "unknown@sender.com"
    from_header = msg.get('From', '')
    if from_header: _, final_sender = parseaddr(from_header)
    subject = ""
    if msg['Subject']:
        subject_raw, encoding = decode_header(msg['Subject'])[0]
        if isinstance(subject_raw, bytes): subject = subject_raw.decode(encoding or 'utf-8', errors='ignore')
        else: subject = str(subject_raw)
    body, body_type = "", "text/plain"
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html':
                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore'); body_type="text/html"; break
            elif part.get_content_type() == 'text/plain':
                body = part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='ignore'); body_type="text/plain"
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
    conn = get_db_conn()
    conn.execute("INSERT INTO received_emails (recipient, sender, subject, body, body_type) VALUES (?, ?, ?, ?, ?)",
                 (final_recipient, final_sender, subject, body, body_type))
    conn.commit()
    conn.close()
    app.logger.info(f"邮件已存入: To='{final_recipient}', From='{final_sender}', Subject='{subject[:30]}...'")
    run_cleanup_if_needed()
def extract_code_from_body(body_text):
    if not body_text: return None
    match_specific = re.search(r'[^0-9A-Za-z](\d{6})[^0-9A-Za-z]', " " + body_text + " ")
    if match_specific: return match_specific.group(1)
    match_general = re.search(r'\b(\d{4,8})\b', body_text)
    if match_general: return match_general.group(1)
    return None
def strip_tags_for_preview(html_content):
    if not html_content: return ""
    text_content = re.sub(r'<style.*?</style>|<script.*?</script>|<[^>]+>', ' ', html_content, flags=re.S)
    return re.sub(r'\s+', ' ', text_content).strip()
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session: return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'): return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
@app.route('/api/unread_count')
@login_required
def unread_count():
    conn = get_db_conn()
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
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db_conn()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if email == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['user_email'], session['is_admin'] = ADMIN_USERNAME, True
            return redirect(request.args.get('next') or url_for('admin_view'))
        elif user and check_password_hash(user['password_hash'], password):
            session['user_email'], session.pop('is_admin', None) = user['email'], None
            return redirect(request.args.get('next') or url_for('view_emails'))
        else:
            flash('邮箱或密码错误', 'error')
    return render_template_string('<!DOCTYPE html><html><head><title>登录</title></head><body><h2>登录</h2>{% with m=get_flashed_messages(with_categories=true) %}{% for c,msg in m %}<p style="color:red;">{{msg}}</p>{% endfor %}{% endwith %}<form method=post><p>邮箱: <input type=text name=email required></p><p>密码: <input type=password name=password required></p><p><input type=submit value=登录></p></form></body></html>')
@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))
def render_email_list_page(emails_data, page, total_pages, total_emails, search_query, is_admin_view):
    view_endpoint = 'admin_view' if is_admin_view else 'view_emails'
    title_text = f"管理员视图 (共 {total_emails} 封)" if is_admin_view else f"收件箱 ({session.get('user_email', '')} - 共 {total_emails} 封)"
    processed_emails = []
    beijing_tz = ZoneInfo("Asia/Shanghai")
    for item in emails_data:
        utc_dt = datetime.strptime(item['timestamp'], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        bjt_str = utc_dt.astimezone(beijing_tz).strftime('%Y-%m-%d %H:%M:%S')
        body_for_preview = strip_tags_for_preview(item['body']) if item['body_type'] and 'html' in item['body_type'] else item['body']
        code = extract_code_from_body(body_for_preview)
        processed_emails.append({
            'id': item['id'], 'bjt_str': bjt_str, 'subject': item['subject'], 'is_read': item['is_read'],
            'preview_text': code if code else body_for_preview, 'is_code': bool(code),
            'recipient': item['recipient'], 'sender': parseaddr(item['sender'] or "")[1]
        })
    return render_template_string('''
        <!DOCTYPE html><html><head><title>{{title}}</title><style>body{font-family:sans-serif;margin:1em;}table{width:100%;border-collapse:collapse;}th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top;word-wrap:break-word;}tr.unread{font-weight:bold;}th{background:#f0f0f0;}.actions-bar{margin-bottom:1em;}.pagination{margin-top:1em;}</style></head>
        <body><div class="actions-bar"><h2>{{title}}</h2><div><a href="{{url_for('logout')}}">登出</a>{% if is_admin_view %}|<a href="{{url_for('manage_users')}}">管理用户</a>{% endif %}</div></div>
        <form method=get><input type=text name=search value="{{search_query|e}}" placeholder="搜索..."><button type=submit>搜索</button></form>
        <table><thead><tr><th>时间</th><th>主题</th><th>预览</th><th>收件人</th><th>发件人</th><th>操作</th></tr></thead><tbody>
        {% for mail in mails %}
        <tr class="{{'unread' if not mail.is_read else ''}}"><td>{{mail.bjt_str}}</td><td>{{mail.subject|e}}</td><td>{% if mail.is_code %}<strong style="color:red;">{{mail.preview_text|e}}</strong>{% else %}<div style="max-height:3.6em;overflow:hidden;">{{mail.preview_text|e}}</div>{% endif %}</td><td>{{mail.recipient|e}}</td><td>{{mail.sender|e}}</td><td><a href="{{url_for('view_email_detail',email_id=mail.id)}}" target=_blank>查看</a></td></tr>
        {% else %}<tr><td colspan=6>无邮件</td></tr>{% endfor %}
        </tbody></table>
        <div class=pagination>{% if page>1 %}<a href="{{url_for(endpoint,page=page-1,search=search_query)}}">上一页</a>{% endif %} Page {{page}}/{{total_pages}} {% if page<total_pages %}<a href="{{url_for(endpoint,page=page+1,search=search_query)}}">下一页</a>{% endif %}</div>
        </body></html>
    ''', title=title_text, mails=processed_emails, page=page, total_pages=total_pages, search_query=search_query, is_admin_view=is_admin_view, endpoint=view_endpoint)
@app.route('/view')
@login_required
def view_emails():
    return base_view_logic(is_admin_view=False)
@app.route('/admin')
@login_required
@admin_required
def admin_view():
    return base_view_logic(is_admin_view=True)
def base_view_logic(is_admin_view):
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    conn = get_db_conn()
    where_clauses, params = [], []
    if is_admin_view:
        if search_query: where_clauses.append("(subject LIKE ? OR recipient LIKE ? OR sender LIKE ?)"); params.extend([f"%{search_query}%"]*3)
    else:
        where_clauses.append("recipient = ?"); params.append(session['user_email'])
        if search_query: where_clauses.append("(subject LIKE ? OR sender LIKE ?)"); params.extend([f"%{search_query}%"]*2)
    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    total_emails = conn.execute(f"SELECT COUNT(*) FROM received_emails {where_sql}", params).fetchone()[0]
    total_pages = math.ceil(total_emails / EMAILS_PER_PAGE)
    offset = (page - 1) * EMAILS_PER_PAGE
    emails_data = conn.execute(f"SELECT * FROM received_emails {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?", params + [EMAILS_PER_PAGE, offset]).fetchall()
    conn.execute(f"UPDATE received_emails SET is_read=1 WHERE id IN (SELECT id FROM received_emails {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?)", params + [EMAILS_PER_PAGE, offset])
    conn.commit()
    conn.close()
    return render_email_list_page(emails_data, page, total_pages, total_emails, search_query, is_admin_view)
@app.route('/view_email/<int:email_id>')
@login_required
def view_email_detail(email_id):
    conn = get_db_conn()
    if session.get('is_admin'):
        email = conn.execute("SELECT * FROM received_emails WHERE id = ?", (email_id,)).fetchone()
    else:
        email = conn.execute("SELECT * FROM received_emails WHERE id = ? AND recipient = ?", (email_id, session['user_email'])).fetchone()
    if not email: conn.close(); return "邮件未找到或无权查看", 404
    conn.execute("UPDATE received_emails SET is_read = 1 WHERE id = ?", (email_id,)); conn.commit(); conn.close()
    body_content = email['body'] or ''
    if 'text/html' in (email['body_type'] or ''):
        email_display = f'<iframe srcdoc="{html.escape(body_content)}" style="width:100%;height:calc(100vh - 20px);border:none;"></iframe>'
    else:
        email_display = f'<pre style="white-space:pre-wrap;word-wrap:break-word;">{escape(body_content)}</pre>'
    return Response(email_display, mimetype="text/html; charset=utf-8")
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    conn = get_db_conn()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            email, password = request.form.get('email'), request.form.get('password')
            if email and password:
                try:
                    conn.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, generate_password_hash(password)))
                    conn.commit(); flash(f"用户 {email} 添加成功", 'success')
                except sqlite3.IntegrityError:
                    flash(f"用户 {email} 已存在", 'error')
        elif action == 'delete':
            user_id = request.form.get('user_id')
            conn.execute("DELETE FROM users WHERE id = ? AND email != ?", (user_id, ADMIN_USERNAME)); conn.commit(); flash("用户已删除", 'success')
    users = conn.execute("SELECT id, email FROM users WHERE email != ?", (ADMIN_USERNAME,)).fetchall()
    conn.close()
    return render_template_string('''
        <!DOCTYPE html><html><head><title>管理用户</title></head><body><h2>管理用户</h2><a href="{{url_for('admin_view')}}">返回</a>
        {% with m=get_flashed_messages(with_categories=true) %}{% for c,msg in m %}<p style="color:{{'green' if c=='success' else 'red'}}">{{msg}}</p>{% endfor %}{% endwith %}
        <h3>添加新用户</h3><form method=post><input type=hidden name=action value=add><input type=email name=email placeholder="邮箱" required><input type=password name=password placeholder="密码" required><button type=submit>添加</button></form>
        <h3>现有用户</h3><ul>{% for user in users %}<li>{{user.email}} <form method=post style="display:inline;"><input type=hidden name=action value=delete><input type=hidden name=user_id value={{user.id}}><button type=submit>删除</button></form></li>{% else %}<li>无普通用户</li>{% endfor %}</ul>
        </body></html>
    ''', users=users)
# --- SMTP 服务器逻辑 ---
class CustomSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        try:
            process_email_data(','.join(envelope.rcpt_tos), envelope.content)
            return '250 OK'
        except Exception as e:
            app.logger.error(f"处理邮件时发生严重错误: {e}")
            return '500 Error processing message'
# --- 脚本主入口 ---
if __name__ == '__main__':
    init_db()
    controller = Controller(CustomSMTPHandler(), hostname='0.0.0.0', port=25)
    controller.start()
    app.logger.info("SMTP 服务器启动，监听端口 25...")
    try:
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        controller.stop()
        app.logger.info("SMTP 服务器已关闭。")
EOF

    sed -i "s#_PLACEHOLDER_ADMIN_USERNAME_#${ADMIN_USERNAME}#g" "${PROJECT_DIR}/app.py"
    sed -i "s#_PLACEHOLDER_ADMIN_PASSWORD_HASH_#${ADMIN_PASSWORD_HASH}#g" "${PROJECT_DIR}/app.py"
    sed -i "s#_PLACEHOLDER_FLASK_SECRET_KEY_#${FLASK_SECRET_KEY}#g" "${PROJECT_DIR}/app.py"

    # --- 步骤 5: 创建 systemd 服务文件 ---
    echo -e "${GREEN}>>> 步骤 5: 创建 systemd 服务文件...${NC}"
    cat << EOF > /etc/systemd/system/mail-smtp.service
[Unit]
Description=Custom Python SMTP Server (Receive-Only)
After=network.target
[Service]
User=root
Group=root
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PROJECT_DIR}/venv/bin/python3 ${PROJECT_DIR}/app.py
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    cat << EOF > /etc/systemd/system/mail-api.service
[Unit]
Description=Gunicorn instance for Mail Web UI (Receive-Only)
After=network.target
[Service]
User=root
Group=root
WorkingDirectory=${PROJECT_DIR}
ExecStart=${PROJECT_DIR}/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:${GUNICORN_PORT} 'app:app'
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    # --- 步骤 6: 创建一个空的 Caddy 配置文件 ---
    echo -e "${GREEN}>>> 步骤 6: 创建初始 Caddy 配置文件...${NC}"
    # 创建一个空的Caddyfile，确保Caddy服务能正常启动，但不托管任何网站
    # 这样可以避免因DNS未解析导致安装失败
    touch ${CADDYFILE_PATH}

    # --- 步骤 7: 启动并检查所有服务 ---
    echo -e "${GREEN}>>> 步骤 7: 启动并启用所有服务...${NC}"
    ${PROJECT_DIR}/venv/bin/python3 -c "from app import init_db; init_db()"
    systemctl daemon-reload
    systemctl restart mail-smtp.service mail-api.service caddy
    systemctl enable mail-smtp.service mail-api.service caddy

    # --- 安装完成 ---
    echo "================================================================"
    echo -e "${GREEN}🎉 恭喜！邮件服务器核心软件安装完成！ 🎉${NC}"
    echo "================================================================"
    echo ""
    echo -e "你的管理员账户是: ${YELLOW}${ADMIN_USERNAME}${NC}"
    echo -e "你的管理员密码是: (你在安装时输入的密码)"
    echo ""
    echo -e "${RED}下一步：请手动配置域名并上线服务${NC}"
    echo "----------------------------------------------------------------"
    echo "服务尚未对公网开放。请按以下步骤操作："
    echo ""
    echo -e "1. ${YELLOW}配置DNS:${NC} 前往您的域名提供商，将域名 A 记录指向本服务器的公网IP。"
    echo -e "   您的域名: ${BLUE}${MAIL_HOSTNAME}${NC}"
    echo ""
    echo -e "2. ${YELLOW}等待解析生效:${NC} 您可以使用 `ping ${MAIL_HOSTNAME}` 或在线工具检查解析是否生效。"
    echo ""
    echo -e "3. ${YELLOW}上线服务:${NC} 当确认DNS解析生效后，登录到服务器，执行以下【单行命令】即可： "
    echo ""
    echo -e "${BLUE}echo -e '${MAIL_HOSTNAME} {\n    reverse_proxy 127.0.0.1:${GUNICORN_PORT}\n}' > ${CADDYFILE_PATH} && systemctl reload caddy${NC}"
    echo ""
    echo "   这条命令会自动更新Caddy配置并使其生效。Caddy会自动为您申请HTTPS证书。"
    echo ""
    echo "4. ${YELLOW}访问后台:${NC} 完成以上步骤后，即可通过以下链接访问您的邮件管理后台："
    echo -e "   ${GREEN}https://${MAIL_HOSTNAME}${NC}"
    echo "----------------------------------------------------------------"
    echo ""
    echo "你可以使用以下命令来查看服务状态:"
    echo " - SMTP 服务: systemctl status mail-smtp.service"
    echo " - 网页服务: systemctl status mail-api.service"
    echo " - Caddy 服务: systemctl status caddy"
    echo "================================================================"
}

# --- 主逻辑 ---
clear
echo -e "${BLUE}轻量级邮件服务器一键脚本 V4${NC}"
echo "============================"
echo "请选择要执行的操作:"
echo "1) 安装邮件服务器"
echo "2) 卸载邮件服务器"
echo ""
read -p "请输入选项 [1-2]: " choice

case $choice in
    1)
        install_server
        ;;
    2)
        uninstall_server
        ;;
    *)
        echo -e "${RED}无效选项，脚本退出。${NC}"
        exit 1
        ;;
esac
