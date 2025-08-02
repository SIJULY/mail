#!/bin/bash
# =================================================================================
# 轻量级邮件服务器一键安装脚本 (终极版)
#
# 作者: 小龙女她爸
# 日期: 2025-08-02
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

# --- 检查Root权限 ---
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}错误：此脚本必须以 root 身份运行。${NC}"
    exit 1
fi

# --- APT 锁处理函数 ---
handle_apt_locks() {
    echo -e "${YELLOW}>>> 正在检查并处理APT锁...${NC}"
    if ! command -v killall &> /dev/null; then
        echo "正在安装psmisc以使用killall命令..."
        apt-get -y install psmisc
    fi
    systemctl stop unattended-upgrades 2>/dev/null || true
    systemctl disable unattended-upgrades 2>/dev/null || true
    if pgrep -x "apt" > /dev/null || pgrep -x "apt-get" > /dev/null; then
        echo "检测到正在运行的APT进程，正在强制终止..."
        killall -9 apt apt-get || true
        sleep 2
    fi
    rm -f /var/lib/apt/lists/lock
    rm -f /var/cache/apt/archives/lock
    rm -f /var/lib/dpkg/lock*
    dpkg --configure -a
    echo -e "${GREEN}>>> APT环境已清理完毕。${NC}"
}


# --- 卸载功能 ---
uninstall_server() {
    echo -e "${YELLOW}警告：你确定要卸载邮件服务器核心服务吗？${NC}"
    echo "- 注意: 本脚本不会关闭您之前自定义的防火墙端口。"
    read -p "请输入 'yes' 以确认卸载: " CONFIRM_UNINSTALL
    if [ "$CONFIRM_UNINSTALL" != "yes" ]; then
        echo "卸载已取消。"
        exit 0
    fi
    echo -e "${BLUE}>>> 正在停止服务...${NC}"
    systemctl stop mail-smtp.service mail-api.service 2>/dev/null || true
    systemctl disable mail-smtp.service mail-api.service 2>/dev/null || true
    echo -e "${BLUE}>>> 正在删除服务文件...${NC}"
    rm -f /etc/systemd/system/mail-smtp.service
    rm -f /etc/systemd/system/mail-api.service
    echo -e "${BLUE}>>> 正在删除应用程序目录...${NC}"
    rm -rf ${PROJECT_DIR}
    systemctl daemon-reload
    echo -e "${GREEN}✅ 邮件服务器核心服务已成功卸载。${NC}"
    exit 0
}

# --- 安装功能 ---
install_server() {
    echo -e "${GREEN}欢迎使用轻量级邮件服务器一键安装脚本 (响应式UI终极版)！${NC}"
    
    # --- 收集用户信息 ---
    read -p "请输入您想为本系统命名的标题 (例如: 我的私人邮箱): " SYSTEM_TITLE
    SYSTEM_TITLE=${SYSTEM_TITLE:-"轻量级邮件服务器"}

    read -p "请输入您希望使用的网页后台端口 [默认为: 2099]: " WEB_PORT
    WEB_PORT=${WEB_PORT:-2099}
    if ! [[ "$WEB_PORT" =~ ^[0-9]+$ ]] || [ "$WEB_PORT" -lt 1 ] || [ "$WEB_PORT" -gt 65535 ]; then
        echo -e "${RED}错误：端口号无效，请输入1-65535之间的数字。${NC}"
        exit 1
    fi

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
    FLASK_SECRET_KEY=$(openssl rand -hex 24)
    
    # --- 自动获取公网IP ---
    echo -e "${BLUE}>>> 正在获取服务器公网IP...${NC}"
    PUBLIC_IP=$(curl -s icanhazip.com || echo "127.0.0.1")
    if [ -z "$PUBLIC_IP" ]; then
        echo -e "${RED}错误：无法自动获取公网IP地址。${NC}"
        exit 1
    fi
    echo -e "${GREEN}服务器公网IP为: ${PUBLIC_IP}${NC}"

    # --- 步骤 1: 清理APT环境并安装依赖 ---
    handle_apt_locks
    echo -e "${GREEN}>>> 步骤 1: 更新系统并安装依赖...${NC}"
    apt-get update
    apt-get -y upgrade
    apt-get -y install python3-pip python3-venv ufw curl
    
    # --- 步骤 2: 配置防火墙 ---
    echo -e "${GREEN}>>> 步骤 2: 配置防火墙...${NC}"
    ufw allow ssh
    ufw allow 25/tcp
    ufw allow ${WEB_PORT}/tcp
    ufw --force enable

    # --- 步骤 3: 创建应用程序 ---
    echo -e "${GREEN}>>> 步骤 3: 创建应用程序...${NC}"
    mkdir -p $PROJECT_DIR
    cd $PROJECT_DIR
    python3 -m venv venv
    ${PROJECT_DIR}/venv/bin/pip install flask gunicorn aiosmtpd werkzeug
    
    # --- 步骤 4: 写入核心应用代码 ---
    echo -e "${GREEN}>>> 步骤 4: 写入核心应用代码 (app.py)...${NC}"
    ADMIN_PASSWORD_HASH=$(${PROJECT_DIR}/venv/bin/python3 -c "from werkzeug.security import generate_password_hash; print(generate_password_hash('''$ADMIN_PASSWORD'''))")
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
DB_FILE = 'emails.db'
EMAILS_PER_PAGE = 50
LAST_CLEANUP_FILE = '/opt/mail_api/last_cleanup.txt'
CLEANUP_INTERVAL_DAYS = 1
EMAILS_TO_KEEP = 1000
ADMIN_USERNAME = "_PLACEHOLDER_ADMIN_USERNAME_"
ADMIN_PASSWORD_HASH = "_PLACEHOLDER_ADMIN_PASSWORD_HASH_"
SYSTEM_TITLE = "_PLACEHOLDER_SYSTEM_TITLE_"
SPECIAL_VIEW_TOKEN = "2088"
app = Flask(__name__)
app.config['SECRET_KEY'] = '_PLACEHOLDER_FLASK_SECRET_KEY_'
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)
def get_db_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn
def init_db():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute('CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)')
    c.execute('CREATE TABLE IF NOT EXISTS received_emails (id INTEGER PRIMARY KEY, recipient TEXT, sender TEXT, subject TEXT, body TEXT, body_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, is_read BOOLEAN DEFAULT 0)')
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
            session['user_email'] = user['email']
            session.pop('is_admin', None)
            return redirect(request.args.get('next') or url_for('view_emails'))
        else:
            flash('邮箱或密码错误', 'error')
    return render_template_string('''
        <!DOCTYPE html><html><head><title>登录 - {{ SYSTEM_TITLE }}</title><style>
        body{display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;margin:0;background-color:#f4f4f4;}
        .main-title{font-size:2em;color:#333;margin-bottom:1em;font-weight:bold;}
        .login-box{padding:2em;border:1px solid #ddd;border-radius:8px;background-color:#fff;box-shadow:0 4px 6px rgba(0,0,0,0.1);width:300px;}
        h2 {text-align:center;color:#333;margin-top:0;margin-bottom:1.5em;}
        form {display:flex;flex-direction:column;}
        label {margin-bottom:0.5em;color:#555;}
        input[type="text"], input[type="password"] {padding:0.8em;margin-bottom:1em;border:1px solid #ccc;border-radius:4px;font-size:1em;}
        input[type="submit"] {padding:0.8em;border:none;border-radius:4px;background-color:#007bff;color:white;cursor:pointer;font-size:1em;transition:background-color 0.2s;}
        input[type="submit"]:hover {background-color:#0056b3;}
        .error{color:red;text-align:center;margin-bottom:1em;}
        {% with m=get_flashed_messages(with_categories=true) %}{% for c,msg in m %}<p class="error">{{msg}}</p>{% endfor %}{% endwith %}
        </style></head><body>
        <h1 class="main-title">{{ SYSTEM_TITLE }}</h1>
        <div class="login-box"><h2>邮箱登录</h2>
        <form method="post">
        <label for="email">邮箱地址 (或管理员账户):</label><input type="text" name="email" required>
        <label for="password">密码:</label><input type="password" name="password" required>
        <input type="submit" value="登录"></form></div></body></html>
    ''', SYSTEM_TITLE=SYSTEM_TITLE)
@app.route('/logout')
def logout():
    session.clear(); return redirect(url_for('login'))
def render_email_list_page(emails_data, page, total_pages, total_emails, search_query, is_admin_view, token_view_context=None):
    if token_view_context:
        endpoint = 'view_mail_by_token'
        title_text = f"收件箱 ({token_view_context['mail']}) - 共 {total_emails} 封"
    else:
        endpoint = 'admin_view' if is_admin_view else 'view_emails'
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
        <!DOCTYPE html><html><head><title>{{title}} - {{SYSTEM_TITLE}}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: #f8f9fa; font-size: 14px; }
            .container { max-width: 95%; margin: 0 auto; padding: 1em; }
            table { border-collapse: collapse; width: 100%; box-shadow: 0 2px 4px rgba(0,0,0,0.05); background-color: #fff; margin-top: 1.5em; border: 1px solid #dee2e6; }
            th, td { padding: 12px 15px; vertical-align: middle; border-bottom: 1px solid #dee2e6; border-right: 1px solid #dee2e6; word-break: break-all; }
            th:last-child, td:last-child { border-right: none; }
            tr.unread { font-weight: bold; background-color: #fffaf0; }
            tr:hover { background-color: #f1f3f5; }
            th { background-color: #4CAF50; color: white; text-transform: uppercase; font-size: 0.85em; letter-spacing: 0.05em; text-align: center; }
            .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5em; flex-wrap: wrap; gap: 1em;}
            .top-bar h2 { margin: 0; color: #333; font-size: 1.5em; }
            .top-bar .user-actions { display: flex; gap: 10px; }
            .btn { text-decoration: none; display: inline-block; padding: 8px 15px; border: 1px solid transparent; border-radius: 4px; color: white; cursor: pointer; font-size: 0.9em; transition: background-color 0.2s; white-space: nowrap; }
            .btn-primary { background-color: #007bff; border-color: #007bff; }
            .btn-primary:hover { background-color: #0056b3; }
            .btn-secondary { background-color: #6c757d; border-color: #6c757d; }
            .btn-danger { background-color: #dc3545; border-color: #dc3545; }
            .controls { display: flex; justify-content: space-between; align-items: center; padding-bottom: 1.5em; border-bottom: 1px solid #dee2e6; flex-wrap: wrap; gap: 1em;}
            .controls .bulk-actions { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
            .search-form { display: flex; gap: 5px; }
            .search-form input[type="text"] { padding: 8px; border: 1px solid #ccc; border-radius: 4px; min-width: 200px;}
            .pagination { margin-top: 1.5em; text-align: center; }
            .pagination a { color: #007bff; padding: 8px 12px; text-decoration: none; border: 1px solid #ddd; margin: 0 4px; border-radius: 4px; }
            .pagination a:hover { background-color: #e9ecef; }
            .preview-code { color: #e83e8c; font-weight: bold; font-family: monospace; }
            a.view-link { color: #007bff; text-decoration: none; }
            a.view-link:hover { text-decoration: underline; }
            td { text-align: left; }
        </style></head><body>
        <div class="container">
            <div class="top-bar">
                <h2>{{title}}</h2>
                <div class="user-actions">
                    {% if not token_view_context and is_admin_view %}
                        <a href="{{url_for('manage_users')}}" class="btn btn-primary">管理用户</a>
                    {% endif %}
                    {% if not token_view_context %}
                         <a href="{{url_for('logout')}}" class="btn btn-danger">登出</a>
                    {% endif %}
                </div>
            </div>
            
            <div class="controls">
                <div class="bulk-actions">
                    {% if is_admin_view %}
                        <button onclick="window.location.reload();" class="btn btn-secondary">刷新</button>
                        <button type="submit" form="delete-selected-form" class="btn btn-secondary">删除选中</button>
                        <form id="delete-all-form" method="POST" action="{{url_for('delete_all_emails')}}" style="display: inline;" onsubmit="return confirm('您确定要删除所有邮件吗？这将无法恢复！');">
                           <button type="submit" class="btn btn-danger">删除所有</button>
                        </form>
                    {% endif %}
                </div>
                <form method="get" class="search-form" action="{{ url_for(endpoint) }}">
                    <input type="text" name="search" value="{{search_query|e}}" placeholder="搜索...">
                    {% if token_view_context %}
                    <input type="hidden" name="token" value="{{ token_view_context.token }}">
                    <input type="hidden" name="mail" value="{{ token_view_context.mail }}">
                    {% endif %}
                    <button type="submit" class="btn btn-primary">搜索</button>
                </form>
            </div>
            
            <form id="delete-selected-form" method="POST" action="{{url_for('delete_selected_emails')}}">
            <table>
                <thead><tr>
                    <th style="width: 3%; min-width: 40px;"><input type="checkbox" onclick="toggleAllCheckboxes(this);" {% if not is_admin_view %}style="display:none;"{% endif %}></th>
                    <th style="width: 15%; min-width: 160px;">时间 (北京)</th>
                    <th style="width: 20%; min-width: 150px;">主题</th>
                    <th style="width: 35%; min-width: 200px;">内容预览</th>
                    <th style="width: 13%; min-width: 120px;">收件人</th>
                    <th style="width: 14%; min-width: 120px;">发件人</th>
                </tr></thead>
                <tbody>
                {% for mail in mails %}
                <tr class="{{'unread' if not mail.is_read else ''}}">
                    <td style="text-align: center;"><input type="checkbox" name="selected_ids" value="{{mail.id}}" {% if not is_admin_view %}style="display:none;"{% endif %}></td>
                    <td>{{mail.bjt_str}}</td>
                    <td>{{mail.subject|e}} <a href="{{ url_for('view_email_token_detail' if token_view_context else 'view_email_detail', email_id=mail.id, token=token_view_context.token if token_view_context) }}" target="_blank" class="view-link" title="新窗口打开">↳</a></td>
                    <td>
                        {% if mail.is_code %}
                            <span class="preview-code">{{mail.preview_text|e}}</span>
                        {% else %}
                            {{mail.preview_text|e}}
                        {% endif %}
                    </td>
                    <td>{{mail.recipient|e}}</td>
                    <td>{{mail.sender|e}}</td>
                </tr>
                {% else %}<tr><td colspan="6" style="text-align:center;padding:2em;">无邮件</td></tr>{% endfor %}
                </tbody>
            </table>
            </form>

            <div class="pagination">
                {% if page > 1 %}
                    {% set pagination_params = {'page': page-1, 'search': search_query} %}
                    {% if token_view_context %}{% set _ = pagination_params.update({'token': token_view_context.token, 'mail': token_view_context.mail}) %}{% endif %}
                    <a href="{{url_for(endpoint, **pagination_params)}}">&laquo; 上一页</a>
                {% endif %}
                <span> Page {{page}} / {{total_pages}} </span>
                {% if page < total_pages %}
                    {% set pagination_params = {'page': page + 1, 'search': search_query} %}
                    {% if token_view_context %}{% set _ = pagination_params.update({'token': token_view_context.token, 'mail': token_view_context.mail}) %}{% endif %}
                    <a href="{{url_for(endpoint, **pagination_params)}}">下一页 &raquo;</a>
                {% endif %}
            </div>
        </div>
        <script>
            function toggleAllCheckboxes(source) {
                var form = document.getElementById('delete-selected-form');
                var checkboxes = form.getElementsByName('selected_ids');
                for(var i=0; i < checkboxes.length; i++) {
                    checkboxes[i].checked = source.checked;
                }
            }
        </script>
        </body></html>
    ''', title=title_text, mails=processed_emails, page=page, total_pages=total_pages, search_query=search_query, is_admin_view=is_admin_view, endpoint=endpoint, SYSTEM_TITLE=SYSTEM_TITLE, token_view_context=token_view_context)
@app.route('/view')
@login_required
def view_emails():
    return base_view_logic(is_admin_view=False)
@app.route('/admin')
@login_required
@admin_required
def admin_view():
    return base_view_logic(is_admin_view=True)
def base_view_logic(is_admin_view, mark_as_read=True, recipient_override=None):
    search_query = request.args.get('search', '').strip()
    page = request.args.get('page', 1, type=int)
    conn = get_db_conn()
    where_clauses, params = [], []
    token_context = None

    if recipient_override:
        is_admin_view = False
        where_clauses.append("recipient = ?"); params.append(recipient_override)
        if search_query: where_clauses.append("(subject LIKE ? OR sender LIKE ?)"); params.extend([f"%{search_query}%"]*2)
        token_context = {'token': request.args.get('token'), 'mail': recipient_override}
    elif is_admin_view:
        if search_query: where_clauses.append("(subject LIKE ? OR recipient LIKE ? OR sender LIKE ?)"); params.extend([f"%{search_query}%"]*3)
    else:
        where_clauses.append("recipient = ?"); params.append(session['user_email'])
        if search_query: where_clauses.append("(subject LIKE ? OR sender LIKE ?)"); params.extend([f"%{search_query}%"]*2)

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    total_emails = conn.execute(f"SELECT COUNT(*) FROM received_emails {where_sql}", params).fetchone()[0]
    total_pages = math.ceil(total_emails / EMAILS_PER_PAGE) if total_emails > 0 else 1
    offset = (page - 1) * EMAILS_PER_PAGE
    emails_data = conn.execute(f"SELECT * FROM received_emails {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?", params + [EMAILS_PER_PAGE, offset]).fetchall()
    
    if mark_as_read:
        ids_to_mark = [str(e['id']) for e in emails_data if not e['is_read']]
        if ids_to_mark:
            conn.execute(f"UPDATE received_emails SET is_read=1 WHERE id IN ({','.join(ids_to_mark)})")
            conn.commit()

    conn.close()
    return render_email_list_page(emails_data, page, total_pages, total_emails, search_query, is_admin_view, token_view_context=token_context)
@app.route('/Mail')
def view_mail_by_token():
    token = request.args.get('token')
    recipient_mail = request.args.get('mail')
    if token != SPECIAL_VIEW_TOKEN:
        return "无效的Token", 403
    if not recipient_mail:
        return "必须提供 'mail' 参数", 400
    return base_view_logic(is_admin_view=False, mark_as_read=False, recipient_override=recipient_mail)
@app.route('/delete_selected_emails', methods=['POST'])
@login_required
@admin_required
def delete_selected_emails():
    selected_ids = request.form.getlist('selected_ids')
    if selected_ids:
        conn = get_db_conn()
        placeholders = ','.join('?' for _ in selected_ids)
        query = f"DELETE FROM received_emails WHERE id IN ({placeholders})"
        conn.execute(query, selected_ids)
        conn.commit()
        conn.close()
    return redirect(request.referrer or url_for('admin_view'))

@app.route('/delete_all_emails', methods=['POST'])
@login_required
@admin_required
def delete_all_emails():
    conn = get_db_conn()
    conn.execute("DELETE FROM received_emails")
    conn.commit()
    conn.close()
    return redirect(url_for('admin_view'))
@app.route('/view_email/<int:email_id>')
@login_required
def view_email_detail(email_id):
    conn = get_db_conn()
    if session.get('is_admin'):
        email = conn.execute("SELECT * FROM received_emails WHERE id = ?", (email_id,)).fetchone()
    else:
        email = conn.execute("SELECT * FROM received_emails WHERE id = ? AND recipient = ?", (email_id, session['user_email'])).fetchone()
    if not email: conn.close(); return "邮件未找到或无权查看", 404
    if not email['is_read']:
        conn.execute("UPDATE received_emails SET is_read = 1 WHERE id = ?", (email_id,)); conn.commit()
    conn.close()
    
    body_content = email['body'] or ''
    if 'text/html' in (email['body_type'] or ''):
        email_display = f'<iframe srcdoc="{html.escape(body_content)}" style="width:100%;height:calc(100vh - 20px);border:none;"></iframe>'
    else:
        email_display = f'<pre style="white-space:pre-wrap;word-wrap:break-word;">{escape(body_content)}</pre>'
    return Response(email_display, mimetype="text/html; charset=utf-8")
@app.route('/view_email_token/<int:email_id>')
def view_email_token_detail(email_id):
    token = request.args.get('token')
    if token != SPECIAL_VIEW_TOKEN:
        return "无效的Token", 403
    conn = get_db_conn()
    email = conn.execute("SELECT * FROM received_emails WHERE id = ?", (email_id,)).fetchone()
    conn.close()
    if not email: return "邮件未找到", 404
    
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
        <!DOCTYPE html><html><head><title>管理用户 - {{SYSTEM_TITLE}}</title><style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; background-color: #f8f9fa; display: flex; justify-content: center; padding-top: 4em; }
            .container { width: 100%; max-width: 800px; background: #fff; padding: 2em; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h2, h3 { color: #333; }
            a { color: #007bff; text-decoration: none; }
            a:hover { text-decoration: underline; }
            form { margin-bottom: 2em; padding: 1.5em; border: 1px solid #ddd; border-radius: 5px; background: #fdfdfd; }
            form.inline-form { display: inline; border: none; padding: 0; margin: 0; background: none; }
            input[type="email"], input[type="password"] { width: calc(100% - 22px); padding: 10px; margin-bottom: 10px; border: 1px solid #ccc; border-radius: 4px; }
            button { padding: 10px 15px; border: none; border-radius: 4px; color: white; cursor: pointer; transition: background-color 0.2s; }
            button.add { background-color: #28a745; }
            button.add:hover { background-color: #218838; }
            button.delete { background-color: #dc3545; }
            button.delete:hover { background-color: #c82333; }
            ul { list-style: none; padding: 0; }
            li { background: #f8f9fa; padding: 15px; border-bottom: 1px solid #ddd; display: flex; justify-content: space-between; align-items: center; }
            li:last-child { border-bottom: none; }
            .flash-success { color: green; font-weight: bold; margin-bottom: 1em; }
            .flash-error { color: red; font-weight: bold; margin-bottom: 1em; }
            .nav-link { font-size: 1.2em; }
        </style></head><body><div class="container">
        <h2><a href="{{url_for('admin_view')}}" class="nav-link">&larr; 返回收件箱</a> | 管理用户</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
                <p class="flash-{{ category }}">{{ message }}</p>
            {% endfor %}
        {% endwith %}
        <h3>添加新用户</h3>
        <form method="post">
            <input type="hidden" name="action" value="add">
            <input type="email" name="email" placeholder="新用户邮箱地址" required>
            <input type="password" name="password" placeholder="新用户密码" required>
            <button type="submit" class="add">添加用户</button>
        </form>
        <h3>现有用户</h3>
        <ul>
            {% for user in users %}
            <li>
                <span>{{user.email}}</span>
                <form method="post" class="inline-form">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="user_id" value="{{user.id}}">
                    <button type="submit" class="delete">删除</button>
                </form>
            </li>
            {% else %}
                <li>无普通用户</li>
            {% endfor %}
        </ul>
        </div></body></html>
    ''', users=users, SYSTEM_TITLE=SYSTEM_TITLE)
class CustomSMTPHandler:
    async def handle_DATA(self, server, session, envelope):
        try:
            process_email_data(','.join(envelope.rcpt_tos), envelope.content)
            return '250 OK'
        except Exception as e:
            app.logger.error(f"处理邮件时发生严重错误: {e}")
            return '500 Error processing message'
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
    sed -i "s#_PLACEHOLDER_SYSTEM_TITLE_#${SYSTEM_TITLE}#g" "${PROJECT_DIR}/app.py"

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
ExecStart=${PROJECT_DIR}/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:${WEB_PORT} 'app:app'
Restart=always
[Install]
WantedBy=multi-user.target
EOF

    # --- 步骤 6: 启动核心服务 ---
    echo -e "${GREEN}>>> 步骤 6: 启动核心服务...${NC}"
    ${PROJECT_DIR}/venv/bin/python3 -c "from app import init_db; init_db()"
    systemctl daemon-reload
    systemctl restart mail-smtp.service mail-api.service
    systemctl enable mail-smtp.service mail-api.service

    # --- 安装完成 ---
    echo "================================================================"
    echo -e "${GREEN}🎉 恭喜！邮件服务器核心服务安装完成！ 🎉${NC}"
    echo "================================================================"
    echo ""
    echo -e "${RED}重要安全警告：${NC}"
    echo -e "您的Web后台正通过 ${YELLOW}HTTP协议${NC} 暴露在公网上，这意味着您的登录密码将以 ${RED}明文传输${NC}。"
    echo "此模式仅建议用于临时测试，请尽快配置域名和反向代理以启用HTTPS安全连接。"
    echo "----------------------------------------------------------------"
    echo -e "您的网页版登录地址是："
    echo -e "${YELLOW}http://${PUBLIC_IP}:${WEB_PORT}${NC}"
    echo ""
    echo -e "邮件查看地址格式为 (注意替换{}中的内容):"
    echo -e "${YELLOW}http://${PUBLIC_IP}:${WEB_PORT}/Mail?token=2088&mail={收件人邮箱地址}${NC}"
    echo "================================================================"
}

# --- 主逻辑 ---
clear
echo -e "${BLUE}轻量级邮件服务器一键脚本${NC}"
echo "=============================================================="
echo "请选择要执行的操作:"
echo "1) 安装邮件服务器核心服务"
echo "2) 卸载邮件服务器核心服务"
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
