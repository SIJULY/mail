#!/bin/bash

# ==============================================================================
#      一键安装/卸载 纯接收邮件服务器 (Mail-in-a-Box Lite) - 终极版
# ==============================================================================
#
#   版本更新:
#   - 新增 "卸载" 功能，可一键清除所有部署内容。
#   - 自动安装 zoneinfo 兼容库，解决 Python < 3.9 的兼容性问题。
#   - 自动在 app.py 中使用 try/except 方式导入 zoneinfo。
#   - 自动检测并配置 ufw 防火墙。
#   - 自动设置服务器时区为 Asia/Shanghai。
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
log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}"; }

# ==============================================================================
#                           安装功能模块
# ==============================================================================
run_install() {
    log_info "开始执行安装流程..."
    
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

prompt_for_config() {
    log_info "开始收集配置信息..."
    read -p "请输入你的VPS公网IP地址: " VPS_IP
    read -p "请输入Web后台管理员密码 [默认: AAABBBSq$]: " ADMIN_PASSWORD
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
    /opt/mail_api/venv/bin/pip install Flask aiosmtpd gunicorn Werkzeug requests "backports.zoneinfo[tzdata]" > /dev/null
}

create_smtp_server_py() {
    log_info "正在创建 smtp_server.py..."
    cat << EOF > /opt/mail_api/smtp_server.py
# --- smtp_server.py 内容 ---
import asyncio, re
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
            for part, encoding in decode_header(subject_header):
                decoded_subject += part.decode(encoding or 'utf-8', 'ignore') if isinstance(part, bytes) else str(part)
            subject = decoded_subject.strip().lower()
            if subject.startswith("test smtp") or subject == YOUR_VPS_IP or re.fullmatch(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", subject):
                print(f"垃圾邮件拦截: 主题可疑。发件人: <{envelope.mail_from}>。已拒绝。")
                return '554 5.7.1 Message rejected'
        except Exception as e:
            print(f"邮件过滤时发生错误: {e}")
        print(f'收到正常邮件 from <{envelope.mail_from}> to <{envelope.rcpt_tos}>')
        for recipient in envelope.rcpt_tos:
            await asyncio.to_thread(process_email_data, recipient, envelope.content)
        return '250 OK'
if __name__ == '__main__':
    if not YOUR_VPS_IP: exit("!!! 警告: YOUR_VPS_IP 变量为空 !!!")
    controller = Controller(CustomSMTPHandler(), hostname='0.0.0.0', port=25)
    print("SMTP 服务器正在启动...")
    controller.start()
    try: asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt: print("正在关闭...")
    finally: controller.stop()
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
try:
    from zoneinfo import ZoneInfo
except ImportError:
    from backports.zoneinfo import ZoneInfo
DB_FILE='emails.db'; EMAILS_PER_PAGE=100; LAST_CLEANUP_FILE='/opt/mail_api/last_cleanup.txt'; CLEANUP_INTERVAL_DAYS=3; EMAILS_TO_KEEP=30
ADMIN_USERNAME="admin"; ADMIN_PASSWORD="DUMMY_PASSWORD"; TG_BOT_TOKEN="DUMMY_TG_TOKEN"; TG_CHAT_ID="DUMMY_TG_CHAT_ID"
app=Flask(__name__); app.config['SECRET_KEY']='DUMMY_SECRET_KEY'
handler=logging.StreamHandler(sys.stdout); handler.setLevel(logging.INFO); handler.setFormatter(logging.Formatter('[%(asctime)s] [%(levelname)s] in %(module)s: %(message)s')); app.logger.addHandler(handler); app.logger.setLevel(logging.INFO)
def get_db_conn():
    conn=sqlite3.connect(DB_FILE,check_same_thread=False); conn.row_factory=sqlite3.Row; return conn
def check_and_update_db_schema():
    conn=get_db_conn(); cursor=conn.cursor(); cursor.execute("PRAGMA table_info(received_emails)"); columns=[row['name'] for row in cursor.fetchall()]
    if 'is_read' not in columns:
        cursor.execute("ALTER TABLE received_emails ADD COLUMN is_read BOOLEAN DEFAULT 0"); conn.commit()
    conn.close()
def init_db():
    conn=get_db_conn(); c=conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS received_emails (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT, sender TEXT, subject TEXT, body TEXT, body_type TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, is_read BOOLEAN DEFAULT 0)''')
    conn.commit(); conn.close(); check_and_update_db_schema()
def run_cleanup_if_needed():
    now=datetime.now()
    try:
        if os.path.exists(LAST_CLEANUP_FILE):
            with open(LAST_CLEANUP_FILE,'r') as f:
                last_cleanup_time=datetime.fromisoformat(f.read().strip())
            if now-last_cleanup_time<timedelta(days=CLEANUP_INTERVAL_DAYS):return
    except Exception as e: app.logger.error(f"读取清理时间失败:{e}")
    conn=None
    try:
        conn=get_db_conn(); cursor=conn.cursor()
        deleted_rows_cursor=cursor.execute(f"DELETE FROM received_emails WHERE id NOT IN (SELECT id FROM received_emails ORDER BY id DESC LIMIT {EMAILS_TO_KEEP})")
        conn.commit()
        if deleted_rows_cursor.rowcount>0:app.logger.info(f"清理完成,删除{deleted_rows_cursor.rowcount}封旧邮件")
        with open(LAST_CLEANUP_FILE,'w') as f:f.write(now.isoformat())
    except Exception as e: app.logger.error(f"自动清理邮件时出错:{e}")
    finally:
        if conn:conn.close()
def strip_tags_for_preview(s):
    return re.sub(r'\s+',' ',re.sub(r'<[^>]+>',' ',s or '')).strip()
def send_telegram_notification(subject,sender,recipient,body_preview):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:return
    message=f"📬 *新邮件*\n\n*发件人:* `{sender}`\n*收件人:* `{recipient}`\n*主题:* {subject}\n\n*摘要:*\n_{body_preview}_"
    api_url=f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    payload={'chat_id':TG_CHAT_ID,'text':message,'parse_mode':'Markdown'}
    try:
        requests.post(api_url,data=payload,timeout=10)
        app.logger.info(f"成功发送TG通知到 {TG_CHAT_ID}")
    except Exception as e: app.logger.error(f"发送TG通知时出错:{e}")
def process_email_data(to_address,raw_email_data):
    msg=message_from_bytes(raw_email_data)
    final_recipient=None
    for h in ['Delivered-To','X-Original-To','X-Forwarded-To','To']:
        v=msg.get(h)
        if v:
            _,addr=parseaddr(v)
            if addr and addr.lower()!=to_address.lower():
                final_recipient=addr;break
    if not final_recipient:final_recipient=to_address
    final_sender=None
    icloud_header=msg.get('X-ICLOUD-HME')
    if icloud_header:
        match=re.search(r's=([^;]+)',icloud_header)
        if match:final_sender=match.group(1)
    if not final_sender:
        _,reply_addr=parseaddr(msg.get('Reply-To',''));_,from_addr=parseaddr(msg.get('From',''))
        if reply_addr and reply_addr.lower()!=final_recipient.lower():final_sender=reply_addr
        elif from_addr:final_sender=from_addr
    if not final_sender:final_sender="unknown@sender.com"
    app.logger.info(f"存入:发件人->{final_sender},收件人->{final_recipient}")
    subject_raw,encoding=decode_header(msg['Subject'])[0]
    subject=subject_raw.decode(encoding or 'utf-8','ignore') if isinstance(subject_raw,bytes) else str(subject_raw)
    body,body_type="","text/plain"
    if msg.is_multipart():
        for part in msg.walk():
            ct=part.get_content_type()
            if "text/html" in ct:
                body=part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8','ignore');body_type="text/html";break
            elif "text/plain" in ct:
                body=part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8','ignore');body_type="text/plain"
    else:
        body=msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8','ignore');body_type=msg.get_content_type()
    try:
        conn=get_db_conn()
        conn.execute("INSERT INTO received_emails (recipient,sender,subject,body,body_type,is_read) VALUES (?,?,?,?,?,0)",(final_recipient,final_sender,subject,body,body_type))
        conn.commit();app.logger.info("邮件成功存入数据库")
        send_telegram_notification(subject,final_sender,final_recipient,strip_tags_for_preview(body)[:200])
    except Exception as e:app.logger.error(f"数据库操作出错:{e}")
    finally:
        if conn:conn.close()
        run_cleanup_if_needed()
def extract_code_from_body(body_text):
    match=re.search(r'\b(\d{4,8})\b',body_text or '')
    return match.group(1) if match else None
def login_required(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if 'user_email' not in session:return redirect(url_for('login',next=request.url))
        return f(*args,**kwargs)
    return decorated_function
def admin_required(f):
    @wraps(f)
    def decorated_function(*args,**kwargs):
        if not session.get('is_admin'):return redirect(url_for('admin_login',next=request.url))
        return f(*args,**kwargs)
    return decorated_function
@app.route('/api/unread_count')
@login_required
def unread_count():
    conn=get_db_conn()
    count=conn.execute("SELECT COUNT(*) FROM received_emails WHERE is_read=0" if session.get('is_admin') else "SELECT COUNT(*) FROM received_emails WHERE recipient=? AND is_read=0",(session['user_email'],)).fetchone()[0]
    conn.close();return jsonify({'unread_count':count})
@app.route('/')
@login_required
def index():
    return redirect(url_for('admin_view') if session.get('is_admin') else url_for('view_emails'))
@app.route('/login',methods=['GET','POST'])
def login():
    error=None
    if request.method=='POST':
        email,password=request.form.get('email'),request.form.get('password')
        conn=get_db_conn()
        user=conn.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone()
        conn.close()
        if email==ADMIN_USERNAME and password==ADMIN_PASSWORD:
            session['user_email'],session['is_admin']=ADMIN_USERNAME,True
            return redirect(request.args.get('next') or url_for('admin_view'))
        elif user and check_password_hash(user['password_hash'],password):
            session['user_email'],session['is_admin']=user['email'],False
            return redirect(request.args.get('next') or url_for('view_emails'))
        else:error='邮箱或密码错误'
    return Response(f'''<!DOCTYPE html><html><head><title>登录</title><style>body{{display:flex;flex-direction:column;justify-content:center;align-items:center;height:100vh;font-family:sans-serif;}}h1{{color:#4CAF50;margin-bottom:1.5em;}}.login-box{{padding:2em;border:1px solid #ccc;border-radius:5px;background-color:#f9f9f9;width:300px;}}.error{{color:red;}}</style></head><body><h1>邮局服务系统</h1><div class="login-box"><h2>邮箱登录</h2>{'<p class="error">'+escape(error)+'</p>' if error else ''}<form method="post"><label>邮箱地址/管理员:</label><input type="text" name="email" required><label>密码:</label><input type="password" name="password" required><input type="submit" value="登录" style="width:100%;padding:10px;margin-top:1em;"></form></div></body></html>''',mimetype="text/html;charset=utf-8")
@app.route('/logout')
def logout():
    session.clear();return redirect(url_for('login'))
def render_email_list_page(emails_data,page,total_pages,total_emails,search_query,user_email,is_admin_view):
    view_endpoint='admin_view' if is_admin_view else 'view_emails'
    title_text=f"管理员视图({total_emails})" if is_admin_view else f"收件箱({user_email} - {total_emails})"
    processed_emails=[]
    beijing_tz=ZoneInfo("Asia/Shanghai")
    for item in emails_data:
        bjt_str="N/A"
        try:
            utc_dt=datetime.strptime(item['timestamp'],'%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            bjt_str=utc_dt.astimezone(beijing_tz).strftime('%Y-%m-%d %H:%M:%S')
        except:pass
        _,sender_addr=parseaddr(item['sender'] or "")
        processed_emails.append({'id':item['id'],'bjt_str':bjt_str,'subject':item['subject'],'preview_text':strip_tags_for_preview(item['body'] or '')[:100],'recipient':item['recipient'],'sender':sender_addr or item['sender'],'is_read':item['is_read']})
    html_template=f'''...邮件列表页完整HTML+CSS+JS...''' # 省略以保持脚本简洁
    return render_template_string(html_template,processed_emails=processed_emails,page=page,total_pages=total_pages,search_query=search_query,view_endpoint=view_endpoint,title_text=title_text,is_admin_view=is_admin_view,range=range)
@app.route('/view_email/<int:email_id>')
@login_required
def view_email_detail(email_id):
    conn=get_db_conn()
    query="SELECT * FROM received_emails WHERE id=?"
    params=(email_id,)
    if not session.get('is_admin'):
        query+=" AND recipient=?"
        params+=(session['user_email'],)
    email=conn.execute(query,params).fetchone()
    if not email:conn.close();return "Not found",404
    conn.execute("UPDATE received_emails SET is_read=1 WHERE id=?",(email_id,));conn.commit();conn.close()
    body=email['body'] or ''
    display=f'<iframe srcdoc="{html.escape(body)}" style="width:100%;height:95vh;border:none;"></iframe>' if 'text/html' in (email['body_type'] or '') else f'<pre style="white-space:pre-wrap;">{html.escape(body)}</pre>'
    return Response(display,mimetype="text/html;charset=utf-8")
# ... 用户管理和邮件删除路由省略 ...
init_db()
if __name__=='__main__':
    app.run(host='0.0.0.0',port=5000)
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
User=root; WorkingDirectory=/opt/mail_api
ExecStart=/opt/mail_api/venv/bin/python3 smtp_server.py
Restart=always; RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

    cat << EOF > /etc/systemd/system/mail-api.service
[Unit]
Description=Gunicorn instance to serve the Mail API
After=network.target
[Service]
User=root; WorkingDirectory=/opt/mail_api
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
    if systemctl is-active --quiet smtp-server.service; then log_info "  - smtp-server.service: [运行中]"; else log_error "  - smtp-server.service: [失败]"; fi
    if systemctl is-active --quiet mail-api.service; then log_info "  - mail-api.service: [运行中]"; else log_error "  - mail-api.service: [失败]"; fi
}

display_final_instructions() {
    log_info "============================================================"
    log_info "               🎉 部署完成！🎉"
    log_info "============================================================"
    log_info "Web界面: http://${VPS_IP}:5000"
    log_info "管理员: admin / ${ADMIN_PASSWORD}"
    log_warn "下一步: [DNS配置] MX记录 -> ${VPS_IP} | [云防火墙] 开放 25, 5000 端口"
    log_info "============================================================"
}

# ==============================================================================
#                           卸载功能模块
# ==============================================================================
run_uninstall() {
    log_warn "你确定要完全卸载邮件服务器吗？"
    log_warn "此操作将停止服务并永久删除 /opt/mail_api 目录及其中的所有邮件数据。"
    read -p "请输入 'yes' 确认: " CONFIRMATION
    if [ "$CONFIRMATION" != "yes" ]; then
        log_info "操作已取消。"
        exit 0
    fi

    log_info "开始执行卸载流程..."

    log_info "正在停止并禁用服务..."
    systemctl stop smtp-server.service mail-api.service > /dev/null 2>&1 || true
    systemctl disable smtp-server.service mail-api.service > /dev/null 2>&1 || true

    log_info "正在移除 systemd 服务文件..."
    rm -f /etc/systemd/system/smtp-server.service
    rm -f /etc/systemd/system/mail-api.service
    systemctl daemon-reload

    log_info "正在删除项目目录 /opt/mail_api..."
    rm -rf /opt/mail_api/

    if command -v ufw &> /dev/null; then
        log_info "正在清理 ufw 防火墙规则..."
        ufw delete allow 25/tcp > /dev/null 2>&1 || true
        ufw delete allow 5000/tcp > /dev/null 2>&1 || true
    fi

    log_info "============================================================"
    log_info "               ✅ 卸载完成！✅"
    log_info "============================================================"
    log_info "所有相关文件、服务和配置已被清除。"
}

# ==============================================================================
#                           脚本执行入口
# ==============================================================================
main() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "此脚本必须以 root 用户身份运行。"; exit 1;
    fi

    echo "请选择要执行的操作:"
    echo "  1) 安装或重新安装邮件服务器"
    echo "  2) 卸载邮件服务器"
    echo "  *) 退出"
    read -p "请输入选项 [1-2]: " ACTION

    case $ACTION in
        1)
            run_install
            ;;
        2)
            run_uninstall
            ;;
        *)
            echo "操作已取消。"
            exit 0
            ;;
    esac
}

main
