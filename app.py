import sqlite3
import re
import os
import math
import smtplib
from functools import wraps
from flask import Flask, request, Response, redirect, url_for, session, render_template_string, flash
from email.mime.text import MIMEText
from email.header import Header
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr
from markupsafe import escape
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from werkzeug.security import check_password_hash, generate_password_hash

# --- 配置 ---
DB_FILE = 'emails.db'
EMAILS_PER_PAGE = 100
LAST_CLEANUP_FILE = '/opt/mail_api/last_cleanup.txt'
CLEANUP_INTERVAL_DAYS = 3
EMAILS_TO_KEEP = 30

# 管理员账户配置
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "aaabbb$"  # 您指定的管理员密码

# --- SMTP 发信配置 ---
SMTP_SERVER = "smtp.sendgrid.net"
SMTP_PORT = 587
SMTP_USERNAME = "apikey"
SMTP_PASSWORD = "YOUR_NEW_SECURE_SENDGRID_API_KEY"  # !!! 在这里粘贴您新的、安全的API密钥
DEFAULT_SENDER = "noreply@mail.sijuly.nyc.mn"

# --- Flask 应用设置 ---
app = Flask(__name__)
app.config['SECRET_KEY'] = '111222333Sq$_a_very_long_and_random_string'  # !!! 强烈建议修改


# --- 数据库操作 ---
def get_db_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_conn()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS received_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT, sender TEXT,
            subject TEXT, body TEXT, body_type TEXT, 
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()


# --- 集成的自动清理函数 ---
def run_cleanup_if_needed():
    now = datetime.now()
    try:
        if os.path.exists(LAST_CLEANUP_FILE):
            with open(LAST_CLEANUP_FILE, 'r') as f:
                last_cleanup_time = datetime.fromisoformat(f.read().strip())
            if now - last_cleanup_time < timedelta(days=CLEANUP_INTERVAL_DAYS):
                return
    except Exception as e:
        print(f"读取上次清理时间失败: {e}，将继续执行清理检查。")
    print(f"[{now}] 开始执行定时邮件清理任务...")
    conn = None
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        query_delete = f"DELETE FROM received_emails WHERE id NOT IN (SELECT id FROM received_emails ORDER BY id DESC LIMIT {EMAILS_TO_KEEP})"
        deleted_rows_cursor = cursor.execute(query_delete)
        conn.commit()
        deleted_count = deleted_rows_cursor.rowcount
        if deleted_count > 0:
            print(f"清理完成，成功删除了 {deleted_count} 封旧邮件。")
        else:
            print("无需清理。")
        with open(LAST_CLEANUP_FILE, 'w') as f:
            f.write(now.isoformat())
            print(f"已更新清理时间戳: {now.isoformat()}")
    except Exception as e:
        print(f"自动清理邮件时发生错误: {e}")
    finally:
        if conn: conn.close()


# --- 核心邮件处理逻辑 ---
def process_email_data(to_address, raw_email_data):
    msg = message_from_bytes(raw_email_data)
    subject_raw, encoding = decode_header(msg['Subject'])[0]
    if isinstance(subject_raw, bytes):
        subject = subject_raw.decode(encoding or 'utf-8', errors='ignore')
    else:
        subject = str(subject_raw)
    sender = msg.get('From')
    body, body_type = "", "text/plain"
    if msg.is_multipart():
        html_part, text_part = None, None
        for part in msg.walk():
            if "text/html" in part.get_content_type():
                html_part = part
            elif "text/plain" in part.get_content_type():
                text_part = part
        if html_part:
            body = html_part.get_payload(decode=True).decode(html_part.get_content_charset() or 'utf-8',
                                                             errors='ignore')
            body_type = "text/html"
        elif text_part:
            body = text_part.get_payload(decode=True).decode(text_part.get_content_charset() or 'utf-8',
                                                             errors='ignore')
            body_type = "text/plain"
    else:
        body = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='ignore')
        body_type = msg.get_content_type()
    conn = None
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO received_emails (recipient, sender, subject, body, body_type) VALUES (?, ?, ?, ?, ?)",
            (to_address, sender, subject, body, body_type))
        conn.commit()
        print(f"邮件已存入: To='{to_address}', Subject='{subject}'")
    except Exception as e:
        print(f"数据库操作时出错: {e}")
    finally:
        if conn: conn.close()
        run_cleanup_if_needed()


# --- 辅助函数 ---
def strip_tags_for_preview(html_content):
    if not html_content: return ""
    text_content = re.sub(r'<[^>]+>', ' ', html_content)
    return re.sub(r'\s+', ' ', text_content).strip()


def send_email(to_address, subject, body):
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    msg['From'] = DEFAULT_SENDER
    msg['To'] = to_address
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True, "邮件发送成功！"
    except Exception as e:
        print(f"发送邮件时发生错误: {e}")
        return False, f"邮件发送失败: {e}"


# --- 登录系统 ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_email' not in session: return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login', next=request.url))
        return f(*args, **kwargs)

    return decorated_function


# --- Flask 路由 ---
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
            session['user_email'] = ADMIN_USERNAME
            session['is_admin'] = True
            next_url = request.args.get('next') or url_for('admin_view')
            return redirect(next_url)
        elif user and check_password_hash(user['password_hash'], password):
            session['user_email'] = user['email']
            session.pop('is_admin', None)
            next_url = request.args.get('next') or url_for('view_emails')
            return redirect(next_url)
        else:
            error = '邮箱或密码错误，请重试'

    login_form_html = f"""
        <!DOCTYPE html><html><head><title>登录</title>
        <style>body{{display:flex; flex-direction: column; justify-content:center; align-items:center; height:100vh; font-family:sans-serif;}} 
        h1{{color: #4CAF50; margin-bottom: 1.5em; font-size: 2.5em;}}
        .login-box{{padding:2em; border:1px solid #ccc; border-radius:5px; background-color:#f9f9f9; width: 300px;}}
        label{{margin-top: 1em;}}
        input{{display:block; margin-top:0.5em; margin-bottom:1em; padding:0.5em; width: 95%;}}
        .error{{color:red;}}</style></head>
        <body>
        <h1>小龙女她爸邮局服务系统</h1>
        <div class="login-box"><h2>邮箱登录</h2>
        {'<p class="error">' + escape(error) + '</p>' if error else ''}
        <form method="post">
            <label>邮箱地址 (或管理员账户):</label><input type="text" name="email" required>
            <label>密码:</label><input type="password" name="password" required>
            <input type="hidden" name="next" value="{escape(request.args.get('next', ''))}">
            <input type="submit" value="登录" style="width:100%; padding: 10px;"></form>
        </div></body></html>
    """
    return Response(login_form_html, mimetype="text/html; charset=utf-8")


@app.route('/admin_login', methods=['GET', 'POST'])
@login_required
def admin_login():
    error = None
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['is_admin'] = True
            next_url = request.args.get('next') or url_for('admin_view')
            return redirect(next_url)
        else:
            error = "管理员密码错误！"

    admin_login_html = f"""
        <!DOCTYPE html><html><head><title>管理员验证</title>
        <style>body{{display:flex; flex-direction: column; justify-content:center; align-items:center; height:100vh; font-family:sans-serif;}} 
        .login-box{{padding:2em; border:1px solid #ccc; border-radius:5px; background-color:#f9f9f9; width: 300px;}}
        .error{{color:red;}}</style></head>
        <body><div class="login-box"><h2>管理员验证</h2>
        <p>您正在尝试访问管理员视图，请输入管理员密码。</p>
        {'<p class="error">' + escape(error) + '</p>' if error else ''}
        <form method="post">
            <label>管理员密码:</label><input type="password" name="password" required>
            <input type="hidden" name="next" value="{escape(request.args.get('next', ''))}">
            <input type="submit" value="验证"></form>
        <p style="margin-top:2em;"><a href="{url_for('view_emails')}">返回个人收件箱</a></p>
        </div></body></html>
    """
    return Response(admin_login_html, mimetype="text/html; charset=utf-8")


@app.route('/logout')
def logout():
    session.pop('user_email', None)
    session.pop('is_admin', None)
    return redirect(url_for('login'))


@app.route('/view_emails')
@login_required
def view_emails():
    user_email = session['user_email']
    if user_email == ADMIN_USERNAME:
        return redirect(url_for('admin_view'))
    search_query = request.args.get('search', '').strip()
    try:
        page = int(request.args.get('page', 1))
    except (ValueError, TypeError):
        page = 1
    conn = get_db_conn()
    cursor = conn.cursor()
    params = [user_email]
    where_clauses = ["recipient = ?"]
    if search_query:
        search_term = f"%{search_query}%"
        where_clauses.append("(subject LIKE ?)")
        params.append(search_term)
    where_sql = "WHERE " + " AND ".join(where_clauses)
    count_query = f"SELECT COUNT(*) FROM received_emails {where_sql}"
    total_emails = cursor.execute(count_query, params).fetchone()[0]
    total_pages = math.ceil(total_emails / EMAILS_PER_PAGE) if total_emails > 0 else 1
    page = max(1, min(page, total_pages))
    offset = (page - 1) * EMAILS_PER_PAGE
    query_params = params + [EMAILS_PER_PAGE, offset]
    main_query = f"SELECT * FROM received_emails {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    emails_data = cursor.execute(main_query, query_params).fetchall()
    conn.close()
    return render_email_list_page(
        emails_data=emails_data, page=page, total_pages=total_pages,
        total_emails=total_emails, search_query=search_query,
        user_email=user_email, is_admin_view=False
    )


@app.route('/admin_view')
@login_required
@admin_required
def admin_view():
    search_query = request.args.get('search', '').strip()
    try:
        page = int(request.args.get('page', 1))
    except (ValueError, TypeError):
        page = 1
    conn = get_db_conn()
    cursor = conn.cursor()
    params, where_clauses = [], []
    if search_query:
        search_term = f"%{search_query}%"
        where_clauses.append("(subject LIKE ? OR recipient LIKE ?)")
        params.extend([search_term, search_term])
    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""
    count_query = f"SELECT COUNT(*) FROM received_emails {where_sql}"
    total_emails = cursor.execute(count_query, params).fetchone()[0]
    total_pages = math.ceil(total_emails / EMAILS_PER_PAGE) if total_emails > 0 else 1
    page = max(1, min(page, total_pages))
    offset = (page - 1) * EMAILS_PER_PAGE
    query_params = params + [EMAILS_PER_PAGE, offset]
    main_query = f"SELECT * FROM received_emails {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
    emails_data = cursor.execute(main_query, query_params).fetchall()
    conn.close()
    return render_email_list_page(
        emails_data=emails_data, page=page, total_pages=total_pages,
        total_emails=total_emails, search_query=search_query,
        user_email=session['user_email'], is_admin_view=True
    )


def render_email_list_page(emails_data, page, total_pages, total_emails, search_query, user_email, is_admin_view):
    view_endpoint = 'admin_view' if is_admin_view else 'view_emails'
    delete_selected_endpoint = 'admin_delete_selected_emails' if is_admin_view else 'delete_selected_emails'
    delete_all_endpoint = 'admin_delete_all_emails' if is_admin_view else 'delete_all_emails'
    title_text = f"管理员视图 (共 {total_emails} 封)" if is_admin_view else f"收件箱 ({user_email} - 共 {total_emails} 封)"
    search_placeholder = "搜索所有邮件的主题或收件人..." if is_admin_view else "在当前邮箱中搜索主题..."

    add_user_button_html = f'<a href="{url_for("add_user")}" class="add-user-button">新建用户</a>' if is_admin_view else ''

    # 使用Jinja2模板字符串来构建HTML
    html_template = f"""
        <!DOCTYPE html><html><head><title>{'管理员视图' if is_admin_view else '收件箱'}</title>
        <style>
            body{{font-family: sans-serif; margin: 2em;}} 
            .page-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 1em; }}
            .page-header h2 {{ margin: 0; }}
            .header-actions a {{ margin-left: 1em; text-decoration: none; font-size: 0.9em; padding: 8px 12px; border-radius: 4px; color: white; }}
            .header-actions .compose-button {{ background-color: #5cb85c; }}
            .header-actions .add-user-button {{ background-color: #337ab7; }}
            .header-actions .view-toggle {{ background-color: #f0ad4e; }}
            .header-actions .logout-link {{ background-color: #d9534f; }}
            table{{border-collapse: collapse; width: 100%; margin-top: 1em; table-layout: fixed;}}
            th, td{{border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; word-wrap: break-word;}}
            .actions, .search-box, .pagination {{margin-bottom: 1em;}} .search-box input[type=text] {{padding: 8px; width: 300px;}} .search-box button, .actions button {{padding: 8px 12px; cursor: pointer;}}
            .pagination {{text-align: center; padding: 1em 0;}} .pagination a, .pagination strong {{ margin: 0 5px; text-decoration: none; padding: 5px 10px; border: 1px solid #ddd; border-radius: 4px;}}
            .pagination strong {{ background-color: #4CAF50; color: white; border-color: #4CAF50; }}
            .preview{{width: 100%; line-height: 1.4em; max-height: 2.8em; overflow: hidden; text-overflow: ellipsis; display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical;}}
        </style>
        </head><body>
        <div class="page-header">
            <h2>{title_text}，第 {page}/{total_pages} 页</h2>
            <div class="header-actions">
                {add_user_button_html}
                <a href="{url_for('compose_email')}" class="compose-button">写邮件</a>
                <a href="{url_for('admin_view' if not is_admin_view else 'view_emails')}" class="view-toggle">切换到{'管理员' if not is_admin_view else '个人'}视图</a>
                <a href="{url_for('logout')}" class="logout-link">登出</a>
            </div>
        </div>
        <div class="search-box">
            <form method="GET" action="{url_for(view_endpoint)}">
                <input type="text" name="search" placeholder="{search_placeholder}" value="{escape(search_query)}">
                <button type="submit">搜索</button>
                {'<a href="' + url_for(view_endpoint) + '" style="margin-left:10px; text-decoration:underline; color:grey;">清空搜索</a>' if search_query else ''}
            </form>
        </div>
        <div class="actions">
            <button onclick="location.href='{url_for(view_endpoint, page=page, search=search_query)}'">刷新列表</button>
            <form method="POST" action="{url_for(delete_all_endpoint)}" style="display: inline;" onsubmit="return confirm('您确定要删除这些邮件吗？');"><button type="submit">删除所有邮件</button></form>
        </div>
        <form method="POST" action="{url_for(delete_selected_endpoint)}?page={page}&search={search_query}">
        <table><thead><tr>
            <th style="width: 3%; text-align: center;"><input type="checkbox" onclick="toggleAll(this);"></th>
            <th style="width: 15%;">时间 (北京)</th><th style="width: 20%;">主题</th><th style="width: 30%;">内容预览</th>
            <th style="width: 15%;">收件人</th><th style="width: 12%;">发件人</th><th style="width: 5%; text-align: center;">操作</th>
        </tr></thead><tbody>
    """

    if not emails_data:
        html_template += '<tr><td colspan="7" style="text-align:center;">没有找到邮件。</td></tr>'
    else:
        beijing_tz = ZoneInfo("Asia/Shanghai")
        for item in emails_data:
            utc_ts, bjt_str = item['timestamp'], "N/A"
            if utc_ts:
                try:
                    bjt_str = datetime.strptime(utc_ts, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc).astimezone(
                        beijing_tz).strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, TypeError):
                    bjt_str = utc_ts

            preview_text = escape(strip_tags_for_preview(item['body'] or ''))

            _, sender_addr = parseaddr(item['sender'] or "")

            html_template += f"""<tr>
                <td style="text-align: center;"><input type="checkbox" name="selected_ids" value="{item['id']}"></td>
                <td>{escape(bjt_str)}</td><td>{escape(item['subject'])}</td>
                <td><div class='preview'>{preview_text}</div></td>
                <td>{escape(item['recipient'])}</td><td>{escape(sender_addr or item['sender'] or "")}</td>
                <td><a href="{url_for('view_email_detail', email_id=item['id'])}" target="_blank">查看</a></td></tr>"""

    pagination_html = '<div class="pagination">'
    if total_pages > 1:
        if page > 1: pagination_html += f'<a href="{url_for(view_endpoint, page=page - 1, search=search_query)}">&laquo; 上一页</a>'
        for p in range(1, total_pages + 1):
            if p == page:
                pagination_html += f'<strong>{p}</strong>'
            else:
                pagination_html += f'<a href="{url_for(view_endpoint, page=p, search=search_query)}">{p}</a>'
        if page < total_pages: pagination_html += f'<a href="{url_for(view_endpoint, page=page + 1, search=search_query)}">下一页 &raquo;</a>'
    pagination_html += '</div>'

    html_template += f"""
        </tbody></table>
        {'<div class="actions" style="margin-top: 1em;"><button type="submit">删除选中邮件</button></div>' if emails_data else ''}
        </form>{pagination_html}
        <script>function toggleAll(source) {{ checkboxes = document.getElementsByName('selected_ids'); for(var c of checkboxes) c.checked = source.checked; }}</script>
        </body></html>
    """
    return Response(html_template, mimetype="text/html; charset=utf-8")


@app.route('/view_email/<int:email_id>')
@login_required
def view_email_detail(email_id):
    user_email = session['user_email']
    conn = get_db_conn()
    email = None
    if session.get('is_admin'):
        email = conn.execute("SELECT * FROM received_emails WHERE id = ?", (email_id,)).fetchone()
    else:
        email = conn.execute("SELECT * FROM received_emails WHERE id = ? AND recipient = ?",
                             (email_id, user_email)).fetchone()
    conn.close()
    if email: return Response(email['body'], mimetype=f"{email['body_type']}; charset=utf-8")
    return "邮件未找到或您无权查看。", 404


@app.route('/compose', methods=['GET', 'POST'])
@login_required
def compose_email():
    if request.method == 'POST':
        to = request.form.get('to')
        subject = request.form.get('subject')
        body = request.form.get('body')
        if not to or not subject or not body:
            flash("收件人、主题和内容都不能为空！", 'error')
        else:
            success, message = send_email(to, subject, body)
            flash(message, 'success' if success else 'error')
            if success: return redirect(url_for('view_emails'))

    compose_html = """
        <!DOCTYPE html><html><head><title>写邮件</title>
        <style>
            body{font-family: sans-serif; margin: 2em;} .container{max-width: 800px; margin: auto;}
            a {color: #4CAF50; text-decoration:none; margin-bottom: 1em; display: inline-block;}
            label{display: block; margin-top: 1em;} input, textarea{width: 100%; padding: 8px; margin-top: 5px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;}
            textarea{height: 200px; resize: vertical;} button{margin-top: 1em; padding: 10px 15px; cursor: pointer; background-color: #4CAF50; color: white; border: none; border-radius: 4px;}
            .flash{padding: 1em; margin-bottom: 1em; border-radius: 5px;}
            .flash.success{background-color: #d4edda; color: #155724;}
            .flash.error{background-color: #f8d7da; color: #721c24;}
        </style>
        </head><body><div class="container">
        <p><a href="{{ url_for('view_emails') }}">&laquo; 返回收件箱</a></p>
        <h2>写邮件</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST">
            <label for="to">收件人:</label><input type="email" id="to" name="to" required value="{{ request.form.get('to', '') }}">
            <label for="subject">主题:</label><input type="text" id="subject" name="subject" required value="{{ request.form.get('subject', '') }}">
            <label for="body">正文:</label><textarea id="body" name="body" required>{{ request.form.get('body', '') }}</textarea>
            <button type="submit">发送邮件</button>
        </form>
        </div></body></html>
    """
    return render_template_string(compose_html)


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        if not email or not password or not password_confirm:
            flash("邮箱和密码不能为空！", 'error')
        elif password != password_confirm:
            flash("两次输入的密码不匹配！", 'error')
        else:
            try:
                conn = get_db_conn()
                cursor = conn.cursor()
                cursor.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)",
                               (email, generate_password_hash(password)))
                conn.commit()
                flash(f"用户 '{escape(email)}' 添加成功。", 'success')
                return redirect(url_for('admin_view'))
            except sqlite3.IntegrityError:
                flash(f"错误：用户 '{escape(email)}' 已存在。", 'error')
            finally:
                if conn: conn.close()

    add_user_html = """
        <!DOCTYPE html><html><head><title>新建用户</title>
        <style>
            body{font-family: sans-serif; margin: 2em;} .container{max-width: 800px; margin: auto;}
            a {color: #4CAF50; text-decoration:none; margin-bottom: 1em; display: inline-block;}
            label{display: block; margin-top: 1em;} input{width: 100%; padding: 8px; margin-top: 5px; box-sizing: border-box; border: 1px solid #ccc; border-radius: 4px;}
            button{margin-top: 1em; padding: 10px 15px; cursor: pointer; background-color: #337ab7; color: white; border: none; border-radius: 4px;}
            .flash{padding: 1em; margin-bottom: 1em; border-radius: 5px;}
            .flash.success{background-color: #d4edda; color: #155724;}
            .flash.error{background-color: #f8d7da; color: #721c24;}
        </style>
        </head><body><div class="container">
        <p><a href="{{ url_for('admin_view') }}">&laquo; 返回管理员视图</a></p>
        <h2>新建用户</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="POST">
            <label for="email">新用户邮箱地址:</label><input type="email" id="email" name="email" required>
            <label for="password">密码:</label><input type="password" id="password" name="password" required>
            <label for="password_confirm">确认密码:</label><input type="password" id="password_confirm" name="password_confirm" required>
            <button type="submit">创建用户</button>
        </form>
        </div></body></html>
    """
    return render_template_string(add_user_html)


@app.route('/delete_selected_emails', methods=['POST'])
@login_required
def delete_selected_emails():
    user_email = session['user_email']
    ids = request.form.getlist('selected_ids')
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    if ids:
        try:
            conn = get_db_conn()
            cursor = conn.cursor()
            placeholders = ','.join('?' * len(ids))
            query = f"DELETE FROM received_emails WHERE id IN ({placeholders}) AND recipient = ?"
            cursor.execute(query, ids + [user_email])
            conn.commit()
        finally:
            if conn: conn.close()
    return redirect(url_for('view_emails', search=search, page=page))


@app.route('/delete_all_emails', methods=['POST'])
@login_required
def delete_all_emails():
    user_email = session['user_email']
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM received_emails WHERE recipient = ?", (user_email,))
        conn.commit()
    finally:
        if conn: conn.close()
    return redirect(url_for('view_emails'))


# 【新增】管理员删除路由
@app.route('/admin_delete_selected_emails', methods=['POST'])
@login_required
@admin_required
def admin_delete_selected_emails():
    ids = request.form.getlist('selected_ids')
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    if ids:
        try:
            conn = get_db_conn()
            cursor = conn.cursor()
            placeholders = ','.join('?' * len(ids))
            query = f"DELETE FROM received_emails WHERE id IN ({placeholders})"
            cursor.execute(query, ids)
            conn.commit()
        finally:
            if conn: conn.close()
    return redirect(url_for('admin_view', search=search, page=page))


@app.route('/admin_delete_all_emails', methods=['POST'])
@login_required
@admin_required
def admin_delete_all_emails():
    try:
        conn = get_db_conn()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM received_emails")
        conn.commit()
    finally:
        if conn: conn.close()
    return redirect(url_for('admin_view'))


init_db()