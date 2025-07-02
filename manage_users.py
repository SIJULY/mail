import sqlite3
import argparse
from getpass import getpass
from werkzeug.security import generate_password_hash
import os

# --- 配置 ---
# 确保脚本能找到正确的数据库文件路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, 'emails.db')

def get_db_conn():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def setup_database():
    """初始化数据库，确保所有需要的表都已创建"""
    print("正在检查并初始化数据库...")
    conn = get_db_conn()
    c = conn.cursor()
    # 创建 users 表，用于存储用户信息
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    # 同时确保 received_emails 表也存在
    c.execute('''
        CREATE TABLE IF NOT EXISTS received_emails (
            id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT, sender TEXT,
            subject TEXT, body TEXT, body_type TEXT, 
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("数据库初始化完成。")

def add_user(email, password):
    """添加一个新用户"""
    conn = get_db_conn()
    cursor = conn.cursor()
    try:
        # 使用 werkzeug 生成安全的密码哈希值
        password_hash = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (email, password_hash) VALUES (?, ?)",
            (email, password_hash)
        )
        conn.commit()
        print(f"用户 '{email}' 添加成功。")
    except sqlite3.IntegrityError:
        # 如果邮箱地址已存在，会触发这个错误
        print(f"错误：用户 '{email}' 已存在。")
    finally:
        conn.close()

def delete_user(email):
    """根据邮箱地址删除一个用户"""
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE email = ?", (email,))
    if cursor.rowcount > 0:
        conn.commit()
        print(f"用户 '{email}' 已被删除。")
    else:
        print(f"错误：未找到用户 '{email}'。")
    conn.close()

def list_users():
    """列出所有已存在的用户"""
    conn = get_db_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email FROM users ORDER BY id")
    users = cursor.fetchall()
    if not users:
        print("数据库中当前没有用户。")
    else:
        print("用户列表:")
        print("--------------------")
        for user in users:
            print(f"  ID: {user['id']:<5} Email: {user['email']}")
        print("--------------------")
    conn.close()

if __name__ == "__main__":
    # 每次运行脚本时，都先确保数据库和表是准备好的
    setup_database()

    # 使用 argparse 创建友好的命令行界面
    parser = argparse.ArgumentParser(
        description="邮件服务用户管理工具",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command', required=True, help='可用的命令')

    # 'add' 命令
    parser_add = subparsers.add_parser('add', help='添加一个新用户 (例如: python3 manage_users.py add user@example.com)')
    parser_add.add_argument('email', type=str, help='新用户的邮箱地址')

    # 'delete' 命令
    parser_delete = subparsers.add_parser('delete', help='删除一个用户 (例如: python3 manage_users.py delete user@example.com)')
    parser_delete.add_argument('email', type=str, help='要删除的用户的邮箱地址')

    # 'list' 命令
    subparsers.add_parser('list', help='列出所有用户 (例如: python3 manage_users.py list)')

    args = parser.parse_args()

    # 根据命令执行相应的函数
    if args.command == 'add':
        # 使用 getpass 安全地输入密码，不会在屏幕上显示
        password = getpass(f"请输入用户 '{args.email}' 的密码: ")
        if not password:
            print("密码不能为空。操作取消。")
        else:
            password_confirm = getpass("请再次输入密码确认: ")
            if password != password_confirm:
                print("两次输入的密码不匹配。操作取消。")
            else:
                add_user(args.email, password)
    elif args.command == 'delete':
        # 删除前进行确认
        confirm = input(f"您确定要删除用户 '{args.email}' 吗？此操作无法恢复。[y/N]: ")
        if confirm.lower() == 'y':
            delete_user(args.email)
        else:
            print("操作已取消。")
    elif args.command == 'list':
        list_users()
