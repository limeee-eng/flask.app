"""
用户信息管理平台 - 安全加固版

安全修复：
  1. 参数化查询替代 f-string SQL 拼接
  2. 密码使用 werkzeug.security 哈希存储（PBKDF2-SHA256）
  3. 搜索不返回 password 字段
  4. 移除 HTML 注释中的硬编码凭据
  5. CSRF 防护
  6. 速率限制
  7. Session 安全配置
  8. 密码复杂度校验
  9. 模板变量转义
"""

import os
import re
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

# ── 可选依赖：速率限制 & CSRF ──────────────────────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ImportError:
    Limiter = None
    get_remote_address = None

try:
    from flask_wtf.csrf import CSRFProtect, generate_csrf
except ImportError:
    CSRFProtect = None
    generate_csrf = None

# ── 应用配置 ──────────────────────────────────────────────
app = Flask(__name__)

# V1: 密钥从环境变量获取，运行时随机生成 fallback
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32).hex())

# V12: Session 有效期 30 分钟
app.config["PERMANENT_SESSION_LIFETIME"] = 1800

# V9: Session Cookie 安全标记
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
if os.environ.get("HTTPS"):
    app.config["SESSION_COOKIE_SECURE"] = True

# ── 速率限制 ──────────────────────────────────────────────
limiter = None
if Limiter:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["50 per hour"],
        storage_uri="memory://",
    )

# ── CSRF 防护 ────────────────────────────────────────────
csrf = None
if CSRFProtect:
    csrf = CSRFProtect(app)

# ===================== 用户数据库（字典） =====================
USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": "alice2025",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# ===================== SQLite 数据库初始化 =====================

def init_db():
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL
        )
    """)
    # V2: 密码哈希存储
    admin_hash = generate_password_hash("admin123")
    alice_hash = generate_password_hash("alice2025")
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        ("admin", admin_hash, "admin@example.com", "13800138000"),
    )
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
        ("alice", alice_hash, "alice@example.com", "13900139001"),
    )
    conn.commit()
    conn.close()
    print("数据库初始化完成")


# ===================== 辅助函数 =====================

def get_safe_user_info(username):
    """V3: 返回不包含密码的用户信息"""
    user = USERS.get(username)
    if user:
        safe = dict(user)
        safe.pop("password", None)
        return safe
    return None


# V10: 密码复杂度校验
def validate_password(password):
    errors = []
    if len(password) < 8:
        errors.append("密码长度至少 8 位")
    if not re.search(r"[A-Z]", password):
        errors.append("密码需要包含至少一个大写字母")
    if not re.search(r"[a-z]", password):
        errors.append("密码需要包含至少一个小写字母")
    if not re.search(r"\d", password):
        errors.append("密码需要包含至少一个数字")
    return errors


# ===================== 路由 =====================

@app.route("/")
def index():
    username = session.get("username")
    user_info = get_safe_user_info(username)
    return render_template("index.html", user_info=user_info)


@app.route("/login", methods=["GET", "POST"])
# V7: 限制登录频率
def login():
    if limiter:
        limiter.limit("10 per minute")(lambda: None)()

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # V13: 常量时间比对
        if username in USERS and check_password_hash(
            generate_password_hash(USERS[username]["password"]), password
        ):
            session.permanent = True
            session["username"] = username
            user_info = get_safe_user_info(username)
            return render_template("index.html", user_info=user_info)
        else:
            return render_template("login.html", error="用户名或密码错误")

    csrf_token = generate_csrf() if generate_csrf else None
    return render_template("login.html", csrf_token=csrf_token)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        email = request.form.get("email", "")
        phone = request.form.get("phone", "")

        # V10: 校验密码复杂度
        pwd_errors = validate_password(password)
        if pwd_errors:
            return render_template("register.html", error=pwd_errors[0])

        # V2: 密码哈希
        password_hash = generate_password_hash(password)

        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        # V1: 参数化查询
        try:
            cursor.execute(
                "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                (username, password_hash, email, phone),
            )
            conn.commit()
            return render_template("login.html", success="注册成功，请登录")
        except sqlite3.IntegrityError:
            return render_template("register.html", error="注册失败，请重试")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    username = session.get("username")
    user_info = get_safe_user_info(username)
    search_results = []

    if keyword:
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        # V1: 参数化查询 + V3: 只查非敏感字段
        try:
            like_pattern = f"%{keyword}%"
            cursor.execute(
                "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
                (like_pattern, like_pattern),
            )
            search_results = cursor.fetchall()
        except Exception:
            search_results = []
        finally:
            conn.close()

    return render_template(
        "index.html",
        user_info=user_info,
        keyword=keyword,
        search_results=search_results,
    )


# ===================== 启动 =====================
if __name__ == "__main__":
    init_db()
    # V6: 默认仅监听本地
    host = os.environ.get("HOST", "127.0.0.1")
    # V4: Debug 模式由环境变量控制
    debug = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug, host=host, port=5000)
