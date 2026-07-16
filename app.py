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
  10. 文件上传安全加固（V14-V25）
  11. 越权和业务逻辑安全加固（V26-V30 见下方）
"""

import os
import re
import uuid
import imghdr
import urllib.request
import urllib.error
import subprocess
import platform
from flask import (
    Flask, render_template, request, redirect,
    session, url_for, send_from_directory, abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
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

# 文件上传限制（V14: 从 16MB 降至 2MB）
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

# V15: 允许的图片扩展名白名单
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

# V16: 上传目录（放在 static 外部，避免直接访问）
UPLOAD_DIR = "uploads/avatars"

# V17: 用户头像映射（username -> safe_filename）
USER_AVATARS = {}

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
        "id": 1,
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "id": 2,
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


def find_user_by_id(user_id):
    """根据 user_id 查找用户，返回用户信息或 None"""
    for u in USERS.values():
        if u["id"] == user_id:
            safe = dict(u)
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

    # V18: 传递用户头像 URL
    avatar_url = None
    if username and username in USER_AVATARS:
        avatar_url = url_for("serve_upload", filename=USER_AVATARS[username])

    return render_template("index.html", user_info=user_info, avatar_url=avatar_url)


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
            avatar_url = None
            if username in USER_AVATARS:
                avatar_url = url_for("serve_upload", filename=USER_AVATARS[username])
            return render_template("index.html", user_info=user_info, avatar_url=avatar_url)
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
        avatar_url=avatar_url if username and username in USER_AVATARS else None,
    )


@app.route("/profile")
def profile():
    """个人中心 — 仅允许查看自己的资料"""
    if "username" not in session:
        return redirect("/login")

    current_username = session["username"]
    current_user = USERS.get(current_username)

    try:
        user_id = int(request.args.get("user_id", current_user["id"]))
    except ValueError:
        abort(400)

    # V26: 仅允许查看自己的资料
    if current_user["id"] != user_id:
        abort(403)

    user_data = find_user_by_id(user_id)
    if not user_data:
        return render_template("profile.html", error="用户不存在", user=None)

    return render_template("profile.html", user=user_data, error=None)


@app.route("/recharge", methods=["POST"])
def recharge():
    """充值 — 仅允许给自己充值，校验金额"""
    if "username" not in session:
        return redirect("/login")

    current_username = session["username"]
    current_user = USERS.get(current_username)

    try:
        user_id = int(request.form.get("user_id", 0))
        amount = float(request.form.get("amount", 0))
    except (ValueError, TypeError):
        abort(400)

    # V27: 仅允许给自己充值
    if current_user["id"] != user_id:
        abort(403)

    # V28: 金额必须为正
    if amount <= 0:
        return render_template("profile.html",
                               user=find_user_by_id(user_id),
                               error="充值金额必须大于 0")

    # V29: 单次充值上限
    if amount > 100000:
        return render_template("profile.html",
                               user=find_user_by_id(user_id),
                               error="单次充值不能超过 100,000 元")

    # 查找用户并更新余额
    for u in USERS.values():
        if u["id"] == user_id:
            # V30: 余额上限 999999
            new_balance = u["balance"] + amount
            if new_balance > 999999:
                return render_template("profile.html",
                                       user=find_user_by_id(user_id),
                                       error="余额已达上限 999,999 元")
            u["balance"] = new_balance
            break

    return redirect(f"/profile")


@app.route("/change-password", methods=["POST"])
def change_password():
    """修改密码 — 不验证原密码，不验证用户身份"""
    if "username" not in session:
        return redirect("/login")

    username = request.form.get("username", "")
    new_password = request.form.get("new_password", "")

    if username in USERS and new_password:
        USERS[username]["password"] = new_password

    return redirect("/profile")


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    """URL 抓取 — 不限制协议，不检查内网地址"""
    if "username" not in session:
        return redirect("/login")

    url = request.form.get("url", "")
    if not url:
        return render_template("index.html", fetch_error="请输入 URL")

    try:
        resp = urllib.request.urlopen(url, timeout=10)
        content = resp.read().decode("utf-8", errors="replace")
        status_code = resp.getcode()

        # 取前 5000 字符
        truncated = content[:5000]
        if len(content) > 5000:
            truncated += "\n\n... (内容已截断，仅显示前 5000 字符)"

        fetch_result = {
            "url": url,
            "status": status_code,
            "content": truncated,
        }
    except urllib.error.URLError as e:
        fetch_result = {
            "url": url,
            "error": str(e.reason),
        }
    except Exception as e:
        fetch_result = {
            "url": url,
            "error": str(e),
        }

    username = session.get("username")
    user_info = None
    if username and username in USER_AVATARS:
        avatar_url = url_for("serve_upload", filename=USER_AVATARS[username])
    else:
        avatar_url = None

    return render_template(
        "index.html", user_info=user_info, avatar_url=avatar_url,
        fetch_result=fetch_result,
    )


@app.route("/ping", methods=["GET", "POST"])
def ping():
    """Ping 诊断 — 使用 shell=True 执行命令"""
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        ip = request.form.get("ip", "")
        command = f"ping -c 3 {ip}"
        try:
            output = subprocess.check_output(command, shell=True, timeout=30,
                                             stderr=subprocess.STDOUT)
            result = output.decode("utf-8", errors="replace")
        except subprocess.CalledProcessError as e:
            result = e.output.decode("utf-8", errors="replace") if e.output else str(e)
        except subprocess.TimeoutExpired as e:
            result = str(e)
        except Exception as e:
            result = str(e)

        return render_template("ping.html", result=result, ip=ip)

    return render_template("ping.html")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    username = session["username"]

    if request.method == "POST":
        file = request.files.get("avatar")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择一个文件")

        # V19: 使用 secure_filename 防止路径穿越
        filename = secure_filename(file.filename)
        if not filename:
            return render_template("upload.html", error="无效的文件名")

        # V20: 阻止隐藏文件（.htaccess 等）
        if filename.startswith("."):
            return render_template("upload.html", error="不支持的文件类型")

        # V21: 只允许图片扩展名
        ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
        if ext not in ALLOWED_EXTENSIONS:
            return render_template("upload.html", error="仅支持 PNG/JPG/GIF/WebP 格式的图片")

        # V22: UUID 重命名，防止覆盖和可预测文件名
        safe_name = f"{uuid.uuid4().hex}.{ext}"
        upload_dir = os.path.join(app.root_path, UPLOAD_DIR)
        os.makedirs(upload_dir, exist_ok=True)
        filepath = os.path.join(upload_dir, safe_name)
        file.save(filepath)

        # V23: 验证文件内容是否为有效图片
        if not imghdr.what(filepath):
            os.remove(filepath)
            return render_template("upload.html", error="文件不是有效的图片")

        # 记录用户头像
        USER_AVATARS[username] = safe_name

        file_url = url_for("serve_upload", filename=safe_name)
        return render_template("upload.html", uploaded=True, file_url=file_url)

    # GET: 显示当前头像（如果有）
    avatar_url = None
    if username in USER_AVATARS:
        avatar_url = url_for("serve_upload", filename=USER_AVATARS[username])
    return render_template("upload.html", avatar_url=avatar_url)


@app.route("/uploads/<filename>")
def serve_upload(filename):
    """V24: 通过认证路由提供文件访问，避免 static/ 直接暴露"""
    if "username" not in session:
        abort(403)

    upload_dir = os.path.join(app.root_path, UPLOAD_DIR)

    # V25: 用 safe_filename 防止路径穿越
    safe = secure_filename(filename)
    if not safe or safe != filename:
        abort(404)

    return send_from_directory(upload_dir, filename)


@app.route("/page")
def page():
    """动态页面加载 — 直接拼接用户输入，不做路径校验"""
    name = request.args.get("name", "")
    if not name:
        return render_template("index.html", page_error="请指定页面名称")

    # 直接拼接用户输入到路径（不校验 ../ ）
    page_path = os.path.join("pages", name)

    # 如果文件不存在，尝试加 .html 后缀
    if not os.path.exists(page_path):
        page_path = os.path.join("pages", name + ".html")

    if os.path.exists(page_path):
        try:
            with open(page_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        except Exception:
            page_content = None
            page_error = "页面读取失败"
    else:
        page_content = None

    page_error = None
    if page_content is None:
        page_error = "页面不存在"

    username = session.get("username")
    user_info = get_safe_user_info(username)
    avatar_url = None
    if username and username in USER_AVATARS:
        avatar_url = url_for("serve_upload", filename=USER_AVATARS[username])

    return render_template(
        "index.html",
        user_info=user_info,
        avatar_url=avatar_url,
        page_content=page_content,
        page_error=page_error,
    )


# ===================== 启动 =====================
if __name__ == "__main__":
    init_db()
    # V6: 默认仅监听本地
    host = os.environ.get("HOST", "127.0.0.1")
    # V4: Debug 模式由环境变量控制
    debug = os.environ.get("DEBUG", "").lower() in ("1", "true", "yes")
    app.run(debug=debug, host=host, port=5000)
