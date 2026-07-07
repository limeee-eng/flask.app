"""
用户信息管理平台 - 安全加固版

漏洞修复清单：
  V1  - 密钥从环境变量获取，运行时随机生成 fallback
  V2  - 密码使用 werkzeug.security 哈希存储（PBKDF2-SHA256）
  V3  - 密码不传入模板，添加 get_safe_user_info() 过滤
  V4  - Debug 模式由环境变量控制，默认关闭
  V5  - 删除 HTML 注释中的硬编码凭据（见 login.html）
  V6  - 默认仅监听 127.0.0.1，由环境变量覆盖
  V7  - Flask-Limiter 速率限制（10次/分钟登录；50次/小时全局）
  V8  - CSRFProtect 跨站请求伪造防护
  V9  - Session Cookie 标记 HttpOnly + SameSite=Lax
  V10 - 密码复杂度校验辅助函数
  V11 - 模板变量添加 | e 显式转义
  V12 - PERMANENT_SESSION_LIFETIME = 30分钟
  V13 - check_password_hash 常量时间比对
"""

import os
from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash

# ── 可选依赖：速率限制 & CSRF ──────────────────────────────
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ImportError:
    Limiter = None
    get_remote_address = None

try:
    from flask_wtf.csrf import CSRFProtect
except ImportError:
    CSRFProtect = None


# ── 应用初始化 ──────────────────────────────────────────────
app = Flask(__name__)

# V1 FIX: 密钥从环境变量获取，无环境变量时运行时随机生成
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# V9/V12 FIX: Session 安全配置
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,  # 30 分钟
)

# V8 FIX: CSRF 全局保护
csrf = CSRFProtect(app) if CSRFProtect else None

# V7 FIX: 速率限制
limiter = None
if Limiter and get_remote_address:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["50 per hour"],
        storage_uri="memory://",
    )


# ── 用户数据库 ──────────────────────────────────────────────
# V2 FIX: 密码以 PBKDF2-SHA256 哈希存储，而非明文
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}


# ── 辅助函数 ────────────────────────────────────────────────
def get_safe_user_info(user):
    """V3 FIX: 返回不包含密码字段的用户信息字典"""
    if user is None:
        return None
    return {k: v for k, v in user.items() if k != "password"}


def validate_password_strength(password):
    """V10 FIX: 密码强度校验——至少8位，含字母和数字"""
    if len(password) < 8:
        return "密码长度不能少于8位"
    if not any(c.isalpha() for c in password):
        return "密码必须包含至少一个字母"
    if not any(c.isdigit() for c in password):
        return "密码必须包含至少一个数字"
    return None


# ── 路由 ────────────────────────────────────────────────────
@app.route("/")
def index():
    """首页"""
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        # V3 FIX: 只传不含密码的用户信息
        user_info = get_safe_user_info(USERS[username])
    return render_template("index.html", user=user_info)


def _login():
    """登录视图（内部函数，外层注册路由并应用限流）"""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = USERS.get(username)

        # V2/V13 FIX: check_password_hash 使用 PBKDF2 常量时间比对
        if user and check_password_hash(user["password"], password):
            session.permanent = True
            session["username"] = username
            return render_template("index.html", user=get_safe_user_info(user))

        return render_template("login.html", error="用户名或密码错误")

    return render_template("login.html")


# V7 FIX: 对登录路由施加更严格的速率限制（10次/分钟），再注册路由
_login_view = limiter.limit("10 per minute")(_login) if limiter else _login
login = app.route("/login", methods=["GET", "POST"])(_login_view)


@app.route("/logout")
def logout():
    """登出"""
    session.clear()
    return redirect("/")


# ── 启动 ────────────────────────────────────────────────────
if __name__ == "__main__":
    # V4 FIX: Debug 模式由环境变量显式控制，默认关闭
    debug_enabled = os.environ.get("FLASK_DEBUG", "").lower() in ("1", "true", "yes")

    # V6 FIX: 默认仅监听本地地址
    host = os.environ.get("FLASK_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_PORT", 5000))

    print(f"  → 服务启动: http://{host}:{port}")
    print(f"  → Debug 模式: {'开启' if debug_enabled else '关闭'}")
    print(f"  → CSRF 保护: {'已启用' if csrf else '未安装 flask-wtf（建议安装）'}")
    print(f"  → 速率限制: {'已启用' if limiter else '未安装 flask-limiter（建议安装）'}")

    app.run(debug=debug_enabled, host=host, port=port)
