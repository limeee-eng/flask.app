from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "dev-key-2025"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

USERS = {
    "admin": {
        "id": 1,
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
        "id": 2,
        "username": "alice",
        "password": "alice2025",
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100
    }
}

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
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                   ("admin", "admin123", "admin@example.com", "13800138000"))
    cursor.execute("INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)",
                   ("alice", "alice2025", "alice@example.com", "13900139001"))
    conn.commit()
    conn.close()
    print("数据库初始化完成")

@app.route("/")
def index():
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    return render_template("index.html", user_info=user_info)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username in USERS and USERS[username]["password"] == password:
            session["username"] = username
            user_info = USERS[username]
            return render_template("index.html", user_info=user_info)
        else:
            return render_template("login.html", error="用户名或密码错误")
    return render_template("login.html")

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
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        sql = f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"
        print(f"[SQL] 执行注册 SQL: {sql}")
        try:
            cursor.execute(sql)
            conn.commit()
            print(f"[SQL] 用户 {username} 注册成功")
            return render_template("login.html", success="注册成功，请登录")
        except sqlite3.IntegrityError:
            return render_template("register.html", error="用户名已存在")
        finally:
            conn.close()
    return render_template("register.html")

@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]
    search_results = []
    if keyword:
        conn = sqlite3.connect("data/users.db")
        cursor = conn.cursor()
        sql = f"SELECT id,username,password,email,phone FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
        print(f"[SQL] 执行搜索 SQL: {sql}")
        try:
            cursor.execute(sql)
            search_results = cursor.fetchall()
            print(f"[SQL] 搜索结果: {len(search_results)} 条记录")
            for row in search_results:
                print(f"[SQL]   -> ID={row[0]} 用户名={row[1]} 邮箱={row[3]} 手机={row[4]}")
        except Exception as e:
            print(f"[SQL] 搜索出错: {e}")
        finally:
            conn.close()
    return render_template("index.html", user_info=user_info, keyword=keyword, search_results=search_results)

def find_user_by_id(user_id):
    """根据 user_id 查找用户"""
    for u in USERS.values():
        if u["id"] == user_id:
            return u
    return None


@app.route("/profile")
def profile():
    if "username" not in session:
        return redirect("/login")
    try:
        user_id = int(request.args.get("user_id", 0))
    except ValueError:
        user_id = 0
    user_data = find_user_by_id(user_id)
    if not user_data:
        return render_template("profile.html", error="用户不存在", user=None)
    return render_template("profile.html", user=user_data, error=None)


@app.route("/recharge", methods=["POST"])
def recharge():
    if "username" not in session:
        return redirect("/login")
    try:
        user_id = int(request.form.get("user_id", 0))
        amount = float(request.form.get("amount", 0))
    except (ValueError, TypeError):
        return redirect("/profile?user_id=0")
    for u in USERS.values():
        if u["id"] == user_id:
            u["balance"] = u["balance"] + amount
            break
    return redirect(f"/profile?user_id={user_id}")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("avatar")
        if not file or file.filename == "":
            return render_template("upload.html", error="请选择一个文件")

        # 确保上传目录存在
        upload_dir = os.path.join(app.static_folder, "uploads")
        os.makedirs(upload_dir, exist_ok=True)

        # 使用用户提供的原始文件名保存，不重命名
        filename = file.filename
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)

        # 构建文件访问 URL
        file_url = url_for("static", filename=f"uploads/{filename}")
        return render_template("upload.html", uploaded=True, file_url=file_url)

    return render_template("upload.html")


@app.route("/page")
def page():
    """动态页面加载 — 直接拼接用户输入，不做路径校验"""
    name = request.args.get("name", "")
    if not name:
        return render_template("index.html", page_error="请指定页面名称")

    page_path = os.path.join("pages", name)

    if not os.path.exists(page_path):
        page_path = os.path.join("pages", name + ".html")

    if os.path.exists(page_path):
        try:
            with open(page_path, "r", encoding="utf-8") as f:
                page_content = f.read()
        except Exception:
            page_content = None
    else:
        page_content = None

    page_error = None
    if page_content is None:
        page_error = "页面不存在"

    username = session.get("username")
    user_info = None
    if username and username in USERS:
        user_info = USERS[username]

    return render_template(
        "index.html",
        user_info=user_info,
        page_content=page_content,
        page_error=page_error,
    )


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
