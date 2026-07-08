from flask import Flask, render_template, request, redirect, session
import sqlite3
import os

app = Flask(__name__)
app.secret_key = "dev-key-2025"

USERS = {
    "admin": {
        "username": "admin",
        "password": "admin123",
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999
    },
    "alice": {
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

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
