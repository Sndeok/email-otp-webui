# Email OTP WebUI

[中文说明](#中文说明) | [English](#english)

## 中文说明

一个本地邮箱验证码聚合服务和 Web 管理界面，用于统一查询多个邮箱中的验证码邮件。支持普通 IMAP/POP/SMTP 邮箱配置，也支持 Microsoft Graph 应用邮箱列表。

### 功能特性

- 轮询多个邮箱账号中的验证码/安全码/登录码邮件。
- 支持 Microsoft Graph 应用方式读取多个邮箱。
- 将近期邮件和提取出的验证码保存到本地 SQLite。
- 支持按邮箱、关键词、发件人和条数查询。
- 提供 WebUI：登录保护、邮箱管理、Graph 配置、批量删除、主题切换、响应式布局。
- 删除邮箱后会同步清理对应本地缓存，避免继续显示历史孤儿验证码。

### 目录结构

```text
email-otp-webui/
├── Dockerfile                  # Docker 镜像构建文件
├── docker-compose.yml          # Docker Compose 单容器部署
├── docker-entrypoint.sh        # 容器启动脚本，同时启动 8088 后端和 8090 WebUI
├── requirements.txt            # Python 依赖
├── config.example.json         # 已脱敏示例配置
├── email_otp_service.py        # 本地邮箱轮询/刷新后端，容器内监听 127.0.0.1:8088
├── email_otp_webui.py          # Flask WebUI，容器内监听 0.0.0.0:8090
├── config/
│   └── README.md               # 运行配置目录说明，真实 config.json 会放这里
└── data/
    └── README.md               # SQLite 数据目录说明，数据库会放这里
```

运行后会生成但不会提交到 Git 的文件：

```text
config/config.json              # 真实配置、邮箱密码、Graph Secret
data/email_otp_service.sqlite3  # 本地邮件/验证码缓存数据库
config/webui.secret             # Flask Session 密钥
```

### Docker 快速部署

进入项目目录：

```bash
cd email-otp-webui
```

启动：

```bash
docker compose up -d --build
```

如果你的系统是老版 Compose：

```bash
docker-compose up -d --build
```

访问：

```text
http://你的设备IP:8090
```

默认登录：

```text
用户名：admin
密码：admin123
```

首次启动时，如果 `config/config.json` 不存在，容器会自动从 `config.example.json` 复制生成一份。

查看日志：

```bash
docker compose logs -f --tail=100
```

验证容器内刷新后端是否正常：

```bash
docker exec -it email-otp-webui sh
python - <<'PY'
import urllib.request
print(urllib.request.urlopen('http://127.0.0.1:8088/health', timeout=3).read().decode())
PY
```

如果返回 `"ok": true`，说明 WebUI 调用的本地刷新后端正常。

### 手动 Python 运行

安装依赖：

```bash
python3 -m pip install -r requirements.txt
```

初始化配置：

```bash
cp config.example.json config.json
```

启动刷新后端：

```bash
python3 email_otp_service.py --config ./config.json --db ./email_otp_service.sqlite3 serve --host 127.0.0.1 --port 8088
```

另开一个终端启动 WebUI：

```bash
EMAIL_OTP_CONFIG=./config.json \
EMAIL_OTP_DB=./email_otp_service.sqlite3 \
EMAIL_OTP_REFRESH_URL=http://127.0.0.1:8088/refresh \
python3 email_otp_webui.py --host 0.0.0.0 --port 8090
```

### Microsoft Graph 字段对应关系

| WebUI 字段 | Azure / Entra ID 字段 |
|---|---|
| Graph Tenant ID | 目录(租户) ID |
| Graph Client ID | 应用程序(客户端) ID |
| Graph Client Secret | 客户端密码的“值” |

不要填写：

- 对象 ID
- 客户端密码的“机密 ID”

### 安全说明

本仓库刻意不包含任何真实配置、token、密钥、邮箱地址或本地 SQLite 数据。

请不要提交真实邮箱密码、Graph `client_secret`、token、数据库、日志或 `.env` 文件。

### 注意事项

- 默认示例配置不包含真实邮箱账号，需要先在 WebUI 中配置邮箱后才能查询验证码。
- 默认管理员密码是 `admin123`，建议首次登录后修改。
- SQLite 数据库只用于本地缓存，不建议提交或公开。
- 如果 163 邮箱刷新失败并提示不安全登录，通常是网易风控或授权码/IMAP 设置问题，不一定是程序错误。

---

## English

A local email verification-code aggregation service and Web UI.

### Features

- Poll email verification messages from IMAP/POP-style configured accounts and Microsoft Graph application mailboxes.
- Store recent OTP messages in local SQLite.
- Search by mailbox, keyword, sender and result limit.
- WebUI with login protection, mailbox/config management, batch delete, theme switching, and responsive layout.

### Directory layout

```text
email-otp-webui/
├── Dockerfile
├── docker-compose.yml
├── docker-entrypoint.sh
├── requirements.txt
├── config.example.json
├── email_otp_service.py
├── email_otp_webui.py
├── config/
│   └── README.md
└── data/
    └── README.md
```

Runtime files are intentionally ignored by Git:

```text
config/config.json
data/email_otp_service.sqlite3
config/webui.secret
```

### Docker quick start

```bash
docker compose up -d --build
```

Open:

```text
http://your-device-ip:8090
```

Default login:

```text
admin / admin123
```

### Manual Python start

```bash
python3 -m pip install -r requirements.txt
cp config.example.json config.json
python3 email_otp_service.py --config ./config.json --db ./email_otp_service.sqlite3 serve --host 127.0.0.1 --port 8088
```

In another terminal:

```bash
EMAIL_OTP_CONFIG=./config.json \
EMAIL_OTP_DB=./email_otp_service.sqlite3 \
EMAIL_OTP_REFRESH_URL=http://127.0.0.1:8088/refresh \
python3 email_otp_webui.py --host 0.0.0.0 --port 8090
```

### Security notes

This repository intentionally does **not** include real configuration, tokens, secrets, mailbox addresses, logs, or local SQLite data.
