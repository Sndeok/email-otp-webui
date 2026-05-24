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

### 安全说明

本仓库刻意不包含任何真实配置、token、密钥、邮箱地址或本地 SQLite 数据。

使用 `config.example.json` 作为模板创建你自己的配置文件，并将真实配置放在 Git 仓库外。请不要提交真实邮箱密码、Graph `client_secret`、token、数据库、日志或 `.env` 文件。

### 文件说明

- `email_otp_service.py` — 本地后端服务，默认端口 `8088`。
- `email_otp_webui.py` — Flask WebUI，默认可使用 `8090` 端口。
- `config.example.json` — 已脱敏的示例配置。
- `.gitignore` — 排除密钥、真实配置、数据库、缓存、日志和环境变量文件。

### 快速开始

```bash
python3 email_otp_service.py --config ./config.example.json --db ./email_otp_service.sqlite3
python3 email_otp_webui.py --host 0.0.0.0 --port 8090
```

实际使用时，建议复制一份自己的配置文件，例如：

```bash
cp config.example.json config.json
```

然后把真实邮箱、Microsoft Graph 配置和管理员密码写入 `config.json`，并确保它不会被提交到 Git。

WebUI 也支持通过环境变量指定配置、数据库和密钥路径：

```bash
export EMAIL_OTP_CONFIG=/path/to/config.json
export EMAIL_OTP_DB=/path/to/email_otp_service.sqlite3
export EMAIL_OTP_WEBUI_SECRET=/path/to/webui.secret
python3 email_otp_webui.py --host 0.0.0.0 --port 8090
```

### 注意事项

- 默认示例配置不包含真实账号，需要先配置邮箱后才能查询验证码。
- 如果对外开放 WebUI，请务必修改默认管理员密码，并只在可信网络中使用。
- SQLite 数据库只用于本地缓存，不建议提交或公开。
- Microsoft Graph 需要自行在 Azure / Entra ID 中配置应用权限和 `tenant_id`、`client_id`、`client_secret`。

---

## English

A local email verification-code aggregation service and Web UI.

### Features

- Poll email verification messages from IMAP/POP-style configured accounts and Microsoft Graph application mailboxes.
- Store recent OTP messages in local SQLite.
- Search by mailbox, keyword, sender and result limit.
- WebUI with login protection, mailbox/config management, batch delete, theme switching, and responsive layout.

### Security notes

This repository intentionally does **not** include real configuration, tokens, secrets, mailbox addresses, or local SQLite data.

Use the example config as a template and keep your real config outside Git.

### Files

- `email_otp_service.py` — local backend service, default port `8088`.
- `email_otp_webui.py` — Flask WebUI, default LAN port can be `8090`.
- `config.example.json` — sanitized example config.
- `.gitignore` — excludes secrets, databases, caches, logs, and env files.

### Quick start

```bash
python3 email_otp_service.py --config ./config.example.json --db ./email_otp_service.sqlite3
python3 email_otp_webui.py --host 0.0.0.0 --port 8090
```

For production/local use, create your own config file and point the services to it with environment variables or command-line options. Do not commit real secrets.
