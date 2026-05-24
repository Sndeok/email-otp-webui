# Email OTP WebUI

A local email verification-code aggregation service and Web UI.

## Features

- Poll email verification messages from IMAP/POP-style configured accounts and Microsoft Graph application mailboxes.
- Store recent OTP messages in local SQLite.
- Search by mailbox, keyword, sender and result limit.
- WebUI with login protection, mailbox/config management, batch delete, theme switching, and responsive layout.

## Security notes

This repository intentionally does **not** include real configuration, tokens, secrets, mailbox addresses, or local SQLite data.

Use the example config below as a template and keep your real config outside Git.

## Files

- `email_otp_service.py` — local backend service, default port `8088`.
- `email_otp_webui.py` — Flask WebUI, default LAN port can be `8090`.
- `config.example.json` — sanitized example config.
- `.gitignore` — excludes secrets, databases, caches, logs, and env files.

## Quick start

```bash
python3 email_otp_service.py --config ./config.example.json --db ./email_otp_service.sqlite3
python3 email_otp_webui.py --host 0.0.0.0 --port 8090
```

For production/local use, create your own config file and point the services to it with environment variables or command-line options. Do not commit real secrets.
