# Runtime data directory

This directory is mounted into the Docker container as `/app/data`.

The SQLite cache database is stored here by default:

```text
data/email_otp_service.sqlite3
```

Database files are intentionally ignored by Git because they may contain mailbox addresses, message snippets, OTP codes, and other private local data.
