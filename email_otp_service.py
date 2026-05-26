#!/usr/bin/env python3
"""Local email OTP aggregation service.

Features:
- Poll multiple mailboxes over IMAP
- Store recent messages and extracted OTP codes in SQLite
- Serve a small local HTTP API for querying latest codes
- Supports 163.com and Outlook defaults, plus generic IMAP

Security notes:
- Bind to 127.0.0.1 by default
- Store credentials only in local config files
- Do not expose this service directly to the internet
"""
from __future__ import annotations

import argparse
import email
import email.policy
import imaplib
import json
import os
import re
import sqlite3
import threading
import time
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs, urlparse
from urllib.parse import urlencode, quote
import urllib.request
import urllib.error
import ssl
import socket

DEFAULT_CONFIG = Path.home() / ".config" / "hermes" / "email_otp_service.json"
DEFAULT_DB = Path.home() / ".local" / "share" / "hermes" / "email_otp_service.sqlite3"
DEFAULT_PORT = 8088
DEFAULT_HOST = "127.0.0.1"

PROVIDER_DEFAULTS = {
    "163": {"imap_host": "imap.163.com", "imap_port": 993, "ssl": True},
    "outlook": {"imap_host": "outlook.office365.com", "imap_port": 993, "ssl": True},
    "imap": {"imap_host": None, "imap_port": 993, "ssl": True},
}

OTP_CONTEXT_WORDS = [
    "验证码",
    "校验码",
    "动态码",
    "verification code",
    "security code",
    "login code",
    "temporary code",
    "one-time password",
    "one time password",
    "otp",
]

OTP_PATTERNS = [
    re.compile(r"(?i)verification\s*code[:\s\-]*(?:is\s*)?([A-Z0-9]{4,10})"),
    re.compile(r"(?i)security\s*code[:\s\-]*(?:is\s*)?([A-Z0-9]{4,10})"),
    re.compile(r"(?i)login\s*code[:\s\-]*(?:is\s*)?([A-Z0-9]{4,10})"),
    re.compile(r"(?i)temporary\s+(?:chatgpt\s+)?(?:login\s+)?code[:\s\-]*(?:is\s*)?([A-Z0-9]{4,10})"),
    re.compile(r"(?i)(?:one[-\s]?time\s+password|otp)[:\s\-]*(?:is\s*)?([A-Z0-9]{4,10})"),
    re.compile(r"(?i)([A-Z0-9]{4,10})\s+is\s+your\s+(?:verification|security|login|temporary|one[-\s]?time)\s+code"),
    re.compile(r"(?i)your\s+(?:verification|security|login|temporary|one[-\s]?time)\s+code\s+is\s+([A-Z0-9]{4,10})"),
    re.compile(r"(?i)code[:\s\-]+([A-Z0-9]{4,10})"),
    re.compile(r"(?i)验证码[:\s：-]*([A-Z0-9]{4,10})"),
    re.compile(r"(?i)([A-Z0-9]{4,10})\s*(?:是|为)\s*(?:您|你的|您的)?(?:验证码|校验码|动态码)"),
]

KEYWORDS = OTP_CONTEXT_WORDS + ["verify", "authentication"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def decode_mime(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def strip_html(text: str) -> str:
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = text.replace("&nbsp;", " ").replace("&lt;", "<").replace("&gt;", ">")
    text = text.replace("&amp;", "&")
    return re.sub(r"\s+", " ", text).strip()


def ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, data: Any) -> None:
    ensure_dir(path)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_account_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", name.strip())


def redacted_account_config(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Return account config safe for DB/API display; never persist passwords."""
    data = json.loads(json.dumps(raw, ensure_ascii=False))
    if "password" in data:
        data["password"] = "***"
    if "token" in data:
        data["token"] = "***"
    return data


def open_db(db_path: Path) -> sqlite3.Connection:
    ensure_dir(db_path)
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def init_db(db_path: Path) -> None:
    conn = open_db(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                name TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                username TEXT NOT NULL,
                imap_host TEXT,
                imap_port INTEGER,
                imap_ssl INTEGER,
                folder TEXT DEFAULT 'INBOX',
                poll_interval INTEGER DEFAULT 60,
                enabled INTEGER DEFAULT 1,
                created_at TEXT,
                updated_at TEXT,
                last_uid INTEGER DEFAULT 0,
                last_error TEXT,
                config_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_name TEXT NOT NULL,
                uid INTEGER NOT NULL,
                message_id TEXT,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                date TEXT,
                received_at TEXT,
                snippet TEXT,
                body TEXT,
                code TEXT,
                code_reason TEXT,
                score INTEGER DEFAULT 0,
                raw_headers TEXT,
                UNIQUE(account_name, uid)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_account_date ON messages(account_name, received_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_account_code ON messages(account_name, code)")
        conn.commit()
    finally:
        conn.close()


def default_config() -> Dict[str, Any]:
    return {
        "http_host": DEFAULT_HOST,
        "http_port": DEFAULT_PORT,
        "poll_interval": 60,
        "lookback_messages": 30,
        "graph_application": {
            "enabled": False,
            "tenant_id": "",
            "client_id": "",
            "client_secret": "",
            "mailboxes": []
        },
        "accounts": [],
    }


def load_config(path: Path) -> Dict[str, Any]:
    return {**default_config(), **load_json(path, {})}


@dataclass
class AccountSpec:
    name: str
    provider: str
    username: str
    password: str
    imap_host: str
    imap_port: int = 993
    imap_ssl: bool = True
    folder: str = "INBOX"
    poll_interval: int = 60
    enabled: bool = True
    filters: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict)


def parse_account(raw: Dict[str, Any]) -> AccountSpec:
    provider = str(raw.get("provider", "imap")).lower()
    defaults = PROVIDER_DEFAULTS.get(provider, PROVIDER_DEFAULTS["imap"])
    imap = raw.get("imap", {}) or {}
    username = raw.get("username") or raw.get("email") or ""
    password = raw.get("password") or ""
    host = imap.get("host") or defaults["imap_host"]
    if not host:
        raise ValueError(f"Missing imap.host for account {raw.get('name')}")
    return AccountSpec(
        name=normalize_account_name(raw.get("name") or username),
        provider=provider,
        username=username,
        password=password,
        imap_host=host,
        imap_port=int(imap.get("port") or defaults["imap_port"] or 993),
        imap_ssl=bool(imap.get("ssl", defaults["ssl"])),
        folder=str(imap.get("folder") or raw.get("folder") or "INBOX"),
        poll_interval=int(raw.get("poll_interval") or 60),
        enabled=bool(raw.get("enabled", True)),
        filters=raw.get("filters", {}) or {},
        raw=raw,
    )


def upsert_account(db_path: Path, account: AccountSpec) -> None:
    conn = open_db(db_path)
    try:
        conn.execute(
            """
            INSERT INTO accounts (
                name, provider, username, imap_host, imap_port, imap_ssl, folder,
                poll_interval, enabled, created_at, updated_at, last_uid, last_error, config_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT last_uid FROM accounts WHERE name=?), 0), '', ?)
            ON CONFLICT(name) DO UPDATE SET
                provider=excluded.provider,
                username=excluded.username,
                imap_host=excluded.imap_host,
                imap_port=excluded.imap_port,
                imap_ssl=excluded.imap_ssl,
                folder=excluded.folder,
                poll_interval=excluded.poll_interval,
                enabled=excluded.enabled,
                updated_at=excluded.updated_at,
                config_json=excluded.config_json
            """,
            (
                account.name,
                account.provider,
                account.username,
                account.imap_host,
                account.imap_port,
                1 if account.imap_ssl else 0,
                account.folder,
                account.poll_interval,
                1 if account.enabled else 0,
                utc_now(),
                utc_now(),
                account.name,
                json.dumps(redacted_account_config(account.raw), ensure_ascii=False),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def list_accounts(db_path: Path) -> List[Dict[str, Any]]:
    conn = open_db(db_path)
    try:
        rows = conn.execute("SELECT * FROM accounts ORDER BY name").fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def save_message(db_path: Path, msg: Dict[str, Any]) -> None:
    conn = open_db(db_path)
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO messages (
                account_name, uid, message_id, sender, recipient, subject, date, received_at,
                snippet, body, code, code_reason, score, raw_headers
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                msg["account_name"],
                msg["uid"],
                msg.get("message_id"),
                msg.get("sender"),
                msg.get("recipient"),
                msg.get("subject"),
                msg.get("date"),
                msg.get("received_at"),
                msg.get("snippet"),
                msg.get("body"),
                msg.get("code"),
                msg.get("code_reason"),
                msg.get("score", 0),
                msg.get("raw_headers"),
            ),
        )
        conn.execute(
            "UPDATE accounts SET last_uid=?, last_error='', updated_at=? WHERE name=?",
            (int(msg["uid"]), utc_now(), msg["account_name"]),
        )
        conn.commit()
    finally:
        conn.close()


def graph_uid(mailbox: str, message_id: str) -> int:
    """Stable positive SQLite uid for Graph messages, unique per mailbox/message."""
    digest = hashlib.sha256(f"graph:{mailbox}:{message_id}".encode("utf-8")).digest()
    return int.from_bytes(digest[:7], "big")


RETRYABLE_HTTP_EXCEPTIONS = (
    TimeoutError,
    socket.timeout,
    urllib.error.URLError,
    ssl.SSLError,
)


def http_json(method: str, url: str, headers: Dict[str, str], data: Optional[Dict[str, Any]] = None, timeout: float = 30.0, attempts: int = 3) -> Dict[str, Any]:
    body = None
    req_headers = dict(headers)
    if data is not None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    last_error: Optional[BaseException] = None
    for attempt in range(1, max(1, attempts) + 1):
        req = urllib.request.Request(url, data=body, method=method, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            raise RuntimeError(f"HTTP {e.code} {url}: {raw[:1000]}") from e
        except RETRYABLE_HTTP_EXCEPTIONS as e:
            last_error = e
            if attempt >= max(1, attempts):
                break
            time.sleep(min(2.0 * attempt, 5.0))
    raise RuntimeError(f"HTTP {method} failed after {max(1, attempts)} attempts: {last_error!r}")


def graph_get_token(graph_cfg: Dict[str, Any]) -> str:
    tenant_id = graph_cfg.get("tenant_id")
    client_id = graph_cfg.get("client_id")
    client_secret = graph_cfg.get("client_secret")
    if not (tenant_id and client_id and client_secret):
        raise ValueError("graph_application tenant_id/client_id/client_secret are required")
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    form = urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=form,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "HermesEmailOTP/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"Graph token failed HTTP {e.code}: {raw[:1000]}") from e
    token = payload.get("access_token")
    if not token:
        raise RuntimeError(f"Graph token response missing access_token: {payload}")
    return token


def graph_fetch_mailbox(db_path: Path, graph_cfg: Dict[str, Any], mailbox: str, token: str, lookback: int = 30) -> Dict[str, Any]:
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "HermesEmailOTP/1.0"}
    params = urlencode({
        "$top": str(min(max(lookback, 1), 50)),
        "$orderby": "receivedDateTime desc",
        "$select": "id,subject,from,toRecipients,receivedDateTime,bodyPreview,body,internetMessageId",
    })
    url = f"https://graph.microsoft.com/v1.0/users/{quote(mailbox)}/mailFolders/inbox/messages?{params}"
    payload = http_json("GET", url, headers)
    processed = 0
    found = 0
    account_name = normalize_account_name(mailbox)
    fake_raw = {
        "name": account_name,
        "provider": "graph_application",
        "username": mailbox,
        "password": "***",
        "imap": {"host": "graph.microsoft.com", "port": 443, "ssl": True, "folder": "INBOX"},
        "enabled": True,
    }
    upsert_account(db_path, parse_account(fake_raw))
    # Clear a previous transient mailbox error as soon as this Graph mailbox
    # is readable. This must happen even when there are no new messages,
    # otherwise the WebUI can keep showing an old SSL/timeout error forever.
    clear_account_error(db_path, account_name)
    for item in payload.get("value", []):
        processed += 1
        msg_id = item.get("id") or item.get("internetMessageId") or ""
        subject = item.get("subject") or ""
        from_obj = item.get("from") or {}
        sender = (((from_obj.get("emailAddress") or {}).get("address")) or ((from_obj.get("emailAddress") or {}).get("name")) or "")
        recipients = item.get("toRecipients") or []
        recipient = ", ".join([((r.get("emailAddress") or {}).get("address") or "") for r in recipients])
        body_preview = item.get("bodyPreview") or ""
        body_obj = item.get("body") or {}
        body = strip_html(body_obj.get("content") or body_preview)
        if not body:
            body = body_preview
        code, reason, code_score = extract_code(subject, sender, body)
        score = score_message(subject, sender, body, graph_cfg.get("filters", {}) or {}) + code_score
        if code:
            found += 1
        save_message(db_path, {
            "account_name": account_name,
            "uid": graph_uid(mailbox, msg_id),
            "message_id": item.get("internetMessageId") or msg_id,
            "sender": sender,
            "recipient": recipient,
            "subject": subject,
            "date": item.get("receivedDateTime") or "",
            "received_at": item.get("receivedDateTime") or utc_now(),
            "snippet": body[:500],
            "body": body,
            "code": code,
            "code_reason": reason,
            "score": score,
            "raw_headers": json.dumps({"graph_id": msg_id, "mailbox": mailbox}, ensure_ascii=False),
        })
    return {"account": account_name, "mailbox": mailbox, "processed": processed, "found": found}


def graph_refresh(db_path: Path, config: Dict[str, Any], mailboxes: Optional[List[str]] = None) -> Dict[str, Any]:
    graph_cfg = config.get("graph_application") or {}
    if not graph_cfg.get("enabled"):
        return {"ok": False, "error": "graph_application.enabled is false"}
    targets = mailboxes or graph_cfg.get("mailboxes") or []
    if not targets:
        return {"ok": False, "error": "No graph mailboxes configured"}
    token = graph_get_token(graph_cfg)
    results = []
    for mailbox in targets:
        try:
            results.append(graph_fetch_mailbox(db_path, graph_cfg, mailbox, token, lookback=int(config.get("lookback_messages", 30))))
        except Exception as e:
            account_name = normalize_account_name(mailbox)
            set_account_error(db_path, account_name, repr(e))
            results.append({"account": account_name, "mailbox": mailbox, "error": repr(e)})
    errors = [r for r in results if isinstance(r, dict) and r.get("error")]
    return {"ok": not errors, "mode": "graph_application", "results": results, "error_count": len(errors)}


def clear_account_error(db_path: Path, account_name: str) -> None:
    conn = open_db(db_path)
    try:
        conn.execute("UPDATE accounts SET last_error='', updated_at=? WHERE name=?", (utc_now(), account_name))
        conn.commit()
    finally:
        conn.close()


def set_account_error(db_path: Path, account_name: str, error: str) -> None:
    conn = open_db(db_path)
    try:
        conn.execute("UPDATE accounts SET last_error=?, updated_at=? WHERE name=?", (error, utc_now(), account_name))
        conn.commit()
    finally:
        conn.close()


def get_last_uid(db_path: Path, account_name: str) -> int:
    conn = open_db(db_path)
    try:
        row = conn.execute("SELECT last_uid FROM accounts WHERE name=?", (account_name,)).fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    finally:
        conn.close()


def fetch_body_from_message(message: Message) -> str:
    parts: List[str] = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_maintype() != "text":
                continue
            if part.get_content_disposition() == "attachment":
                continue
            charset = part.get_content_charset() or "utf-8"
            payload = part.get_payload(decode=True)
            if not payload:
                continue
            try:
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = payload.decode("utf-8", errors="replace")
            if part.get_content_subtype() == "html":
                text = strip_html(text)
            parts.append(text)
    else:
        charset = message.get_content_charset() or "utf-8"
        payload = message.get_payload(decode=True)
        if payload:
            try:
                text = payload.decode(charset, errors="replace")
            except Exception:
                text = payload.decode("utf-8", errors="replace")
            if message.get_content_subtype() == "html":
                text = strip_html(text)
            parts.append(text)
    return re.sub(r"\s+", " ", "\n".join(parts)).strip()


def extract_code(subject: str, sender: str, body: str) -> tuple[Optional[str], str, int]:
    haystack = f"{subject}\n{sender}\n{body}"
    lowered = haystack.lower()
    best = None
    reason = ""
    score = 0
    for pattern in OTP_PATTERNS:
        for match in pattern.finditer(haystack):
            code = match.group(1)
            snippet_start = max(0, match.start() - 80)
            snippet_end = min(len(haystack), match.end() + 80)
            snippet = lowered[snippet_start:snippet_end]
            has_context = any(k in snippet for k in OTP_CONTEXT_WORDS)
            # Never treat a bare number from newsletters, digests, addresses,
            # dates, or postal codes as a verification code. A candidate must
            # have OTP context near it or come from one of the explicit
            # context-bearing regexes above.
            if not has_context:
                continue
            local_score = 4
            if any(k in lowered for k in KEYWORDS):
                local_score += 1
            if len(code) == 6 and code.isdigit():
                local_score += 1
            if local_score > score:
                best = code
                score = local_score
                reason = f"pattern={pattern.pattern}"
    return best, reason, score


def score_message(subject: str, sender: str, body: str, filters: Dict[str, Any]) -> int:
    score = 0
    text = f"{subject}\n{sender}\n{body}".lower()
    for kw in filters.get("keywords", []):
        if kw and kw.lower() in text:
            score += 4
    for kw in filters.get("subject_keywords", []):
        if kw and kw.lower() in subject.lower():
            score += 3
    for kw in filters.get("sender_keywords", []):
        if kw and kw.lower() in sender.lower():
            score += 3
    for kw in KEYWORDS:
        if kw in text:
            score += 1
    return score


def message_matches_filters(subject: str, sender: str, body: str, filters: Dict[str, Any]) -> bool:
    if not filters:
        return True
    include_senders = filters.get("senders") or []
    if include_senders and not any(s.lower() in sender.lower() for s in include_senders):
        return False
    include_keywords = filters.get("keywords") or []
    include_subject = filters.get("subject_keywords") or []
    include_sender_kw = filters.get("sender_keywords") or []
    if not (include_keywords or include_subject or include_sender_kw):
        return True
    text = f"{subject}\n{sender}\n{body}".lower()
    return any(k.lower() in text for k in include_keywords + include_subject + include_sender_kw)


def poll_account(db_path: Path, account: AccountSpec, lookback: int = 30) -> Dict[str, Any]:
    if not account.enabled:
        return {"account": account.name, "skipped": True, "reason": "disabled"}
    if not account.username or not account.password:
        return {"account": account.name, "skipped": True, "reason": "missing credentials"}

    processed = 0
    found = 0
    last_uid = get_last_uid(db_path, account.name)
    try:
        if account.imap_ssl:
            client = imaplib.IMAP4_SSL(account.imap_host, account.imap_port, timeout=25)
        else:
            client = imaplib.IMAP4(account.imap_host, account.imap_port, timeout=25)
        try:
            client.login(account.username, account.password)
            if account.provider in {"163", "126", "yeah"} or account.imap_host.endswith(".163.com") or account.imap_host.endswith(".126.com") or account.imap_host.endswith(".yeah.net"):
                # NetEase mailboxes may accept LOGIN but reject SELECT with
                # "Unsafe Login" unless the client identifies itself first.
                # Python imaplib does not enable ID in AUTH state by default.
                imaplib.Commands.setdefault("ID", ("AUTH", "SELECTED"))
                client._simple_command("ID", '("name" "HermesEmailOTP" "version" "1.0" "vendor" "Hermes" "contact" "hermes-local")')
            folder = account.folder or "INBOX"
            status, select_data = client.select(folder)
            if status != "OK" and folder.upper() != "INBOX":
                status, select_data = client.select("INBOX")
                folder = "INBOX"
            if status != "OK":
                # Include the IMAP server's actual response so the WebUI can show
                # whether this is a disabled IMAP service, missing auth-code
                # permission, or a provider-specific folder namespace issue.
                detail = [x.decode("utf-8", "replace") if isinstance(x, bytes) else str(x) for x in (select_data or [])]
                raise RuntimeError(f"SELECT folder failed: {folder}; server_response={detail}")
            if last_uid > 0:
                criteria = f"UID {last_uid + 1}:*"
            else:
                criteria = "ALL"
            status, data = client.uid("SEARCH", None, criteria)
            if status != "OK":
                raise RuntimeError(f"SEARCH failed: {status}")
            uid_list = [u.decode() for u in data[0].split() if u]
            if last_uid <= 0 and len(uid_list) > lookback:
                uid_list = uid_list[-lookback:]
            for uid in uid_list:
                processed += 1
                status, msg_data = client.uid("FETCH", uid, "(RFC822)")
                if status != "OK" or not msg_data or not msg_data[0]:
                    continue
                raw = msg_data[0][1]
                parsed = email.message_from_bytes(raw, policy=email.policy.default)
                subject = decode_mime(parsed.get("Subject"))
                sender = decode_mime(parsed.get("From"))
                recipient = decode_mime(parsed.get("To"))
                msg_date = decode_mime(parsed.get("Date"))
                message_id = decode_mime(parsed.get("Message-ID"))
                body = fetch_body_from_message(parsed)
                snippet = body[:500]
                if not message_matches_filters(subject, sender, body, account.filters):
                    continue
                code, reason, code_score = extract_code(subject, sender, body)
                score = score_message(subject, sender, body, account.filters)
                if code:
                    found += 1
                save_message(db_path, {
                    "account_name": account.name,
                    "uid": int(uid),
                    "message_id": message_id,
                    "sender": sender,
                    "recipient": recipient,
                    "subject": subject,
                    "date": msg_date,
                    "received_at": utc_now(),
                    "snippet": snippet,
                    "body": body,
                    "code": code,
                    "code_reason": reason,
                    "score": score + code_score,
                    "raw_headers": json.dumps({"Subject": subject, "From": sender, "To": recipient, "Date": msg_date}, ensure_ascii=False),
                })
        finally:
            try:
                client.logout()
            except Exception:
                pass
        return {"account": account.name, "processed": processed, "found": found, "last_uid": last_uid}
    except Exception as e:
        set_account_error(db_path, account.name, repr(e))
        return {"account": account.name, "processed": processed, "found": found, "error": repr(e)}


def poll_all_accounts(db_path: Path, config: Dict[str, Any], accounts: Optional[List[str]] = None) -> Dict[str, Any]:
    results = []
    for raw in config.get("accounts", []):
        account = parse_account(raw)
        if accounts and account.name not in accounts:
            continue
        if not account.enabled:
            continue
        upsert_account(db_path, account)
        results.append(poll_account(db_path, account, lookback=int(config.get("lookback_messages", 30))))
    errors = [r for r in results if isinstance(r, dict) and r.get("error")]
    return {"ok": not errors, "results": results, "error_count": len(errors)}


def refresh_has_errors(result: Any) -> bool:
    """Return True if a nested refresh result contains errors."""
    if isinstance(result, dict):
        if result.get("ok") is False or result.get("error"):
            return True
        return any(refresh_has_errors(v) for v in result.values())
    if isinstance(result, list):
        return any(refresh_has_errors(v) for v in result)
    return False


def query_messages(db_path: Path, account: Optional[str] = None, sender: Optional[str] = None, keyword: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
    conn = open_db(db_path)
    try:
        clauses = []
        params: List[Any] = []
        if account:
            clauses.append("account_name = ?")
            params.append(account)
        if sender:
            clauses.append("sender LIKE ?")
            params.append(f"%{sender}%")
        if keyword:
            clauses.append("(subject LIKE ? OR sender LIKE ? OR body LIKE ? OR COALESCE(code, '') LIKE ?)")
            kw = f"%{keyword}%"
            params.extend([kw, kw, kw, kw])
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = conn.execute(
            f"SELECT * FROM messages {where} ORDER BY received_at DESC, id DESC LIMIT ?",
            (*params, limit),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def latest_code(db_path: Path, account: Optional[str] = None, sender: Optional[str] = None, keyword: Optional[str] = None) -> Optional[Dict[str, Any]]:
    rows = query_messages(db_path, account=account, sender=sender, keyword=keyword, limit=50)
    for row in rows:
        if row.get("code"):
            return row
    return rows[0] if rows else None


class OTPHandler(BaseHTTPRequestHandler):
    server_version = "EmailOTPService/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        server: "OTPServer" = self.server  # type: ignore[assignment]
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query)
        if parsed.path == "/health":
            self._send_json(200, {
                "ok": True,
                "time": utc_now(),
                "accounts": len(list_accounts(server.db_path)),
            })
            return
        if parsed.path == "/accounts":
            self._send_json(200, {"ok": True, "accounts": list_accounts(server.db_path)})
            return
        if parsed.path == "/messages":
            account = q.get("account", [None])[0]
            sender = q.get("sender", [None])[0]
            keyword = q.get("keyword", [None])[0]
            limit = int(q.get("limit", [20])[0])
            self._send_json(200, {"ok": True, "messages": query_messages(server.db_path, account=account, sender=sender, keyword=keyword, limit=limit)})
            return
        if parsed.path == "/latest":
            account = q.get("account", [None])[0]
            sender = q.get("sender", [None])[0]
            keyword = q.get("keyword", [None])[0]
            row = latest_code(server.db_path, account=account, sender=sender, keyword=keyword)
            self._send_json(200, {"ok": True, "message": row})
            return
        self._send_json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:
        server: "OTPServer" = self.server  # type: ignore[assignment]
        parsed = urlparse(self.path)
        if parsed.path == "/refresh":
            length = int(self.headers.get("Content-Length", "0") or 0)
            data = {}
            if length:
                raw = self.rfile.read(length).decode("utf-8")
                if raw.strip():
                    data = json.loads(raw)
            target_accounts = data.get("accounts") or data.get("mailboxes")
            if isinstance(target_accounts, str):
                target_accounts = [target_accounts]
            cfg = load_config(server.config_path) if getattr(server, "config_path", None) else server.config
            server.config = cfg
            graph_cfg = cfg.get("graph_application") or {}
            graph_boxes = set(graph_cfg.get("mailboxes") or [])
            graph_accounts = {normalize_account_name(m): m for m in graph_boxes}
            results = []
            if target_accounts:
                graph_targets = []
                imap_targets = []
                for target in target_accounts:
                    if target in graph_boxes:
                        graph_targets.append(target)
                    elif target in graph_accounts:
                        graph_targets.append(graph_accounts[target])
                    else:
                        imap_targets.append(target)
                if graph_targets and graph_cfg.get("enabled"):
                    results.append(graph_refresh(server.db_path, cfg, mailboxes=graph_targets))
                if imap_targets:
                    # poll_all_accounts expects account names, not email addresses; accept both.
                    name_map = {}
                    for raw_account in cfg.get("accounts", []):
                        name = raw_account.get("name")
                        username = raw_account.get("username") or raw_account.get("email")
                        if name:
                            name_map[name] = name
                        if username:
                            name_map[username] = name
                    mapped = [name_map.get(x, x) for x in imap_targets]
                    results.append(poll_all_accounts(server.db_path, cfg, accounts=mapped))
            else:
                if graph_cfg.get("enabled"):
                    results.append(graph_refresh(server.db_path, cfg))
                if cfg.get("accounts"):
                    results.append(poll_all_accounts(server.db_path, cfg))
            has_errors = refresh_has_errors(results)
            result = {"ok": not has_errors, "results": results}
            if has_errors:
                result["error"] = "部分邮箱刷新失败，请查看账户状态详情"
            self._send_json(200, result)
            return
        self._send_json(404, {"ok": False, "error": "not found"})


class OTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, db_path: Path, config: Dict[str, Any], config_path: Optional[Path] = None):
        super().__init__(server_address, RequestHandlerClass)
        self.db_path = db_path
        self.config = config
        self.config_path = config_path
        self.stop_event = threading.Event()
        self.poll_threads: List[threading.Thread] = []


def poll_loop(db_path: Path, config: Dict[str, Any], stop_event: threading.Event) -> None:
    poll_interval = int(config.get("poll_interval", 60))
    while not stop_event.is_set():
        start = time.time()
        try:
            if (config.get("graph_application") or {}).get("enabled"):
                graph_refresh(db_path, config)
            else:
                poll_all_accounts(db_path, config)
        except Exception as e:
            print(json.dumps({"ok": False, "error": repr(e)}, ensure_ascii=False))
        elapsed = time.time() - start
        wait = max(5, poll_interval - int(elapsed))
        stop_event.wait(wait)


def ensure_example_config(path: Path) -> None:
    if path.exists():
        return
    ensure_dir(path)
    example = {
        "http_host": "127.0.0.1",
        "http_port": 8088,
        "poll_interval": 60,
        "lookback_messages": 30,
        "graph_application": {
            "enabled": False,
            "tenant_id": "",
            "client_id": "",
            "client_secret": "",
            "mailboxes": []
        },
        "accounts": [
            {
                "name": "my_163_mail",
                "provider": "163",
                "username": "user@example.com",
                "password": "your_app_password_or_mail_password",
                "imap": {"host": "imap.163.com", "port": 993, "ssl": True, "folder": "INBOX"},
                "poll_interval": 60,
                "enabled": True,
                "filters": {
                    "senders": ["no-reply"],
                    "keywords": ["验证码", "verification", "code"],
                    "subject_keywords": ["验证码", "verification"],
                    "sender_keywords": ["service"]
                }
            },
            {
                "name": "my_outlook_mail",
                "provider": "outlook",
                "username": "user@example.com",
                "password": "your_password",
                "imap": {"host": "outlook.office365.com", "port": 993, "ssl": True, "folder": "INBOX"},
                "poll_interval": 60,
                "enabled": True,
                "filters": {
                    "keywords": ["verification", "security code", "otp"]
                }
            }
        ]
    }
    save_json(path, example)


def cmd_init(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    ensure_example_config(config_path)
    print(f"Config template ready: {config_path}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    db_path = Path(args.db).expanduser()
    init_db(db_path)
    ensure_example_config(config_path)
    config = load_config(config_path)
    for raw in config.get("accounts", []):
        try:
            upsert_account(db_path, parse_account(raw))
        except Exception as e:
            print(json.dumps({"account": raw.get("name"), "error": repr(e)}, ensure_ascii=False))
    host = args.host or config.get("http_host", DEFAULT_HOST)
    port = int(args.port or config.get("http_port", DEFAULT_PORT))

    server = OTPServer((host, port), OTPHandler, db_path=db_path, config=config, config_path=config_path)
    poller = threading.Thread(target=poll_loop, args=(db_path, config, server.stop_event), daemon=True)
    poller.start()
    server.poll_threads.append(poller)
    print(json.dumps({"ok": True, "message": "service started", "host": host, "port": port, "config": str(config_path), "db": str(db_path)}, ensure_ascii=False))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop_event.set()
        server.server_close()
    return 0


def cmd_refresh(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    db_path = Path(args.db).expanduser()
    init_db(db_path)
    config = load_config(config_path)
    if (config.get("graph_application") or {}).get("enabled"):
        result = graph_refresh(db_path, config, mailboxes=args.accounts)
    else:
        result = poll_all_accounts(db_path, config, accounts=args.accounts)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    config_path = Path(args.config).expanduser()
    db_path = Path(args.db).expanduser()
    init_db(db_path)
    config = load_config(config_path)
    for raw in config.get("accounts", []):
        account = parse_account(raw)
        upsert_account(db_path, account)
    print(json.dumps({"ok": True, "accounts": list_accounts(db_path)}, ensure_ascii=False, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local multi-mailbox OTP service")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="Config JSON path")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite DB path")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init-config", help="Create an example config file if missing")
    p_init.set_defaults(func=cmd_init)

    p_serve = sub.add_parser("serve", help="Run the HTTP service and background poller")
    p_serve.add_argument("--host", default=None, help="HTTP bind host")
    p_serve.add_argument("--port", type=int, default=None, help="HTTP bind port")
    p_serve.set_defaults(func=cmd_serve)

    p_refresh = sub.add_parser("refresh", help="Poll mailboxes once and exit")
    p_refresh.add_argument("--accounts", nargs="*", help="Optional account names to refresh")
    p_refresh.set_defaults(func=cmd_refresh)

    p_list = sub.add_parser("list", help="Show configured accounts and stored metadata")
    p_list.set_defaults(func=cmd_list)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
