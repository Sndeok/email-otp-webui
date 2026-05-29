#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import imaplib
import poplib
import smtplib
import json
import os
import secrets
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from flask import Flask, jsonify, redirect, request, session

CONFIG_PATH = Path(os.environ.get("EMAIL_OTP_CONFIG", str(Path.home() / ".config" / "hermes" / "email_otp_service.json")))
DB_PATH = Path(os.environ.get("EMAIL_OTP_DB", str(Path.home() / ".local" / "share" / "hermes" / "email_otp_service.sqlite3")))
REFRESH_URL = os.environ.get("EMAIL_OTP_REFRESH_URL", "http://127.0.0.1:8088/refresh")
SECRET_PATH = Path(os.environ.get("EMAIL_OTP_WEBUI_SECRET", str(Path.home() / ".config" / "hermes" / "email_otp_webui.secret")))
APP = Flask(__name__)

MAIL_PROVIDER_PRESETS = {'163': {'label': '网易 163', 'imap_host': 'imap.163.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.163.com', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.163.com', 'pop3_port': 995, 'pop3_ssl': True}, '126': {'label': '网易 126', 'imap_host': 'imap.126.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.126.com', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.126.com', 'pop3_port': 995, 'pop3_ssl': True}, 'yeah': {'label': '网易 yeah.net', 'imap_host': 'imap.yeah.net', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.yeah.net', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.yeah.net', 'pop3_port': 995, 'pop3_ssl': True}, 'qq': {'label': 'QQ 邮箱', 'imap_host': 'imap.qq.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.qq.com', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.qq.com', 'pop3_port': 995, 'pop3_ssl': True}, 'foxmail': {'label': 'Foxmail', 'imap_host': 'imap.qq.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.qq.com', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.qq.com', 'pop3_port': 995, 'pop3_ssl': True}, 'outlook': {'label': 'Outlook / Microsoft 365', 'imap_host': 'outlook.office365.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.office365.com', 'smtp_port': 587, 'smtp_ssl': False, 'pop3_host': 'outlook.office365.com', 'pop3_port': 995, 'pop3_ssl': True}, 'gmail': {'label': 'Gmail', 'imap_host': 'imap.gmail.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.gmail.com', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.gmail.com', 'pop3_port': 995, 'pop3_ssl': True}, 'icloud': {'label': 'iCloud Mail', 'imap_host': 'imap.mail.me.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.mail.me.com', 'smtp_port': 587, 'smtp_ssl': False, 'pop3_host': '', 'pop3_port': 995, 'pop3_ssl': True}, 'yahoo': {'label': 'Yahoo Mail', 'imap_host': 'imap.mail.yahoo.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.mail.yahoo.com', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.mail.yahoo.com', 'pop3_port': 995, 'pop3_ssl': True}, 'sina': {'label': '新浪邮箱', 'imap_host': 'imap.sina.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.sina.com', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.sina.com', 'pop3_port': 995, 'pop3_ssl': True}, 'sohu': {'label': '搜狐邮箱', 'imap_host': 'imap.sohu.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.sohu.com', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop3.sohu.com', 'pop3_port': 995, 'pop3_ssl': True}, '189': {'label': '189 邮箱', 'imap_host': 'imap.189.cn', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.189.cn', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.189.cn', 'pop3_port': 995, 'pop3_ssl': True}, 'aliyun': {'label': '阿里邮箱', 'imap_host': 'imap.qiye.aliyun.com', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': 'smtp.qiye.aliyun.com', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': 'pop.qiye.aliyun.com', 'pop3_port': 995, 'pop3_ssl': True}, 'custom': {'label': '自定义', 'imap_host': '', 'imap_port': 993, 'imap_ssl': True, 'smtp_host': '', 'smtp_port': 465, 'smtp_ssl': True, 'pop3_host': '', 'pop3_port': 995, 'pop3_ssl': True}}


def ensure_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def password_hash(password: str, salt: Optional[str] = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260000).hex()
    return f"pbkdf2_sha256${salt}${digest}"


DEFAULT_ADMIN_PASSWORD_HASH = "pbkdf2_sha256$email_otp_webui_default_admin123$e2efc88acc15323d148fdc66fcf79c807af4276c8f6f7d6c483b960b65b64d74"

def normalized_password_hash(stored: str) -> str:
    if not stored or stored == "CHANGE_ME" or stored.count("$") != 2:
        return DEFAULT_ADMIN_PASSWORD_HASH
    return stored

def verify_password(password: str, stored: str) -> bool:
    stored = normalized_password_hash(stored)
    try:
        alg, salt, _ = stored.split("$", 2)
    except ValueError:
        return False
    return alg == "pbkdf2_sha256" and hmac.compare_digest(password_hash(password, salt), stored)


def secret_key() -> str:
    ensure_dir(SECRET_PATH)
    if SECRET_PATH.exists():
        return SECRET_PATH.read_text(encoding="utf-8").strip()
    key = secrets.token_urlsafe(48)
    SECRET_PATH.write_text(key, encoding="utf-8")
    os.chmod(SECRET_PATH, 0o600)
    return key


APP.secret_key = secret_key()


def default_webui() -> Dict[str, Any]:
    return {"admin": {"username": "admin", "password_hash": "pbkdf2_sha256$email_otp_webui_default_admin123$e2efc88acc15323d148fdc66fcf79c807af4276c8f6f7d6c483b960b65b64d74"}, "theme": "system", "proxy": {"enabled": False, "http_proxy": "", "https_proxy": "", "no_proxy": "127.0.0.1,localhost"}}


def load_config() -> Dict[str, Any]:
    cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8")) if CONFIG_PATH.exists() else {}
    changed = False
    if "webui" not in cfg:
        cfg["webui"] = default_webui(); changed = True
    if "admin" not in cfg["webui"]:
        cfg["webui"]["admin"] = default_webui()["admin"]; changed = True
    if "theme" not in cfg["webui"]:
        cfg["webui"]["theme"] = "system"; changed = True
    if "proxy" not in cfg["webui"]:
        cfg["webui"]["proxy"] = default_webui()["proxy"]; changed = True
    cfg.setdefault("graph_application", {}).setdefault("mailboxes", [])
    cfg.setdefault("poll_interval", 60)
    cfg.setdefault("lookback_messages", 30)
    if changed:
        save_config(cfg)
    return cfg


def save_config(cfg: Dict[str, Any]) -> None:
    ensure_dir(CONFIG_PATH)
    tmp = CONFIG_PATH.with_suffix(CONFIG_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(CONFIG_PATH)
    os.chmod(CONFIG_PATH, 0o600)


def sanitized_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    data = json.loads(json.dumps(cfg, ensure_ascii=False))
    graph = data.get("graph_application") or {}
    admin = (data.get("webui") or {}).get("admin") or {}
    if graph.get("client_secret"):
        graph["client_secret"] = "***"
    if admin.get("password_hash"):
        admin["password_hash"] = "***"
    return data



def redact_account(account: Dict[str, Any]) -> Dict[str, Any]:
    data = json.loads(json.dumps(account, ensure_ascii=False))
    if data.get("password"):
        data["password"] = "***"
    return data


def sanitized_accounts(cfg: Dict[str, Any]) -> list[Dict[str, Any]]:
    return [redact_account(a) for a in cfg.get("accounts", [])]


def test_mail_account(account: Dict[str, Any], protocol: str = "imap") -> Dict[str, Any]:
    username = account.get("username") or account.get("email") or ""
    password = account.get("password") or ""
    imap = account.get("imap") or {}
    smtp = account.get("smtp") or {}
    pop3 = account.get("pop3") or {}
    if protocol == "imap":
        host, port, use_ssl = imap.get("host"), int(imap.get("port") or 993), bool(imap.get("ssl", True))
        client = imaplib.IMAP4_SSL(host, port, timeout=25) if use_ssl else imaplib.IMAP4(host, port, timeout=25)
        try:
            client.login(username, password)
            send_netease_imap_id(client, account)
            folder = (imap.get("folder") or account.get("folder") or "INBOX")
            status, select_data = client.select(folder)
            if status != "OK" and str(folder).upper() != "INBOX":
                status, select_data = client.select("INBOX")
                folder = "INBOX"
            if status != "OK":
                detail = [x.decode("utf-8", "replace") if isinstance(x, bytes) else str(x) for x in (select_data or [])]
                raise RuntimeError(f"IMAP SELECT failed: {folder}; server_response={detail}")
            typ, boxes = client.list()
            return {"protocol": "imap", "ok": True, "host": host, "port": port, "folder": folder, "mailboxes": len(boxes or [])}
        finally:
            try: client.logout()
            except Exception: pass
    if protocol == "pop3":
        host, port, use_ssl = pop3.get("host"), int(pop3.get("port") or 995), bool(pop3.get("ssl", True))
        client = poplib.POP3_SSL(host, port, timeout=20) if use_ssl else poplib.POP3(host, port, timeout=20)
        try:
            client.user(username)
            client.pass_(password)
            count, size = client.stat()
            return {"protocol": "pop3", "ok": True, "host": host, "port": port, "messages": count, "size": size}
        finally:
            try: client.quit()
            except Exception: pass
    if protocol == "smtp":
        host, port, use_ssl = smtp.get("host"), int(smtp.get("port") or 465), bool(smtp.get("ssl", True))
        client = smtplib.SMTP_SSL(host, port, timeout=20) if use_ssl else smtplib.SMTP(host, port, timeout=20)
        try:
            if not use_ssl and port == 587:
                client.starttls()
            client.login(username, password)
            return {"protocol": "smtp", "ok": True, "host": host, "port": port}
        finally:
            try: client.quit()
            except Exception: pass
    raise ValueError("unsupported protocol")

def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def fetch_accounts():
    cfg = load_config()
    configured_imap_names = set()
    configured_imap_users = set()
    for a in cfg.get("accounts", []):
        name = a.get("name") or (a.get("username") or a.get("email") or "").replace("@", "_").replace(".", "_")
        username = a.get("username") or a.get("email") or ""
        if name:
            configured_imap_names.add(name)
        if username:
            configured_imap_users.add(username)

    graph_mailboxes = set((cfg.get("graph_application") or {}).get("mailboxes") or [])
    graph_names = {m.replace("@", "_").replace(".", "_") for m in graph_mailboxes}
    rows = []
    if DB_PATH.exists():
        conn = db_conn()
        try:
            for r in conn.execute("SELECT name, provider, username, imap_host, poll_interval, enabled, last_uid, last_error, updated_at FROM accounts ORDER BY name").fetchall():
                row = dict(r)
                name = row.get("name") or ""
                username = row.get("username") or ""
                # Graph accounts are DB-backed; IMAP/POP/SMTP accounts must still
                # exist in config. This prevents deleted IMAP accounts from
                # lingering in the query list just because old local mail exists.
                if name in configured_imap_names or username in configured_imap_users or username in graph_mailboxes or name in graph_names:
                    rows.append(row)
        finally:
            conn.close()
    seen = {r.get("name") for r in rows}
    for mailbox in sorted(graph_mailboxes, key=str.lower):
        name = mailbox.replace("@", "_")
        normalized_name = mailbox.replace("@", "_").replace(".", "_")
        if name not in seen and normalized_name not in seen and mailbox not in seen:
            rows.append({
                "name": name,
                "provider": "graph_application",
                "username": mailbox,
                "imap_host": "Microsoft Graph",
                "poll_interval": cfg.get("poll_interval") or 60,
                "enabled": 1,
                "last_uid": 0,
                "last_error": "未刷新；点击刷新后会读取",
                "updated_at": "config",
            })
            seen.add(name)
    for a in cfg.get("accounts", []):
        name = a.get("name") or (a.get("username") or a.get("email") or "").replace("@", "_").replace(".", "_")
        if name and name not in seen:
            imap = a.get("imap") or {}
            rows.append({
                "name": name,
                "provider": a.get("provider") or "imap",
                "username": a.get("username") or a.get("email") or name,
                "imap_host": imap.get("host"),
                "poll_interval": a.get("poll_interval") or cfg.get("poll_interval") or 60,
                "enabled": 1 if a.get("enabled", True) else 0,
                "last_uid": 0,
                "last_error": "未轮询；点击刷新后会读取",
                "updated_at": "config",
            })
    return sorted(rows, key=lambda x: (x.get("username") or x.get("name") or "").lower())


def account_variants(value: str) -> set[str]:
    value = str(value or "").strip()
    if not value:
        return set()
    bases = {value}
    # Historical Graph DB names used "@" -> "_" while keeping dots.
    # Some UI/config paths use a fully normalized form with both "@" and "." -> "_".
    # If we receive that full-underscore form, reconstruct the likely mailbox by
    # treating the first underscore as "@" and the remaining underscores as dots.
    if "@" not in value and "_" in value:
        local, _, domain = value.partition("_")
        if local and domain and "_" in domain:
            bases.add(local + "@" + domain.replace("_", "."))
    variants: set[str] = set()
    for base in bases:
        variants.add(base)
        variants.add(base.replace("@", "_"))
        variants.add(base.replace("@", "_").replace(".", "_"))
    return variants


def configured_account_names(cfg: Optional[Dict[str, Any]] = None) -> set[str]:
    cfg = cfg or load_config()
    names: set[str] = set()
    for account in cfg.get("accounts", []) or []:
        username = account.get("username") or account.get("email") or ""
        name = account.get("name") or username.replace("@", "_").replace(".", "_")
        names.update(account_variants(name))
        names.update(account_variants(username))
    for mailbox in ((cfg.get("graph_application") or {}).get("mailboxes") or []):
        names.update(account_variants(mailbox))
    return names


def cleanup_cached_accounts(names: Iterable[str]) -> int:
    names = {str(x or "").strip() for x in names if str(x or "").strip()}
    if not names or not DB_PATH.exists():
        return 0
    conn = db_conn()
    deleted = 0
    try:
        for name in names:
            variants = {name, name.replace("@", "_").replace(".", "_")}
            for v in variants:
                cur = conn.execute("DELETE FROM messages WHERE account_name=? OR recipient=?", (v, v))
                deleted += cur.rowcount if cur.rowcount and cur.rowcount > 0 else 0
                conn.execute("DELETE FROM accounts WHERE name=? OR username=?", (v, v))
        conn.commit()
    finally:
        conn.close()
    return deleted


def cleanup_orphan_cache() -> int:
    allowed = configured_account_names()
    if allowed or not DB_PATH.exists():
        return 0
    conn = db_conn()
    try:
        msg_count = conn.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        conn.execute("DELETE FROM messages")
        conn.execute("DELETE FROM accounts")
        conn.commit()
        return int(msg_count or 0)
    finally:
        conn.close()


def fetch_messages(account=None, keyword=None, sender=None, limit=20):
    if not DB_PATH.exists():
        return []
    allowed = configured_account_names()
    # If all mailbox/account configs were deleted, do not show stale cached OTPs.
    if not allowed:
        return []
    selected_variants = account_variants(account) if account else set()
    if account and not (selected_variants & allowed):
        return []
    conn = db_conn()
    clauses = []
    params = []
    try:
        if account:
            values = sorted(selected_variants)
            placeholders = ",".join("?" for _ in values)
            clauses.append(f"(account_name IN ({placeholders}) OR recipient IN ({placeholders}))")
            params.extend(values)
            params.extend(values)
        else:
            values = sorted(allowed)
            placeholders = ",".join("?" for _ in values)
            clauses.append(f"(account_name IN ({placeholders}) OR recipient IN ({placeholders}))")
            params.extend(values)
            params.extend(values)
        if sender:
            clauses.append("sender LIKE ?")
            params.append(f"%{sender}%")
        if keyword:
            clauses.append("(subject LIKE ? OR sender LIKE ? OR body LIKE ? OR COALESCE(code, '') LIKE ?)")
            kw = f"%{keyword}%"
            params += [kw, kw, kw, kw]
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        rows = conn.execute(f"SELECT * FROM messages {where} ORDER BY received_at DESC, id DESC LIMIT ?", (*params, limit)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()



def proxy_opener():
    proxy = (load_config().get("webui") or {}).get("proxy") or {}
    if not proxy.get("enabled"):
        return urllib.request.build_opener()
    proxies = {}
    if proxy.get("http_proxy"):
        proxies["http"] = proxy.get("http_proxy")
    if proxy.get("https_proxy"):
        proxies["https"] = proxy.get("https_proxy")
    return urllib.request.build_opener(urllib.request.ProxyHandler(proxies))


def test_proxy_connection(url: str = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration") -> Dict[str, Any]:
    opener = proxy_opener()
    req = urllib.request.Request(url, headers={"User-Agent": "HermesEmailOTPWebUI/1.0"})
    with opener.open(req, timeout=12) as resp:
        data = resp.read(300).decode("utf-8", "replace")
        return {"status": resp.status, "url": url, "sample": data[:120]}

def graph_token() -> str:
    cfg = load_config()
    g = cfg.get("graph_application") or {}
    form = urllib.parse.urlencode({
        "client_id": g.get("client_id", ""),
        "client_secret": g.get("client_secret", ""),
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    req = urllib.request.Request(
        f"https://login.microsoftonline.com/{g.get('tenant_id')}/oauth2/v2.0/token",
        data=form,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with proxy_opener().open(req, timeout=30) as resp:
        return json.loads(resp.read().decode())["access_token"]


def find_imap_account(account_name: str) -> Optional[Dict[str, Any]]:
    cfg = load_config()
    for account in cfg.get("accounts", []):
        name = account.get("name") or (account.get("username") or account.get("email") or "").replace("@", "_").replace(".", "_")
        if name == account_name or account.get("username") == account_name or account.get("email") == account_name:
            return account
    return None


def send_netease_imap_id(client: imaplib.IMAP4, account: Dict[str, Any]) -> None:
    provider = str(account.get("provider") or "").lower()
    imap_cfg = account.get("imap") or {}
    host = str(imap_cfg.get("host") or "")
    if provider in {"163", "126", "yeah"} or host.endswith(".163.com") or host.endswith(".126.com") or host.endswith(".yeah.net"):
        imaplib.Commands.setdefault("ID", ("AUTH", "SELECTED"))
        client._simple_command("ID", '("name" "HermesEmailOTP" "version" "1.0" "vendor" "Hermes" "contact" "hermes-local")')


def imap_move_or_delete_message(row: sqlite3.Row) -> Dict[str, Any]:
    account_name = row["account_name"]
    uid = int(row["uid"])
    account = find_imap_account(account_name)
    if not account:
        raise ValueError(f"imap account config not found: {account_name}")
    username = account.get("username") or account.get("email") or ""
    password = account.get("password") or ""
    imap_cfg = account.get("imap") or {}
    host = imap_cfg.get("host") or ""
    port = int(imap_cfg.get("port") or 993)
    use_ssl = bool(imap_cfg.get("ssl", True))
    folder = imap_cfg.get("folder") or account.get("folder") or "INBOX"
    if not (username and password and host):
        raise ValueError("imap account missing username/password/host")
    client = imaplib.IMAP4_SSL(host, port, timeout=25) if use_ssl else imaplib.IMAP4(host, port, timeout=25)
    try:
        client.login(username, password)
        send_netease_imap_id(client, account)
        status, data = client.select(folder)
        if status != "OK":
            detail = [x.decode("utf-8", "replace") if isinstance(x, bytes) else str(x) for x in (data or [])]
            raise RuntimeError(f"IMAP SELECT failed: {folder}; server_response={detail}")
        moved_to = None
        last_move_error = None
        for trash in ("Deleted Items", "Trash", "已删除邮件", "Deleted Messages"):
            try:
                status, data = client.uid("MOVE", str(uid), trash)
                if status == "OK":
                    moved_to = trash
                    break
                last_move_error = data
            except Exception as e:
                last_move_error = repr(e)
        if not moved_to:
            status, data = client.uid("STORE", str(uid), "+FLAGS", r"(\Deleted)")
            if status != "OK":
                raise RuntimeError(f"IMAP delete failed: uid={uid}; move_error={last_move_error}; store_response={data}")
            client.expunge()
        return {"id": row["id"], "account": account_name, "uid": uid, "method": "imap-move" if moved_to else "imap-delete", "folder": moved_to}
    finally:
        try:
            client.logout()
        except Exception:
            pass


def move_message_to_deleted(local_id: int) -> Dict[str, Any]:
    conn = db_conn()
    try:
        row = conn.execute("SELECT id, account_name, uid, raw_headers FROM messages WHERE id=?", (local_id,)).fetchone()
        if not row:
            raise ValueError("message not found")
        raw = json.loads(row["raw_headers"] or "{}")
        mailbox = raw.get("mailbox")
        graph_id = raw.get("graph_id")
        if not mailbox or not graph_id:
            result = imap_move_or_delete_message(row)
            conn.execute("DELETE FROM messages WHERE id=?", (local_id,))
            conn.commit()
            return result
    finally:
        conn.close()
    token = graph_token()
    url = f"https://graph.microsoft.com/v1.0/users/{urllib.parse.quote(mailbox)}/messages/{urllib.parse.quote(graph_id)}/move"
    body = json.dumps({"destinationId": "deleteditems"}).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with proxy_opener().open(req, timeout=30) as resp:
            moved = json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")
        raise RuntimeError(f"Graph delete failed HTTP {e.code}: {detail[:1000]}") from e
    conn = db_conn()
    try:
        conn.execute("DELETE FROM messages WHERE id=?", (local_id,))
        conn.commit()
    finally:
        conn.close()
    return {"id": local_id, "mailbox": mailbox, "moved_id": moved.get("id")}


def require_login(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("admin_logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            return redirect("/login")
        return fn(*args, **kwargs)
    return wrapper


LOGIN_HTML = """<!doctype html>
<html lang="zh-CN" data-theme="system">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 - 邮箱验证码中心</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='10' y1='8' x2='54' y2='58' gradientUnits='userSpaceOnUse'%3E%3Cstop stop-color='%2338bdf8'/%3E%3Cstop offset='1' stop-color='%2334d399'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='64' height='64' rx='18' fill='%2307111f'/%3E%3Cpath d='M14 22.5A6.5 6.5 0 0 1 20.5 16h23A6.5 6.5 0 0 1 50 22.5v19A6.5 6.5 0 0 1 43.5 48h-23A6.5 6.5 0 0 1 14 41.5v-19Z' fill='url(%23g)'/%3E%3Cpath d='m18 22 14 11 14-11' fill='none' stroke='white' stroke-width='5' stroke-linecap='round' stroke-linejoin='round'/%3E%3Ccircle cx='47' cy='18' r='8' fill='%23fbbf24' stroke='%2307111f' stroke-width='4'/%3E%3Cpath d='M47 14v5' stroke='%2307111f' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
:root{color-scheme:dark;--bg:#07111f;--bg2:#0b1220;--panel:rgba(15,23,42,.78);--panel2:rgba(15,23,42,.54);--line:rgba(148,163,184,.22);--text:#e5eefc;--muted:#91a3bd;--accent:#38bdf8;--accent2:#34d399;--bad:#fb7185;--input:rgba(2,6,23,.62);--shadow:rgba(0,0,0,.42);--focus:rgba(56,189,248,.24);--selectBg:rgba(15,23,42,.78);--selectArrow:%2391a3bd}
html[data-theme="light"]{color-scheme:light;--bg:#f6f8fc;--bg2:#e9effa;--panel:rgba(255,255,255,.88);--panel2:rgba(255,255,255,.66);--line:rgba(15,23,42,.13);--text:#0f172a;--muted:#64748b;--accent:#2563eb;--accent2:#059669;--bad:#e11d48;--input:rgba(255,255,255,.92);--shadow:rgba(51,65,85,.18);--focus:rgba(37,99,235,.16);--selectBg:rgba(255,255,255,.86);--selectArrow:%2364748b}
@media(prefers-color-scheme:light){html[data-theme="system"]{color-scheme:light;--bg:#f6f8fc;--bg2:#e9effa;--panel:rgba(255,255,255,.88);--panel2:rgba(255,255,255,.66);--line:rgba(15,23,42,.13);--text:#0f172a;--muted:#64748b;--accent:#2563eb;--accent2:#059669;--bad:#e11d48;--input:rgba(255,255,255,.92);--shadow:rgba(51,65,85,.18);--focus:rgba(37,99,235,.16);--selectBg:rgba(255,255,255,.86);--selectArrow:%2364748b}}
*{box-sizing:border-box}html,body{min-height:100%}body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;color:var(--text);background:radial-gradient(circle at 14% 12%,rgba(56,189,248,.22),transparent 25rem),radial-gradient(circle at 88% 18%,rgba(52,211,153,.16),transparent 25rem),linear-gradient(145deg,var(--bg),var(--bg2));display:grid;place-items:center;padding:28px;overflow-x:hidden}.shell{width:min(960px,100%);display:grid;grid-template-columns:minmax(0,1.05fr) minmax(360px,.95fr);gap:22px;align-items:stretch}.hero,.card{border:1px solid var(--line);background:linear-gradient(180deg,var(--panel),var(--panel2));box-shadow:0 28px 90px var(--shadow),inset 0 1px 0 rgba(255,255,255,.14);backdrop-filter:blur(22px) saturate(150%);-webkit-backdrop-filter:blur(22px) saturate(150%);border-radius:32px}.hero{position:relative;overflow:hidden;padding:34px;min-height:470px;display:flex;flex-direction:column;justify-content:space-between}.hero:before{content:"";position:absolute;inset:auto -80px -120px auto;width:280px;height:280px;border-radius:999px;background:linear-gradient(135deg,rgba(56,189,248,.28),rgba(52,211,153,.20));filter:blur(8px)}.brand{position:relative;display:flex;align-items:center;gap:13px}.logo{width:48px;height:48px;border-radius:18px;display:grid;place-items:center;background:linear-gradient(135deg,var(--accent),var(--accent2));color:white;font-weight:800;box-shadow:0 16px 45px rgba(14,165,233,.26)}.eyebrow{font-size:12px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted);font-weight:700}.hero h1{position:relative;margin:26px 0 0;font-size:clamp(34px,5vw,54px);line-height:1.02;letter-spacing:-.055em;text-wrap:balance}.hero p{position:relative;margin:18px 0 0;max-width:48ch;color:var(--muted);font-size:15px;line-height:1.75}.chips{position:relative;display:flex;gap:10px;flex-wrap:wrap;margin-top:26px}.chip{height:34px;display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:0 12px;color:var(--muted);font-size:12px;background:rgba(255,255,255,.045)}.card{padding:34px;display:flex;flex-direction:column;justify-content:center}.card h2{margin:0;font-size:28px;letter-spacing:-.035em}.sub{margin:9px 0 28px;color:var(--muted);font-size:14px;line-height:1.6}.field{display:grid;gap:8px;margin-bottom:16px}label{font-size:13px;color:var(--muted);font-weight:500}input{width:100%;height:48px;border:1px solid var(--line);border-radius:18px;background:var(--input);color:var(--text);padding:0 15px;font-size:15px;outline:none;transition:border-color .16s ease,box-shadow .16s ease,background .16s ease}input::placeholder{color:color-mix(in srgb,var(--muted) 70%,transparent)}input:focus{border-color:var(--accent);box-shadow:0 0 0 4px var(--focus)}button{width:100%;height:48px;border:1px solid rgba(255,255,255,.22);border-radius:999px;background:linear-gradient(135deg,var(--accent),color-mix(in srgb,var(--accent2) 80%,var(--accent)));color:white;font-size:15px;font-weight:650;letter-spacing:.01em;cursor:pointer;box-shadow:0 18px 45px rgba(14,165,233,.22),inset 0 1px 0 rgba(255,255,255,.28);transition:transform .16s ease,filter .16s ease,box-shadow .16s ease}button:hover{transform:translateY(-1px);filter:brightness(1.04)}button:active{transform:translateY(0);filter:brightness(.98)}button:focus-visible{outline:2px solid var(--accent);outline-offset:3px}.err{display:flex;gap:8px;align-items:flex-start;margin:0 0 16px;padding:11px 13px;border:1px solid color-mix(in srgb,var(--bad) 45%,transparent);border-radius:16px;background:color-mix(in srgb,var(--bad) 12%,transparent);color:var(--bad);font-size:13px;line-height:1.45}.err:before{content:"!";width:18px;height:18px;flex:0 0 18px;border-radius:999px;display:grid;place-items:center;background:var(--bad);color:white;font-size:12px;font-weight:800}.hint{margin-top:16px;color:var(--muted);font-size:12px;line-height:1.6;text-align:center}.foot{margin-top:20px;padding-top:18px;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:12px}.dot{display:inline-block;width:7px;height:7px;border-radius:999px;background:var(--accent2);box-shadow:0 0 0 4px color-mix(in srgb,var(--accent2) 18%,transparent);margin-right:8px}.login-theme{position:fixed;right:24px;top:22px;z-index:5;display:flex;align-items:center;gap:10px}.login-theme-label{font-size:13px;color:var(--muted);font-weight:400}.theme-select{width:154px;height:40px;appearance:none;-webkit-appearance:none;border-radius:999px;border:1px solid var(--line);background-color:var(--selectBg);background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'%3E%3Cpath d='M4.5 6.25 8 9.75l3.5-3.5' fill='none' stroke='%2391a3bd' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 13px center;background-size:16px 16px;color:var(--muted);padding:0 38px 0 14px;font-size:13px;font-weight:400;outline:none;box-shadow:none;cursor:pointer;line-height:40px;transition:border-color .16s ease,filter .16s ease}.theme-select:hover{filter:brightness(1.03)}.theme-select:focus,.theme-select:focus-visible{outline:none;border-color:var(--line);box-shadow:none}@media(max-width:820px){body{padding:76px 18px 18px}.login-theme{left:18px;right:18px;top:18px;justify-content:flex-end}.shell{grid-template-columns:1fr}.hero{min-height:auto;padding:26px}.hero h1{font-size:36px}.card{padding:26px;border-radius:26px}.foot{flex-direction:column}}@media(prefers-reduced-motion:reduce){*,*:before,*:after{transition:none!important}}
html[data-theme="light"] .theme-select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'%3E%3Cpath d='M4.5 6.25 8 9.75l3.5-3.5' fill='none' stroke='%2364748b' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")}@media(prefers-color-scheme:light){html[data-theme="system"] .theme-select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'%3E%3Cpath d='M4.5 6.25 8 9.75l3.5-3.5' fill='none' stroke='%2364748b' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")}}
</style>
</head>
<body>
<div class="login-theme"><select id="theme" class="theme-select" aria-label="主题模式"><option value="system">跟随系统</option><option value="light">明亮模式</option><option value="dark">暗黑模式</option></select></div>
<main class="shell">
  <section class="hero" aria-label="产品说明">
    <div>
      <div class="brand"><div class="logo">OTP</div><div><div class="eyebrow">Email verification center</div><strong>邮箱验证码中心</strong></div></div>
      <h1>把散落在邮箱里的验证码，集中到一个干净入口。</h1>
      <p>统一读取 IMAP / POP 邮箱与 Microsoft Graph 邮箱，验证码高亮、快速查询、批量管理。</p>
      <div class="chips"><span class="chip">本地缓存</span><span class="chip">Graph Mailbox</span><span class="chip">明暗主题</span><span class="chip">SQLite 持久化</span></div>
    </div>
    <div class="foot"><span><i class="dot"></i>Local first</span><span>请勿暴露到公网</span></div>
  </section>
  <form class="card" method="post" autocomplete="on">
    <h2>管理员登录</h2>
    <div class="sub">登录后可以查询验证码、管理邮箱账号和修改系统配置。</div>
    {error}
    <div class="field"><label for="username">用户名</label><input id="username" name="username" autofocus autocomplete="username" placeholder="admin"></div>
    <div class="field"><label for="password">密码</label><input id="password" name="password" type="password" autocomplete="current-password" placeholder="输入管理员密码"></div>
    <button type="submit">进入控制台</button>
  </form>
</main>
<script>
function applyLoginTheme(v){document.documentElement.dataset.theme=v;localStorage.setItem('otp-theme',v)}
(function(){const s=document.getElementById('theme');const v=localStorage.getItem('otp-theme')||'system';s.value=v;applyLoginTheme(v);s.addEventListener('change',e=>applyLoginTheme(e.target.value));})();
</script>
</body>
</html>"""

APP_HTML = r"""<!doctype html>
<html lang="zh-CN" data-theme="system">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>邮箱验证码中心</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='10' y1='8' x2='54' y2='58' gradientUnits='userSpaceOnUse'%3E%3Cstop stop-color='%2338bdf8'/%3E%3Cstop offset='1' stop-color='%2334d399'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='64' height='64' rx='18' fill='%2307111f'/%3E%3Cpath d='M14 22.5A6.5 6.5 0 0 1 20.5 16h23A6.5 6.5 0 0 1 50 22.5v19A6.5 6.5 0 0 1 43.5 48h-23A6.5 6.5 0 0 1 14 41.5v-19Z' fill='url(%23g)'/%3E%3Cpath d='m18 22 14 11 14-11' fill='none' stroke='white' stroke-width='5' stroke-linecap='round' stroke-linejoin='round'/%3E%3Ccircle cx='47' cy='18' r='8' fill='%23fbbf24' stroke='%2307111f' stroke-width='4'/%3E%3Cpath d='M47 14v5' stroke='%2307111f' stroke-width='3' stroke-linecap='round'/%3E%3C/svg%3E">
<style>
:root{color-scheme:dark;--bg:#07111f;--bg2:#0b1220;--card:rgba(15,23,42,.9);--line:rgba(148,163,184,.20);--text:#e5eefc;--muted:#91a3bd;--accent:#38bdf8;--bad:#fb7185;--input:#020617cc;--shadow:#0007;--mark:#fde68a;--markText:#111827;--modal:rgba(15,23,42,.94);--modalBackdrop:rgba(2,6,23,.52);--elevShadow:rgba(0,0,0,.46);--toastBg:#047857;--toastText:#fff;--softSurface:rgba(255,255,255,.035)}
html[data-theme="light"]{color-scheme:light;--bg:#f6f8fc;--bg2:#e9effa;--card:rgba(255,255,255,.94);--line:rgba(15,23,42,.14);--text:#0f172a;--muted:#64748b;--accent:#2563eb;--bad:#e11d48;--input:#fff;--shadow:#64748b33;--mark:#fef08a;--markText:#0f172a;--modal:rgba(255,255,255,.98);--modalBackdrop:rgba(15,23,42,.18);--elevShadow:rgba(15,23,42,.18);--toastBg:#ecfdf5;--toastText:#065f46;--softSurface:rgba(15,23,42,.035)}
@media(prefers-color-scheme:light){html[data-theme="system"]{color-scheme:light;--bg:#f6f8fc;--bg2:#e9effa;--card:rgba(255,255,255,.94);--line:rgba(15,23,42,.14);--text:#0f172a;--muted:#64748b;--accent:#2563eb;--bad:#e11d48;--input:#fff;--shadow:#64748b33;--mark:#fef08a;--markText:#0f172a;--modal:rgba(255,255,255,.98);--modalBackdrop:rgba(15,23,42,.18);--elevShadow:rgba(15,23,42,.18);--toastBg:#ecfdf5;--toastText:#065f46;--softSurface:rgba(15,23,42,.035)}}
*{box-sizing:border-box}body{margin:0;font-family:Inter,"PingFang SC",sans-serif;color:var(--text);background:radial-gradient(circle at 10% 10%,rgba(56,189,248,.18),transparent 22rem),radial-gradient(circle at 88% 14%,rgba(52,211,153,.13),transparent 24rem),linear-gradient(180deg,var(--bg),var(--bg2));min-height:100vh}.wrap{max-width:1680px;margin:0 auto;padding:22px}header{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-bottom:16px;flex-wrap:wrap}h1{margin:0;font-size:30px;letter-spacing:.02em}.subtitle{color:var(--muted);font-size:13px;margin-top:7px}.top{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.pill{padding:8px 12px;border:1px solid var(--line);border-radius:999px;background:var(--card);font-size:13px;color:var(--muted)}input,select,button{width:100%;border-radius:14px;border:1px solid var(--line);background:var(--input);color:var(--text);padding:11px 13px;outline:none;font-size:14px}button{cursor:pointer;font-weight:850;color:#fff;border:1px solid rgba(255,255,255,.22);background:linear-gradient(135deg,rgba(37,99,235,.58),rgba(14,165,233,.34));box-shadow:0 12px 34px rgba(14,165,233,.20),inset 0 1px 0 rgba(255,255,255,.25);backdrop-filter:blur(16px) saturate(160%);-webkit-backdrop-filter:blur(16px) saturate(160%);transition:.16s ease}button:hover{filter:brightness(1.10);transform:translateY(-1px)}.secondary{background:linear-gradient(135deg,rgba(148,163,184,.20),rgba(255,255,255,.06));color:var(--text);box-shadow:inset 0 1px 0 rgba(255,255,255,.14)}.danger{background:linear-gradient(135deg,rgba(190,18,60,.70),rgba(244,63,94,.48));color:#fff}.ghost{background:rgba(255,255,255,.04);color:var(--text);box-shadow:none}.tabs{display:flex;gap:8px;margin-bottom:14px}.tab{width:auto}.tab.active{outline:2px solid var(--accent)}.toolbar{display:grid;grid-template-columns:1.2fr 1.1fr .85fr .65fr auto;gap:12px;padding:14px;border:1px solid var(--line);border-radius:22px;background:var(--card);box-shadow:0 24px 80px var(--shadow);margin-bottom:14px}.field label{display:block;font-size:12px;color:var(--muted);margin-bottom:6px}.query-grid{display:grid;grid-template-columns:360px 1fr;gap:16px}.panel{border:1px solid var(--line);border-radius:22px;background:var(--card);box-shadow:0 22px 70px var(--shadow);overflow:hidden}.panel h2{margin:0;padding:13px 15px;font-size:15px;display:flex;gap:10px;justify-content:space-between;align-items:center;border-bottom:1px solid var(--line);background:rgba(127,127,127,.05)}.body{padding:14px}.account-list{height:calc(100vh - 280px);min-height:340px;overflow:auto;padding:2px 6px 2px 2px}.message-list{height:calc(100vh - 288px);min-height:420px;overflow:auto;padding:4px 10px 4px 4px}.mailbox-list{height:320px;overflow:auto;border:1px solid var(--line);border-radius:16px;padding:8px;background:rgba(127,127,127,.06)}.account,.msg{border:1px solid var(--line);border-radius:18px;background:rgba(127,127,127,.07);margin-bottom:10px;padding:12px}.account{cursor:pointer;position:relative}.account:hover{border-color:var(--accent)}.account.active{border-color:rgba(56,189,248,.9);background:linear-gradient(135deg,rgba(56,189,248,.20),rgba(52,211,153,.10));box-shadow:inset 3px 0 0 var(--accent),0 0 0 1px rgba(56,189,248,.16),0 10px 30px rgba(56,189,248,.10)}.account.active .name{color:var(--accent)}.name,.subject{font-weight:850;word-break:break-all}.meta,.from,.date,.snippet{color:var(--muted);font-size:12px;margin-top:7px;word-break:break-word}.msg.selected{border-color:rgba(56,189,248,.72);box-shadow:inset 0 0 0 2px rgba(56,189,248,.55),0 0 0 1px rgba(56,189,248,.20),0 12px 34px rgba(56,189,248,.14)}.msg-top{display:flex;align-items:flex-start;justify-content:space-between;gap:14px}.msg-left{display:flex;gap:10px;min-width:0}.msg-check{width:18px;height:18px;margin-top:3px;accent-color:#2563eb}.snippet{color:var(--text);opacity:.84;line-height:1.65;white-space:pre-wrap}.code{min-width:126px;text-align:center;padding:10px 13px;border-radius:16px;background:linear-gradient(135deg,#bbf7d0,#67e8f9);color:#07111d;font-size:23px;font-weight:950;letter-spacing:.16em;cursor:pointer}.code.empty{background:rgba(127,127,127,.16);color:var(--muted);font-size:13px;letter-spacing:0}.msg-actions{display:grid;gap:8px;min-width:130px}.bulkbar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}.toast{position:fixed;right:18px;bottom:18px;background:var(--toastBg);color:var(--toastText);border:1px solid var(--line);box-shadow:0 18px 50px var(--elevShadow);padding:12px 14px;border-radius:14px;display:none;z-index:50}.hidden{display:none!important}.admin-stack{display:grid;grid-template-columns:1fr;gap:16px}.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,360px));gap:12px;align-items:end}.wide{grid-column:auto}.mailbox-row{display:flex;gap:8px;align-items:center;padding:8px;border-bottom:1px solid var(--line)}.mailbox-row span{flex:1;word-break:break-all}.highlight{background:var(--mark);color:var(--markText);border-radius:5px;padding:0 3px;font-weight:900}.badge{font-size:12px;color:var(--muted)}@media(max-width:1100px){.toolbar,.query-grid,.form-grid{grid-template-columns:1fr}.message-list,.account-list{height:55vh}.msg-top{flex-direction:column}.msg-actions{width:100%;grid-template-columns:1fr 1fr}.code{width:100%}}
.task-float{position:fixed;right:18px;bottom:18px;width:min(390px,calc(100vw - 28px));display:grid;gap:10px;z-index:30;pointer-events:none}.task-card{pointer-events:auto;border:1px solid var(--line);border-radius:18px;background:var(--modal);color:var(--text);box-shadow:0 20px 70px var(--elevShadow),inset 0 1px 0 rgba(255,255,255,.18);backdrop-filter:blur(18px) saturate(160%);-webkit-backdrop-filter:blur(18px) saturate(160%);padding:13px 14px;animation:taskIn .18s ease}.task-card.done{border-color:rgba(52,211,153,.55)}.task-card.fail{border-color:rgba(251,113,133,.68)}.task-head{display:flex;justify-content:space-between;align-items:center;gap:10px;font-weight:900}.task-title{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.task-status{font-size:12px;color:var(--muted);white-space:nowrap}.task-bar{height:7px;border-radius:999px;background:rgba(148,163,184,.18);overflow:hidden;margin-top:10px}.task-fill{height:100%;width:0%;border-radius:999px;background:linear-gradient(90deg,#38bdf8,#34d399);transition:width .25s ease}.task-card.fail .task-fill{background:linear-gradient(90deg,#fb7185,#f97316)}.task-detail{font-size:12px;color:var(--muted);margin-top:8px;line-height:1.45;word-break:break-word}.task-close{width:auto;padding:4px 8px;border-radius:10px;font-size:12px}.task-card.running .task-status::before{content:"";display:inline-block;width:7px;height:7px;border-radius:50%;background:#38bdf8;margin-right:6px;box-shadow:0 0 0 4px rgba(56,189,248,.18);animation:pulse 1s infinite}@keyframes pulse{50%{opacity:.45}}@keyframes taskIn{from{opacity:0;transform:translateY(10px) scale(.98)}to{opacity:1;transform:none}}.modal-mask{position:fixed;inset:0;display:none;place-items:center;background:var(--modalBackdrop);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);z-index:40;padding:18px}.modal-mask.show{display:grid}.modal-card{width:min(430px,calc(100vw - 32px));border:1px solid var(--line);border-radius:24px;background:var(--modal);color:var(--text);box-shadow:0 30px 100px var(--elevShadow),inset 0 1px 0 rgba(255,255,255,.18);padding:20px;animation:taskIn .16s ease}.modal-title{font-size:18px;font-weight:950;margin-bottom:10px}.modal-msg{color:var(--muted);font-size:14px;line-height:1.7;white-space:pre-wrap}.modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:18px}.modal-actions button{width:auto}.modal-danger-note{margin-top:10px;font-size:12px;color:var(--bad)}.top-mail-row{grid-column:1/-1;display:grid;grid-template-columns:repeat(3,minmax(220px,1fr));gap:12px}.graph-config-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;align-items:end}@media(max-width:900px){.top-mail-row{grid-template-columns:1fr}}.mailbox-row input[type="checkbox"]{width:18px;height:18px;accent-color:#2563eb;flex:0 0 auto}.mailbox-actions{display:flex;gap:10px;margin-top:10px;flex-wrap:wrap}.bulk-mini{width:auto}.textarea-mailbox{min-height:86px;resize:vertical;line-height:1.55}
 .save-inline{width:auto;margin-top:12px;padding-left:18px;padding-right:18px}
button{border-radius:999px!important;min-height:40px;padding:0 16px!important;display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:6px;line-height:1.1!important;white-space:nowrap;font-weight:600!important;letter-spacing:.01em;color:var(--text)!important}
button.secondary,button.ghost,button.danger{border-radius:999px!important;font-weight:600!important;color:var(--text)!important}
button:focus-visible{outline:1px solid var(--line);outline-offset:2px}
button:active{transform:translateY(0);filter:brightness(.98)}
.tab{height:40px;min-width:104px;padding:0 18px!important;border-radius:999px!important;font-weight:600!important}
.tab.active{outline:none;border-color:var(--line);background:linear-gradient(135deg,rgba(56,189,248,.22),rgba(14,165,233,.12));box-shadow:inset 0 1px 0 rgba(255,255,255,.18)}
.bulkbar button,.msg-actions button,.mailbox-row button,.modal-actions button,.top button,.mail-searchbar button,.save-inline,.bulk-mini{height:40px!important;min-height:40px!important;border-radius:999px!important;padding:0 16px!important}
.task-close{width:32px!important;height:32px!important;min-height:32px!important;padding:0!important;border-radius:999px!important;font-size:15px!important}
html[data-theme="light"] button{color:#0f172a!important}
html[data-theme="dark"] button{color:#e5eefc!important}
@media(prefers-color-scheme:light){html[data-theme="system"] button{color:#0f172a!important}}
@media(prefers-color-scheme:dark){html[data-theme="system"] button{color:#e5eefc!important}}
#theme{width:154px!important;height:40px;appearance:none;-webkit-appearance:none;padding:0 38px 0 14px;border-radius:999px;border:1px solid var(--line);background-color:var(--card);background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'%3E%3Cpath d='M4.5 6.25 8 9.75l3.5-3.5' fill='none' stroke='%2391a3bd' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 13px center;background-size:16px 16px;color:var(--muted);font-size:13px;font-weight:400;box-shadow:none;cursor:pointer;line-height:40px;transition:border-color .16s ease,filter .16s ease}
#theme:hover{border-color:var(--line);filter:brightness(1.03)}
#theme:focus,#theme:focus-visible{outline:none!important;box-shadow:none!important;border-color:var(--line)}
html[data-theme="light"] #theme{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'%3E%3Cpath d='M4.5 6.25 8 9.75l3.5-3.5' fill='none' stroke='%2364748b' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")}
@media(prefers-color-scheme:light){html[data-theme="system"] #theme{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 16 16'%3E%3Cpath d='M4.5 6.25 8 9.75l3.5-3.5' fill='none' stroke='%2364748b' stroke-width='1.8' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E")}}
.mail-searchbar{display:grid;grid-template-columns:minmax(180px,1fr) minmax(180px,1fr) 110px auto;gap:10px 12px;align-items:end;margin-bottom:12px;padding:12px;border:1px solid var(--line);border-radius:18px;background:var(--softSurface)}
.mail-searchbar .compact select{min-width:0}
.mail-searchbar button{height:40px;width:auto;padding:0 18px;display:inline-flex;align-items:center;justify-content:center}
@media(max-width:900px){.mail-searchbar{grid-template-columns:1fr 1fr}.mail-searchbar button{width:100%}}
@media(max-width:560px){.mail-searchbar{grid-template-columns:1fr}}
.graph-mailbox-tools,.mail-account-tools{display:flex;gap:10px 12px;margin-top:12px;align-items:center;flex-wrap:wrap;min-height:42px}
.mailbox-actions,.mail-account-primary,.bulk-actions{display:flex;gap:10px 12px;flex-wrap:wrap;align-items:center;min-width:0;margin:0;height:40px}
.bulk-actions{display:none;margin-left:4px;align-self:center}
.bulk-actions.show{display:flex}
.bulk-mini{width:auto;min-width:max-content;height:40px;padding:0 13px;display:inline-flex;align-items:center;justify-content:center;white-space:nowrap;flex:0 0 auto;line-height:1}
.mail-account-primary .pill,.bulk-actions .badge{height:40px;display:inline-flex;align-items:center;justify-content:center;padding:0 12px;line-height:1;white-space:nowrap;margin:0;align-self:center}
.bulk-actions .badge{min-width:58px;background:rgba(148,163,184,.14);border:1px solid var(--line);border-radius:999px;color:var(--muted)}
.textarea-mailbox{min-height:150px;resize:both;overflow:auto;width:100%;max-width:100%;line-height:1.55}
@media(max-width:720px){.graph-mailbox-tools,.mail-account-tools{align-items:center}.bulk-actions{margin-left:0}}
@media(max-width:560px){.graph-mailbox-tools,.mail-account-tools,.mailbox-actions,.mail-account-primary,.bulk-actions{gap:8px}.bulk-mini{flex:1 1 calc(50% - 8px);min-width:128px}.bulk-actions .badge{flex:1 1 100%;margin-left:0}}
</style>
</head>
<body><div class="wrap"><header><div><h1>邮箱验证码中心</h1><div class="subtitle">管理员登录 / 多选删除 / 验证码高亮 / 配置管理</div></div><div class="top"><select id="theme" style="width:150px"><option value="system">跟随系统</option><option value="dark">暗黑模式</option><option value="light">明亮模式</option></select><span id="health" class="pill">连接中...</span><button class="secondary" style="width:auto" onclick="logout()">退出</button></div></header><div class="tabs"><button id="tabQuery" class="tab active" onclick="showTab('query')">验证码查询</button><button id="tabAdmin" class="tab secondary" onclick="showTab('admin')">配置管理</button></div><section id="queryPane"><input id="account" type="hidden" value=""><div class="query-grid"><section class="panel"><h2>邮箱列表 <span id="accountCount" class="badge">0</span></h2><div class="body"><input id="accountSearch" placeholder="搜索邮箱 / 品牌 / 账号" style="margin-bottom:10px"><div class="account-list" id="accounts"></div></div></section><section class="panel"><h2>邮件 / 验证码 <span style="display:flex;gap:8px;align-items:center"><button class="secondary" style="width:auto;padding:7px 10px" onclick="refreshMail()">刷新</button><span id="resultCount" class="badge">0</span></span></h2><div class="body"><div class="mail-searchbar"><div class="field"><label>关键词</label><input id="keyword" placeholder="ChatGPT / GitHub / OpenAI"></div><div class="field"><label>发件人</label><input id="sender" placeholder="noreply / github"></div><div class="field compact"><label>条数</label><select id="limit"><option>10</option><option selected>20</option><option>50</option><option>100</option></select></div><button class="bulk-mini" onclick="search()">查询</button></div><div class="bulkbar"><button class="secondary" style="width:auto" onclick="selectAllMessages(true)">全选</button><button class="secondary" style="width:auto" onclick="invertSelection()">反选</button><button class="ghost" style="width:auto" onclick="selectAllMessages(false)">取消选择</button><button class="danger" style="width:auto" onclick="batchDelete()">批量删除所选</button><span class="pill" id="selectedCount">已选 0</span></div><div class="message-list" id="messages"></div></div></section></div></section><section id="adminPane" class="hidden"><div class="admin-stack"><section class="panel"><h2>系统配置</h2><div class="body"><div class="form-grid"><div class="field"><label>轮询间隔秒</label><input id="pollInterval" type="number"></div><div class="field"><label>每邮箱拉取邮件数</label><input id="lookback" type="number"></div><div class="field"><label>管理员用户名</label><input id="adminUser"></div><div class="field"><label>新密码（留空不改）</label><input id="adminPass" type="password"></div></div><button class="save-inline" onclick="saveSettings()">保存配置</button></div></section><section class="panel"><h2>代理管理 <span class="badge">用于 Microsoft Graph / 删除邮件请求</span></h2><div class="body"><div class="form-grid"><div class="field"><label>启用代理</label><select id="proxyEnabled"><option value="true">启用</option><option value="false">停用</option></select></div><div class="field"><label>测试地址</label><input id="proxyTestUrl" value="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"></div><div class="field"><label>HTTP Proxy</label><input id="httpProxy" placeholder="http://proxy.example:7893"></div><div class="field"><label>HTTPS Proxy</label><input id="httpsProxy" placeholder="http://proxy.example:7893"></div><div class="field"><label>No Proxy</label><input id="noProxy" placeholder="127.0.0.1,localhost"></div></div><div style="display:flex;gap:10px;margin-top:12px;flex-wrap:wrap"><button style="width:auto" onclick="saveProxy()">保存代理</button><button class="secondary" style="width:auto" onclick="testProxy()">测试代理</button><span class="pill" id="proxyTestResult">未测试</span></div></div></section><section class="panel"><h2>MicroSoft Graph 配置 <span class="badge">Tenant / Client / Secret</span></h2><div class="body"><div class="graph-config-grid"><div class="field"><label>Graph Tenant ID</label><input id="tenantId"></div><div class="field"><label>Graph Client ID</label><input id="clientId"></div><div class="field"><label>Graph Client Secret（留空不改）</label><input id="clientSecret" type="password"></div></div><button class="save-inline" onclick="saveSettings()">保存 Graph 配置</button></div></section><section class="panel"><h2>MicroSoft Graph 邮箱管理 <span class="badge">支持多选删除 / 一行一个批量新增</span></h2><div class="body"><div class="field"><label>新增邮箱（一行一个）</label><textarea id="newMailbox" class="textarea-mailbox" placeholder="mailbox1@example.com
mailbox2@example.com"></textarea></div><div class="graph-mailbox-tools"><div class="mailbox-actions"><button class="bulk-mini" onclick="addMailbox()">批量新增邮箱</button></div><div id="mailboxBulkActions" class="bulk-actions"><button class="secondary bulk-mini" onclick="selectAllMailboxes(true)">全选</button><button class="secondary bulk-mini" onclick="selectAllMailboxes(false)">取消选择</button><button class="danger bulk-mini" onclick="batchDeleteMailboxes()">批量删除所选</button><span class="badge" id="mailboxSelectedCount">已选 0</span></div></div><div class="mailbox-list" id="mailboxes" style="margin-top:14px"></div></div></section><section class="panel"><h2>POP3 / SMTP / IMAP 邮箱管理 <span class="badge">支持 163 / QQ / Gmail / Outlook 等</span></h2><div class="body"><div class="form-grid"><div class="top-mail-row"><div class="field"><label>邮箱品牌</label><select id="mailProvider" onchange="applyMailPreset()"></select></div><div class="field"><label>邮箱名</label><input id="mailEmail" placeholder="user@example.com"></div><div class="field"><label>授权码 / 应用密码</label><input id="mailPassword" type="password" placeholder="邮箱授权码，不建议使用主密码"></div></div><div class="field"><label>IMAP Host</label><input id="imapHost"></div><div class="field"><label>IMAP Port</label><input id="imapPort" type="number"></div><div class="field"><label>SMTP Host</label><input id="smtpHost"></div><div class="field"><label>SMTP Port</label><input id="smtpPort" type="number"></div><div class="field"><label>POP3 Host</label><input id="pop3Host"></div><div class="field"><label>POP3 Port</label><input id="pop3Port" type="number"></div><div class="field"><label>测试协议</label><select id="mailTestProtocol"><option value="imap">IMAP</option><option value="pop3">POP3</option><option value="smtp">SMTP</option></select></div><div class="field"><label>&nbsp;</label><button class="secondary" onclick="testMailAccount()">测试邮箱配置</button></div></div><div class="mail-account-tools"><div class="mail-account-primary"><button class="bulk-mini" onclick="addMailAccount()">添加邮箱账号</button><span class="pill" id="mailTestResult">未测试</span></div><div id="mailacctBulkActions" class="bulk-actions"><button class="secondary bulk-mini" onclick="selectAllMailAccounts(true)">全选</button><button class="secondary bulk-mini" onclick="selectAllMailAccounts(false)">取消选择</button><button class="danger bulk-mini" onclick="batchDeleteMailAccounts()">批量删除所选</button><span class="badge" id="mailacctSelectedCount">已选 0</span></div></div><div class="mailbox-list" id="mailAccounts" style="margin-top:14px"></div></div></section></div></section></div><div id="confirmModal" class="modal-mask"><div class="modal-card"><div id="confirmTitle" class="modal-title">确认操作</div><div id="confirmMessage" class="modal-msg"></div><div id="confirmNote" class="modal-danger-note"></div><div class="modal-actions"><button id="confirmCancel" class="secondary">取消</button><button id="confirmOk" class="danger">确认删除</button></div></div></div><div id="taskFloat" class="task-float"></div><div id="toast" class="toast"></div>
<script>
let accounts=[], cfg={}, currentMessages=[]; const MAIL_PRESETS = {"163": {"label": "网易 163", "imap_host": "imap.163.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.163.com", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.163.com", "pop3_port": 995, "pop3_ssl": true}, "126": {"label": "网易 126", "imap_host": "imap.126.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.126.com", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.126.com", "pop3_port": 995, "pop3_ssl": true}, "yeah": {"label": "网易 yeah.net", "imap_host": "imap.yeah.net", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.yeah.net", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.yeah.net", "pop3_port": 995, "pop3_ssl": true}, "qq": {"label": "QQ 邮箱", "imap_host": "imap.qq.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.qq.com", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.qq.com", "pop3_port": 995, "pop3_ssl": true}, "foxmail": {"label": "Foxmail", "imap_host": "imap.qq.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.qq.com", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.qq.com", "pop3_port": 995, "pop3_ssl": true}, "outlook": {"label": "Outlook / Microsoft 365", "imap_host": "outlook.office365.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.office365.com", "smtp_port": 587, "smtp_ssl": false, "pop3_host": "outlook.office365.com", "pop3_port": 995, "pop3_ssl": true}, "gmail": {"label": "Gmail", "imap_host": "imap.gmail.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.gmail.com", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.gmail.com", "pop3_port": 995, "pop3_ssl": true}, "icloud": {"label": "iCloud Mail", "imap_host": "imap.mail.me.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.mail.me.com", "smtp_port": 587, "smtp_ssl": false, "pop3_host": "", "pop3_port": 995, "pop3_ssl": true}, "yahoo": {"label": "Yahoo Mail", "imap_host": "imap.mail.yahoo.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.mail.yahoo.com", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.mail.yahoo.com", "pop3_port": 995, "pop3_ssl": true}, "sina": {"label": "新浪邮箱", "imap_host": "imap.sina.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.sina.com", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.sina.com", "pop3_port": 995, "pop3_ssl": true}, "sohu": {"label": "搜狐邮箱", "imap_host": "imap.sohu.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.sohu.com", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop3.sohu.com", "pop3_port": 995, "pop3_ssl": true}, "189": {"label": "189 邮箱", "imap_host": "imap.189.cn", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.189.cn", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.189.cn", "pop3_port": 995, "pop3_ssl": true}, "aliyun": {"label": "阿里邮箱", "imap_host": "imap.qiye.aliyun.com", "imap_port": 993, "imap_ssl": true, "smtp_host": "smtp.qiye.aliyun.com", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "pop.qiye.aliyun.com", "pop3_port": 995, "pop3_ssl": true}, "custom": {"label": "自定义", "imap_host": "", "imap_port": 993, "imap_ssl": true, "smtp_host": "", "smtp_port": 465, "smtp_ssl": true, "pop3_host": "", "pop3_port": 995, "pop3_ssl": true}}; const $=id=>document.getElementById(id);
function toast(m){const t=$('toast');t.textContent=m;t.style.display='block';clearTimeout(window.__tt);window.__tt=setTimeout(()=>t.style.display='none',2000)}
function pageConfirm({title='确认操作',message='',okText='确认',note=''}){return new Promise(resolve=>{const m=$('confirmModal'),ttl=$('confirmTitle'),msg=$('confirmMessage'),nt=$('confirmNote'),ok=$('confirmOk'),cancel=$('confirmCancel');ttl.textContent=title;msg.textContent=message;nt.textContent=note||'';ok.textContent=okText;const cleanup=(v)=>{m.classList.remove('show');ok.onclick=null;cancel.onclick=null;m.onclick=null;document.onkeydown=null;resolve(v)};ok.onclick=()=>cleanup(true);cancel.onclick=()=>cleanup(false);m.onclick=e=>{if(e.target===m)cleanup(false)};document.onkeydown=e=>{if(e.key==='Escape')cleanup(false)};m.classList.add('show')})}

const deleteTasks=new Map();let taskSeq=0;
function taskBox(){return $('taskFloat')}
function taskPercent(t){return t.total?Math.round((t.done/t.total)*100):(t.state==='running'?8:100)}
function taskClass(t){return t.state==='failed'?'fail':(t.state==='done'?'done':'running')}
function taskStatus(t){return t.state==='running'?'删除中':(t.state==='done'?'删除成功':'删除失败')}
function taskDefaultDetail(t){return t.detail||`进度 ${t.done}/${t.total}`}
function taskCardHtml(t){const pct=taskPercent(t);const cls=taskClass(t);return `<div class="task-card ${cls}" data-task-id="${t.id}"><div class="task-head"><div class="task-title">${esc(t.title)}</div><div style="display:flex;gap:8px;align-items:center"><span class="task-status">${taskStatus(t)}</span><button class="secondary task-close" onclick="dismissDeleteTask(${t.id})">×</button></div></div><div class="task-bar"><div class="task-fill" style="width:${pct}%"></div></div><div class="task-detail">${esc(taskDefaultDetail(t))}</div></div>`}
function updateTaskCard(t){const box=taskBox();if(!box)return;let card=box.querySelector(`[data-task-id="${t.id}"]`);if(!card){box.insertAdjacentHTML('beforeend',taskCardHtml(t));card=box.querySelector(`[data-task-id="${t.id}"]`)}card.classList.toggle('running',t.state==='running');card.classList.toggle('done',t.state==='done');card.classList.toggle('fail',t.state==='failed');const status=card.querySelector('.task-status');if(status)status.textContent=taskStatus(t);const fill=card.querySelector('.task-fill');if(fill)fill.style.width=taskPercent(t)+'%';const detail=card.querySelector('.task-detail');if(detail)detail.textContent=taskDefaultDetail(t);const title=card.querySelector('.task-title');if(title)title.textContent=t.title;}
function showDeleteTask(task,{final=false}={}){deleteTasks.set(task.id,task);updateTaskCard(task);if(task.autoTimer)clearTimeout(task.autoTimer);if(task.state!=='running'){task.autoTimer=setTimeout(()=>{deleteTasks.delete(task.id);const card=taskBox()?.querySelector(`[data-task-id="${task.id}"]`);if(card)card.remove()},6500)}}
function renderDeleteTasks(){const box=taskBox();if(!box)return;box.innerHTML='';[...deleteTasks.values()].slice(-4).forEach(t=>updateTaskCard(t))}
function dismissDeleteTask(id){deleteTasks.delete(id);const card=taskBox()?.querySelector(`[data-task-id="${id}"]`);if(card)card.remove()}
async function runDeleteTask(ids,title){const task={id:++taskSeq,title,total:ids.length,done:0,state:'running',detail:`准备删除 ${ids.length} 封邮件...`,lastUi:0};showDeleteTask(task);try{if(ids.length===1){await api('/api/messages/'+ids[0]+'/delete',{method:'POST'});task.done=1;task.state='done';task.detail='已删除 1 封邮件';showDeleteTask(task,{final:true})}else{let ok=0,fail=0;for(const id of ids){try{await api('/api/messages/'+id+'/delete',{method:'POST'});ok++}catch(e){fail++}task.done=ok+fail;task.detail=`已处理 ${task.done}/${task.total}，成功 ${ok}，失败 ${fail}`;const now=Date.now();if(now-task.lastUi>450||task.done===task.total){task.lastUi=now;showDeleteTask(task)}}task.state=fail?'failed':'done';task.detail=fail?`批量删除完成：成功 ${ok}，失败 ${fail}`:`批量删除完成：成功 ${ok} 封`;showDeleteTask(task,{final:true})}await search()}catch(e){task.state='failed';task.detail=e.message||String(e);showDeleteTask(task,{final:true});await search()}}

function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function api(p,o){const r=await fetch(p,o);if(r.status===401){location='/login';return}if(!r.ok)throw new Error(await r.text());return await r.json()}
function setTheme(v){document.documentElement.dataset.theme=v;localStorage.setItem('otp-theme',v)}
function initTheme(){const v=localStorage.getItem('otp-theme')||'system';$('theme').value=v;setTheme(v)}
function showTab(t){$('queryPane').classList.toggle('hidden',t!=='query');$('adminPane').classList.toggle('hidden',t!=='admin');$('tabQuery').classList.toggle('active',t==='query');$('tabAdmin').classList.toggle('active',t==='admin');if(t==='admin')loadConfig()}
async function loadHealth(){const h=await api('/api/health');$('health').textContent=`在线 · ${h.accounts} 个账户`}
async function loadAccounts(){const d=await api('/api/accounts');accounts=d.accounts||[];$('accountCount').textContent=accounts.length;renderAccounts()}
function renderAccounts(){const q=($('accountSearch')?.value||'').trim().toLowerCase();const box=$('accounts');box.innerHTML='';accounts.filter(a=>{const text=`${a.name||''} ${a.username||''} ${a.provider||''}`.toLowerCase();return !q||text.includes(q)}).forEach(a=>{const label=a.username||a.name;box.insertAdjacentHTML('beforeend',`<div class="account" data-account="${esc(a.name)}" onclick="selectAccount('${esc(a.name)}')"><div class="name">${esc(label)}</div><div class="meta">${esc(a.provider||'')} · ${a.last_error?'异常':'正常'}</div>${a.last_error?`<div class="meta" style="color:var(--bad)">${esc(a.last_error)}</div>`:''}</div>`)});markActiveAccount()}
function selectAccount(name){$('account').value=name;const a=accounts.find(x=>x.name===name);markActiveAccount();search()}function markActiveAccount(){document.querySelectorAll('.account').forEach(x=>x.classList.toggle('active',x.dataset.account===$('account').value))}
function highlightedSnippet(m){let s=esc(m.snippet||''); const code=m.code?String(m.code):''; if(code){s=s.replaceAll(esc(code), `<span class="highlight">${esc(code)}</span>`)} return s}
function card(m){const code=m.code?`<div class="code" onclick="copyCode('${String(m.code).replace(/'/g,"\\'")}')">${esc(m.code)}</div>`:`<div class="code empty">无验证码</div>`;return `<article class="msg" data-id="${m.id}"><div class="msg-top"><div class="msg-left"><input class="msg-check" type="checkbox" value="${m.id}" onchange="updateSelected()"><div><div class="subject">${esc(m.subject||'(无主题)')}</div><div class="from">${esc(m.sender||'')} · ${esc(m.account_name||'')}</div></div></div><div class="msg-actions">${code}<button class="danger" onclick="deleteMessage(${m.id})">删除</button></div></div><div class="date">${esc(m.date||m.received_at||'')}</div><div class="snippet">${highlightedSnippet(m)}</div></article>`}
async function copyCode(c){await navigator.clipboard.writeText(c);toast('已复制：'+c)}
async function search(){const q=new URLSearchParams();if($('account').value)q.set('account',$('account').value);if($('keyword').value.trim())q.set('keyword',$('keyword').value.trim());if($('sender').value.trim())q.set('sender',$('sender').value.trim());q.set('limit',$('limit').value);const d=await api('/api/messages?'+q);currentMessages=d.messages||[];$('resultCount').textContent=currentMessages.length;$('messages').innerHTML=currentMessages.length?currentMessages.map(card).join(''):'<div class="subtitle">没有找到匹配邮件</div>';updateSelected()}
function selectedIds(){return [...document.querySelectorAll('.msg-check:checked')].map(x=>Number(x.value))}
function updateSelected(){document.querySelectorAll('.msg').forEach(m=>m.classList.toggle('selected',m.querySelector('.msg-check')?.checked));$('selectedCount').textContent='已选 '+selectedIds().length}
function selectAllMessages(v){document.querySelectorAll('.msg-check').forEach(x=>x.checked=v);updateSelected()}
function invertSelection(){document.querySelectorAll('.msg-check').forEach(x=>x.checked=!x.checked);updateSelected()}
async function deleteMessage(id){const ok=await pageConfirm({title:'删除邮件',message:'确定删除这封邮件吗？\n删除任务会在右下角悬浮窗显示进度，你可以继续操作其他邮箱。',okText:'确认删除',note:'IMAP 邮箱可能会直接从服务器删除；Graph 邮箱会移动到已删除邮件。'});if(!ok)return;runDeleteTask([id],'删除邮件')}
async function batchDelete(){const ids=selectedIds();if(!ids.length){toast('请先选择邮件');return}const ok=await pageConfirm({title:'批量删除邮件',message:`确定批量删除 ${ids.length} 封邮件吗？\n删除会在后台逐封执行，右下角会显示实时进度。`,okText:'确认删除',note:'删除期间可以继续查询或切换邮箱。'});if(!ok)return;runDeleteTask(ids,'批量删除 '+ids.length+' 封邮件')}
async function refreshMail(){const body={};if($('account').value){const a=accounts.find(x=>x.name===$('account').value);if(a)body.mailboxes=[a.username||a.name]}try{const r=await api('/api/refresh',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(r.ok===false){toast('刷新失败：'+(r.error||'请查看账户状态详情'))}else{toast('刷新完成')}await loadHealth();await loadAccounts();await search()}catch(e){toast('刷新失败：'+e.message)}}
async function loadConfig(){const d=await api('/api/config');cfg=d.config;const g=cfg.graph_application||{},w=cfg.webui||{},a=w.admin||{},p=w.proxy||{};$('pollInterval').value=cfg.poll_interval||60;$('lookback').value=cfg.lookback_messages||30;$('adminUser').value=a.username||'admin';$('tenantId').value=g.tenant_id||'';$('clientId').value=g.client_id||'';$('proxyEnabled').value=String(p.enabled!==false);$('httpProxy').value=p.http_proxy||'';$('httpsProxy').value=p.https_proxy||'';$('noProxy').value=p.no_proxy||'';renderMailboxes(g.mailboxes||[]);renderMailAccounts(cfg.accounts||[]);initProviderOptions()}
function renderMailboxes(list){$('mailboxes').innerHTML=list.map(m=>`<div class="mailbox-row"><input class="mailbox-check" type="checkbox" value="${esc(m)}" onchange="updateMailboxBulkActions()"><span>${esc(m)}</span><button class="danger" style="width:auto" onclick="deleteMailbox('${String(m).replace(/'/g,"\\'")}')">删除</button></div>`).join('')||'<div class="subtitle">暂无邮箱</div>';updateMailboxBulkActions()}
function selectedMailboxes(){return [...document.querySelectorAll('.mailbox-check:checked')].map(x=>x.value)}
function updateMailboxBulkActions(){const n=selectedMailboxes().length;const el=$('mailboxBulkActions');if(el)el.classList.toggle('show',n>0);const c=$('mailboxSelectedCount');if(c)c.textContent='已选 '+n}
function selectAllMailboxes(v){document.querySelectorAll('.mailbox-check').forEach(x=>x.checked=v);updateMailboxBulkActions()}
async function addMailbox(){const values=$('newMailbox').value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);const unique=[...new Set(values)];if(!unique.length){toast('请填写邮箱，一行一个');return}let ok=0,fail=0,lastMailboxes=null;for(const mailbox of unique){try{const r=await api('/api/config/mailboxes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mailbox})});lastMailboxes=r.mailboxes||lastMailboxes;ok++}catch(e){fail++}}$('newMailbox').value='';if(lastMailboxes)renderMailboxes(lastMailboxes);toast(`新增完成：成功 ${ok}，失败 ${fail}`);await loadConfig();await loadAccounts()}
async function deleteMailbox(m){const ok=await pageConfirm({title:'删除 Graph 邮箱',message:'确定删除这个 Graph 邮箱吗？\n'+m,okText:'确认删除'});if(!ok)return;await api('/api/config/mailboxes',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({mailbox:m})});toast('已删除');await loadConfig();await loadAccounts()}
async function batchDeleteMailboxes(){const boxes=selectedMailboxes();if(!boxes.length){toast('请先选择 Graph 邮箱');return}const ok=await pageConfirm({title:'批量删除 Graph 邮箱',message:`确定删除 ${boxes.length} 个 Graph 邮箱吗？`,okText:'确认删除'});if(!ok)return;await api('/api/config/mailboxes',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({mailboxes:boxes})});toast('批量删除完成');await loadConfig();await loadAccounts()}
async function saveSettings(){const payload={poll_interval:Number($('pollInterval').value||60),lookback_messages:Number($('lookback').value||30),admin_username:$('adminUser').value.trim(),admin_password:$('adminPass').value,graph:{tenant_id:$('tenantId').value.trim(),client_id:$('clientId').value.trim(),client_secret:$('clientSecret').value}};await api('/api/config',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});$('adminPass').value='';$('clientSecret').value='';toast('配置已保存')}
async function saveProxy(){const payload={proxy:{enabled:$('proxyEnabled').value==='true',http_proxy:$('httpProxy').value.trim(),https_proxy:$('httpsProxy').value.trim(),no_proxy:$('noProxy').value.trim()}};await api('/api/proxy',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});toast('代理配置已保存')}async function testProxy(){const result=$('proxyTestResult');result.textContent='测试中...';try{const r=await api('/api/proxy/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:$('proxyTestUrl').value.trim()})});result.textContent='成功 HTTP '+r.result.status;toast('代理测试成功')}catch(e){result.textContent='失败';toast('代理测试失败：'+e.message)}}function initProviderOptions(){const sel=$('mailProvider'); if(!sel || sel.dataset.ready)return; Object.entries(MAIL_PRESETS).forEach(([k,v])=>sel.insertAdjacentHTML('beforeend',`<option value="${k}">${esc(v.label)}</option>`)); sel.dataset.ready='1'; applyMailPreset()}
function applyMailPreset(){const p=MAIL_PRESETS[$('mailProvider').value]||MAIL_PRESETS.custom; $('imapHost').value=p.imap_host||'';$('imapPort').value=p.imap_port||993;$('smtpHost').value=p.smtp_host||'';$('smtpPort').value=p.smtp_port||465;$('pop3Host').value=p.pop3_host||'';$('pop3Port').value=p.pop3_port||995}
function mailAccountPayload(){return {provider:$('mailProvider').value,email:$('mailEmail').value.trim(),password:$('mailPassword').value,imap:{host:$('imapHost').value.trim(),port:Number($('imapPort').value||993),ssl:true},smtp:{host:$('smtpHost').value.trim(),port:Number($('smtpPort').value||465),ssl:Number($('smtpPort').value||465)!==587},pop3:{host:$('pop3Host').value.trim(),port:Number($('pop3Port').value||995),ssl:true}}}
function renderMailAccounts(list){const el=$('mailAccounts'); if(!el)return; el.innerHTML=(list||[]).map(a=>`<div class="mailbox-row"><input class="mailacct-check" type="checkbox" value="${esc(a.name||'')}" onchange="updateMailAccountBulkActions()"><span>${esc(a.username||a.email||a.name)} <small class="badge">${esc(a.provider||'imap')}</small></span><button class="danger" style="width:auto" onclick="deleteMailAccount('${esc(a.name||'')}')">删除</button></div>`).join('')||'<div class="subtitle">暂无 POP3/SMTP/IMAP 邮箱账号</div>';updateMailAccountBulkActions()}
function selectedMailAccounts(){return [...document.querySelectorAll('.mailacct-check:checked')].map(x=>x.value).filter(Boolean)}
function updateMailAccountBulkActions(){const n=selectedMailAccounts().length;const el=$('mailacctBulkActions');if(el)el.classList.toggle('show',n>0);const c=$('mailacctSelectedCount');if(c)c.textContent='已选 '+n}
function selectAllMailAccounts(v){document.querySelectorAll('.mailacct-check').forEach(x=>x.checked=v);updateMailAccountBulkActions()}
async function testMailAccount(){const result=$('mailTestResult'); result.textContent='测试中...'; try{const r=await api('/api/mail-accounts/test',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({account:mailAccountPayload(),protocol:$('mailTestProtocol').value})}); result.textContent='测试成功 '+r.result.protocol.toUpperCase(); toast('邮箱配置测试成功')}catch(e){result.textContent='测试失败'; toast('邮箱配置测试失败：'+e.message)}}
async function addMailAccount(){const payload=mailAccountPayload(); if(!payload.email||!payload.password){toast('请填写邮箱和授权码');return} await api('/api/mail-accounts',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)}); $('mailPassword').value=''; toast('邮箱账号已添加'); await loadConfig(); await loadAccounts()}
async function deleteMailAccount(name){const ok=await pageConfirm({title:'删除邮箱账号',message:'确定删除这个 POP3/SMTP/IMAP 邮箱账号吗？\n'+name,okText:'确认删除'});if(!ok)return; await api('/api/mail-accounts',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})}); toast('邮箱账号已删除'); await loadConfig(); await loadAccounts()}
async function batchDeleteMailAccounts(){const names=selectedMailAccounts();if(!names.length){toast('请先选择邮箱账号');return}const ok=await pageConfirm({title:'批量删除邮箱账号',message:`确定删除 ${names.length} 个 POP3/SMTP/IMAP 邮箱账号吗？`,okText:'确认删除'});if(!ok)return;await api('/api/mail-accounts',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({names})});toast('批量删除完成');await loadConfig();await loadAccounts()}
async function logout(){await api('/api/logout',{method:'POST'});location='/login'}
$('theme').onchange=e=>setTheme(e.target.value);$('accountSearch')?.addEventListener('input',renderAccounts);$('keyword').addEventListener('keydown',e=>{if(e.key==='Enter')search()});$('sender').addEventListener('keydown',e=>{if(e.key==='Enter')search()});$('account').onchange=()=>{markActiveAccount();search()};(async()=>{initTheme();initProviderOptions();await loadHealth();await loadAccounts();await search()})();
</script></body></html>"""


@APP.get("/login")
def login_page():
    return LOGIN_HTML.replace("{error}", "")


@APP.post("/login")
def login_post():
    admin = (load_config().get("webui") or {}).get("admin") or {}
    if request.form.get("username", "") == admin.get("username", "admin") and verify_password(request.form.get("password", ""), admin.get("password_hash", "")):
        session["admin_logged_in"] = True
        return redirect("/")
    return LOGIN_HTML.replace("{error}", "<div class='err'>用户名或密码错误</div>"), 401


@APP.get("/")
@require_login
def index():
    return APP_HTML


@APP.post("/api/logout")
@require_login
def api_logout():
    session.clear()
    return jsonify({"ok": True})


@APP.get("/api/health")
@require_login
def api_health():
    return jsonify({"ok": True, "accounts": len(fetch_accounts()), "time": datetime.now().isoformat()})


@APP.get("/api/accounts")
@require_login
def api_accounts():
    return jsonify({"ok": True, "accounts": fetch_accounts()})


@APP.get("/api/messages")
@require_login
def api_messages():
    return jsonify({"ok": True, "messages": fetch_messages(request.args.get("account") or None, request.args.get("keyword") or None, request.args.get("sender") or None, int(request.args.get("limit", "20")))})


@APP.post("/api/messages/<int:message_id>/delete")
@require_login
def api_delete_message(message_id: int):
    try:
        return jsonify({"ok": True, "result": move_message_to_deleted(message_id)})
    except Exception as e:
        return jsonify({"ok": False, "error": repr(e)}), 500


@APP.post("/api/messages/batch-delete")
@require_login
def api_batch_delete():
    payload = request.get_json(force=True) or {}
    ids = [int(x) for x in payload.get("ids", [])]
    results = []
    for mid in ids:
        try:
            results.append({"id": mid, "ok": True, "result": move_message_to_deleted(mid)})
        except Exception as e:
            results.append({"id": mid, "ok": False, "error": repr(e)})
    return jsonify({"ok": True, "success_count": sum(1 for r in results if r["ok"]), "failed_count": sum(1 for r in results if not r["ok"]), "results": results})


@APP.get("/api/config")
@require_login
def api_config_get():
    return jsonify({"ok": True, "config": sanitized_config(load_config())})


@APP.get("/api/debug/paths")
@require_login
def api_debug_paths():
    cfg = load_config()
    graph = cfg.get("graph_application") or {}
    return jsonify({
        "ok": True,
        "config_path": str(CONFIG_PATH),
        "config_exists": CONFIG_PATH.exists(),
        "db_path": str(DB_PATH),
        "db_exists": DB_PATH.exists(),
        "graph_enabled": bool(graph.get("enabled")),
        "graph_mailboxes_count": len(graph.get("mailboxes") or []),
        "graph_mailboxes": graph.get("mailboxes") or [],
        "local_accounts_count": len(cfg.get("accounts") or []),
    })


@APP.put("/api/config")
@require_login
def api_config_put():
    payload = request.get_json(force=True) or {}
    cfg = load_config()
    cfg["poll_interval"] = int(payload.get("poll_interval") or cfg.get("poll_interval") or 60)
    cfg["lookback_messages"] = int(payload.get("lookback_messages") or cfg.get("lookback_messages") or 30)
    cfg.setdefault("webui", {}).setdefault("admin", {})
    if payload.get("admin_username"):
        cfg["webui"]["admin"]["username"] = str(payload["admin_username"]).strip()
    if payload.get("admin_password"):
        cfg["webui"]["admin"]["password_hash"] = password_hash(str(payload["admin_password"]))
    graph_payload = payload.get("graph") or {}
    graph = cfg.setdefault("graph_application", {})
    for key in ["tenant_id", "client_id"]:
        if key in graph_payload:
            graph[key] = graph_payload[key]
    if graph_payload.get("client_secret"):
        graph["client_secret"] = graph_payload["client_secret"]
    if graph.get("tenant_id") and graph.get("client_id") and graph.get("client_secret"):
        graph["enabled"] = True
    save_config(cfg)
    return jsonify({"ok": True, "config": sanitized_config(cfg)})


@APP.route("/api/config/mailboxes", methods=["POST", "DELETE"])
@require_login
def api_mailboxes():
    payload = request.get_json(force=True) or {}
    raw_boxes = payload.get("mailboxes")
    if raw_boxes is None:
        raw_boxes = [payload.get("mailbox", "")]
    mailboxes = []
    for item in raw_boxes:
        mailbox = str(item or "").strip()
        if mailbox and "@" in mailbox:
            mailboxes.append(mailbox)
    if not mailboxes:
        return jsonify({"ok": False, "error": "invalid mailbox"}), 400
    cfg = load_config()
    graph = cfg.setdefault("graph_application", {})
    boxes = graph.setdefault("mailboxes", [])
    if request.method == "POST":
        graph["enabled"] = True
        existing = {m.lower() for m in boxes}
        for mailbox in mailboxes:
            if mailbox.lower() not in existing:
                boxes.append(mailbox)
                existing.add(mailbox.lower())
    else:
        remove_set = {m.lower() for m in mailboxes}
        graph["mailboxes"] = [m for m in boxes if m.lower() not in remove_set]
        cleanup_cached_accounts(mailboxes)
        cleanup_orphan_cache()
    save_config(cfg)
    return jsonify({"ok": True, "mailboxes": graph.get("mailboxes", [])})




@APP.get("/api/mail-provider-presets")
@require_login
def api_mail_provider_presets():
    return jsonify({"ok": True, "presets": MAIL_PROVIDER_PRESETS})


@APP.post("/api/mail-accounts/test")
@require_login
def api_mail_accounts_test():
    payload = request.get_json(force=True) or {}
    account = payload.get("account") or {}
    protocol = payload.get("protocol") or "imap"
    try:
        return jsonify({"ok": True, "result": test_mail_account(account, protocol)})
    except Exception as e:
        return jsonify({"ok": False, "error": repr(e)}), 500


@APP.route("/api/mail-accounts", methods=["POST", "DELETE"])
@require_login
def api_mail_accounts():
    payload = request.get_json(force=True) or {}
    cfg = load_config()
    accounts = cfg.setdefault("accounts", [])
    if request.method == "POST":
        email = str(payload.get("email") or "").strip()
        if not email or "@" not in email:
            return jsonify({"ok": False, "error": "invalid email"}), 400
        name = email.replace("@", "_").replace(".", "_")
        account = {
            "name": name,
            "provider": payload.get("provider") or "custom",
            "username": email,
            "password": payload.get("password") or "",
            "imap": payload.get("imap") or {},
            "smtp": payload.get("smtp") or {},
            "pop3": payload.get("pop3") or {},
            "enabled": True,
            "poll_interval": int(cfg.get("poll_interval") or 60),
            "filters": {"keywords": ["验证码", "verification", "security code", "otp", "code"]},
        }
        accounts[:] = [a for a in accounts if a.get("name") != name and a.get("username") != email]
        accounts.append(account)
    else:
        raw_names = payload.get("names")
        if raw_names is None:
            raw_names = [payload.get("name")]
        names = {str(x or "").strip() for x in raw_names if str(x or "").strip()}
        removed_usernames = [a.get("username") or a.get("email") for a in accounts if a.get("name") in names]
        accounts[:] = [a for a in accounts if a.get("name") not in names]
        if DB_PATH.exists() and names:
            conn = db_conn()
            try:
                # Delete both account rows and cached local messages so the
                # query page reflects mailbox deletion immediately.
                for name in names:
                    conn.execute("DELETE FROM messages WHERE account_name=?", (name,))
                    conn.execute("DELETE FROM accounts WHERE name=?", (name,))
                for username in removed_usernames:
                    if username:
                        conn.execute("DELETE FROM messages WHERE account_name=?", (username,))
                        conn.execute("DELETE FROM accounts WHERE username=?", (username,))
                conn.commit()
            finally:
                conn.close()
        cleanup_orphan_cache()
    save_config(cfg)
    return jsonify({"ok": True, "accounts": sanitized_accounts(cfg)})


@APP.put("/api/proxy")
@require_login
def api_proxy_put():
    payload = request.get_json(force=True) or {}
    proxy = payload.get("proxy") or {}
    cfg = load_config()
    webui = cfg.setdefault("webui", {})
    webui["proxy"] = {
        "enabled": bool(proxy.get("enabled")),
        "http_proxy": str(proxy.get("http_proxy", "")).strip(),
        "https_proxy": str(proxy.get("https_proxy", "")).strip(),
        "no_proxy": str(proxy.get("no_proxy", "")).strip(),
    }
    save_config(cfg)
    return jsonify({"ok": True, "proxy": webui["proxy"]})


@APP.post("/api/proxy/test")
@require_login
def api_proxy_test():
    payload = request.get_json(silent=True) or {}
    url = payload.get("url") or "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
    try:
        return jsonify({"ok": True, "result": test_proxy_connection(url)})
    except Exception as e:
        return jsonify({"ok": False, "error": repr(e)}), 500


@APP.post("/api/refresh")
@require_login
def api_refresh():
    payload = request.get_json(silent=True) or {}
    req = urllib.request.Request(REFRESH_URL, data=json.dumps(payload, ensure_ascii=False).encode(), method="POST", headers={"Content-Type": "application/json"})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=180) as resp:
            return jsonify(json.loads(resp.read().decode()))
    except Exception as e:
        return jsonify({"ok": False, "error": repr(e)}), 500


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default=os.environ.get("EMAIL_OTP_WEBUI_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("EMAIL_OTP_WEBUI_PORT", "8090")))
    args = parser.parse_args()
    save_config(load_config())
    APP.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()

