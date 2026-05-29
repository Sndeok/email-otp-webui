#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("email_otp_service.py")


def load_service():
    spec = importlib.util.spec_from_file_location("email_otp_service_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_extracts_openai_chinese_temporary_login_code():
    svc = load_service()
    subject = "你的临时 OpenAI 登录代码"
    sender = "noreply@tm.openai.com · ElijahBaker_takemehigher.onmicrosoft.com"
    body = "输入此临时验证码以继续： 596474 如果你无意登录 OpenAI，请 重置密码 。 谨致问候 OpenAI 团队 OpenAI 帮助中心"

    code, reason, score = svc.extract_code(subject, sender, body)

    assert code == "596474"
    assert score > 0
    assert reason


def test_does_not_extract_bare_numbers_from_openai_newsletters():
    svc = load_service()

    code, reason, score = svc.extract_code(
        "OpenAI Dev News: Realtime 2.0, Codex for Chrome, and beyond",
        "noreply@email.openai.com",
        "Lots of new launches and one date for you to save 2026. Images 2.0 is here.",
    )

    assert code is None
    assert reason == ""
    assert score == 0


def test_feature_word_allows_bare_number_fallback_when_regex_misses():
    svc = load_service()

    code, reason, score = svc.extract_code(
        "账号验证提醒",
        "service@example.test",
        "本次验证请求已提交，请在页面输入 864209 完成操作。",
    )

    assert code == "864209"
    assert "fallback" in reason
    assert score > 0


def test_code_feature_word_allows_uppercase_bare_number_fallback():
    svc = load_service()

    code, reason, score = svc.extract_code(
        "Your login Code",
        "security@example.test",
        "Use 135790 to finish signing in.",
    )

    assert code == "135790"
    assert "fallback" in reason
    assert score > 0


def test_codex_does_not_trigger_code_feature_word_fallback():
    svc = load_service()

    code, reason, score = svc.extract_code(
        "OpenAI Dev News: Realtime 2.0, Codex for Chrome, and beyond",
        "noreply@email.openai.com",
        "Lots of new launches and one date for you to save 2026. Images 2.0 is here.",
    )

    assert code is None
    assert reason == ""
    assert score == 0


def test_save_message_updates_existing_code_after_regex_fix(tmp_path):
    svc = load_service()
    db = tmp_path / "otp.sqlite3"
    svc.init_db(db)
    account = svc.parse_account({
        "name": "demo_163_com",
        "provider": "163",
        "username": "demo@163.com",
        "password": "secret",
        "imap": {"host": "imap.163.com", "port": 993, "ssl": True, "folder": "INBOX"},
    })
    svc.upsert_account(db, account)

    base = {
        "account_name": account.name,
        "uid": 100,
        "message_id": "<same-message>",
        "sender": "noreply@tm.openai.com",
        "recipient": "demo@163.com",
        "subject": "你的临时 OpenAI 登录代码",
        "date": "",
        "received_at": "2026-05-29T08:16:27Z",
        "snippet": "输入此临时验证码以继续： 596474",
        "body": "输入此临时验证码以继续： 596474 如果你无意登录 OpenAI，请 重置密码 。",
        "raw_headers": "{}",
    }

    svc.save_message(db, {**base, "code": None, "code_reason": "", "score": 0})
    svc.save_message(db, {**base, "code": "596474", "code_reason": "regression", "score": 6})

    rows = svc.query_messages(db, account=account.name, limit=10)
    assert len(rows) == 1
    assert rows[0]["code"] == "596474"
    assert rows[0]["code_reason"] == "regression"


def test_targeted_refresh_reports_missing_imap_account(tmp_path):
    svc = load_service()
    db = tmp_path / "otp.sqlite3"
    svc.init_db(db)

    result = svc.poll_all_accounts(db, {"accounts": []}, accounts=["missing_163_account"])

    assert result["ok"] is False
    assert result["error_count"] == 1
    assert "missing_163_account" in result["error"]


def make_raw_email(subject: str, sender: str, recipient: str, body: str) -> bytes:
    return (
        f"Subject: {subject}\n"
        f"From: {sender}\n"
        f"To: {recipient}\n"
        "Date: Fri, 29 May 2026 08:16:27 +0000\n"
        "Message-ID: <regression@example.test>\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\n"
        f"{body}\n"
    ).encode("utf-8")


class FakeIMAP:
    def __init__(self, *args, search_uids=b"1", raw_email=None, **kwargs):
        self.search_uids = search_uids
        self.raw_email = raw_email or make_raw_email("普通通知", "sender@example.test", "demo@163.com", "普通邮件内容")
        self.search_criteria = []

    def login(self, username, password):
        return "OK", [b"LOGIN completed"]

    def _simple_command(self, *args):
        return "OK", [b"ID completed"]

    def select(self, folder):
        return "OK", [b"1"]

    def uid(self, command, *args):
        if command == "SEARCH":
            self.search_criteria.append(args[-1])
            return "OK", [self.search_uids]
        if command == "FETCH":
            return "OK", [(b"1 (RFC822)", self.raw_email)]
        raise AssertionError(command)

    def logout(self):
        return "OK", [b"LOGOUT"]


def test_imap_poll_stores_recent_mail_even_when_filter_keywords_do_not_match(tmp_path):
    svc = load_service()
    db = tmp_path / "otp.sqlite3"
    svc.init_db(db)
    account = svc.parse_account({
        "name": "demo_163_com",
        "provider": "163",
        "username": "demo@163.com",
        "password": "secret",
        "imap": {"host": "imap.163.com", "port": 993, "ssl": True, "folder": "INBOX"},
        "filters": {"keywords": ["验证码"]},
    })
    svc.upsert_account(db, account)
    svc.imaplib.IMAP4_SSL = lambda *a, **kw: FakeIMAP(
        raw_email=make_raw_email("普通通知", "sender@example.test", "demo@163.com", "普通邮件内容")
    )

    result = svc.poll_account(db, account, lookback=10)

    assert result["processed"] == 1
    rows = svc.query_messages(db, account=account.name, limit=10)
    assert len(rows) == 1
    assert rows[0]["subject"] == "普通通知"
    assert rows[0]["code"] is None


def test_imap_poll_refetches_lookback_when_last_uid_exists_but_cache_is_empty(tmp_path):
    svc = load_service()
    db = tmp_path / "otp.sqlite3"
    svc.init_db(db)
    account = svc.parse_account({
        "name": "demo_163_com",
        "provider": "163",
        "username": "demo@163.com",
        "password": "secret",
        "imap": {"host": "imap.163.com", "port": 993, "ssl": True, "folder": "INBOX"},
    })
    svc.upsert_account(db, account)
    conn = svc.open_db(db)
    try:
        conn.execute("UPDATE accounts SET last_uid=100 WHERE name=?", (account.name,))
        conn.commit()
    finally:
        conn.close()

    fake = FakeIMAP(raw_email=make_raw_email("历史邮件", "sender@example.test", "demo@163.com", "旧邮件仍应回填"))
    svc.imaplib.IMAP4_SSL = lambda *a, **kw: fake

    result = svc.poll_account(db, account, lookback=10)

    assert result["processed"] == 1
    assert fake.search_criteria == ["ALL"]
    assert svc.query_messages(db, account=account.name, limit=10)[0]["subject"] == "历史邮件"
