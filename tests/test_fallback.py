"""Tests for the escalating parse-fallback ladder and IP salvage (#3)."""
from conftest import spam


def _fresh_tracker():
    return {'ips': set(), 'domains': set(), 'urls': set(), 'emails': set()}


# ── _salvage_ip ────────────────────────────────────────────────────

def test_salvage_ip_from_spf(eml):
    assert spam._salvage_ip(eml('spam_basic.eml')) == '45.92.72.11'


def test_salvage_ip_rejects_internal(eml):
    assert spam._salvage_ip(eml('internal_ip_spf.eml')) is None


def test_salvage_ip_absent_when_no_spf(eml):
    assert spam._salvage_ip(eml('no_spf.eml')) is None


# ── process_message ladder ─────────────────────────────────────────

def test_valid_message_is_processed(eml, captured_submissions):
    assert spam.process_message(eml('spam_basic.eml'), _fresh_tracker()) == 'processed'


def test_falls_back_to_lenient(eml, captured_submissions, monkeypatch):
    def boom(*a, **k):
        raise ValueError('strict failed')
    monkeypatch.setattr(spam, '_attempt_strict', boom)

    # Lenient parse still handles a well-formed message, so the run succeeds.
    assert spam.process_message(eml('spam_basic.eml'), _fresh_tracker()) == 'processed'
    assert ('ip', '45.92.72.11') in captured_submissions


def test_minimal_salvage_runs_when_parsing_fails(eml, captured_submissions, monkeypatch):
    def boom(*a, **k):
        raise ValueError('parse failed')
    monkeypatch.setattr(spam, '_attempt_strict', boom)
    monkeypatch.setattr(spam, '_attempt_lenient', boom)

    assert spam.process_message(eml('spam_basic.eml'), _fresh_tracker()) == 'processed'
    # Only the salvaged IP should make it through — no domains/urls/email.
    assert captured_submissions == [('ip', '45.92.72.11')]


def test_all_attempts_fail_returns_failed(eml, captured_submissions, monkeypatch):
    def boom(*a, **k):
        raise ValueError('total failure')
    monkeypatch.setattr(spam, '_attempt_strict', boom)
    monkeypatch.setattr(spam, '_attempt_lenient', boom)
    monkeypatch.setattr(spam, '_attempt_minimal', boom)

    assert spam.process_message(eml('spam_basic.eml'), _fresh_tracker()) == 'failed'
    assert captured_submissions == []
