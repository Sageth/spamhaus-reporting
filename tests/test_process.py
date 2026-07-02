"""Behavioural tests for process_message — what actually gets submitted.

submit() and rir_lookup() are patched so no network calls happen; we record
the (submission_type, object) of every submission the run would make.
"""
from conftest import spam


def _fresh_tracker():
    return {'ips': set(), 'domains': set(), 'urls': set(), 'emails': set()}


def test_allowlisted_sender_is_skipped_entirely(eml, captured_submissions):
    spam.process_message(eml('allowlisted_sender.eml'), _fresh_tracker())
    assert captured_submissions == []


def test_forged_brand_sender_is_reported_but_brand_is_not(eml, captured_submissions):
    # A spammer forges From: service@paypal.com but the message is not
    # authenticated for paypal.com (no DKIM, SPF passes only for the spammer's
    # own Return-Path). The message must NOT be skipped, the spam infrastructure
    # must be reported, and the spoofed brand must never be reported.
    spam.process_message(eml('forged_brand_sender.eml'), _fresh_tracker())

    assert captured_submissions != [], 'forged brand From must not skip the message'

    domains = {obj for typ, obj in captured_submissions if typ == 'domain'}
    urls    = {obj for typ, obj in captured_submissions if typ == 'url'}
    ips     = {obj for typ, obj in captured_submissions if typ == 'ip'}

    # The spoofed brand is never reported as an indicator. (The raw email sample
    # naturally still contains the forged "paypal.com" header string — that's
    # evidence, not a reported indicator, so we check indicator types only.)
    assert 'paypal.com' not in domains
    assert not any('paypal.com' in u for u in urls)

    # ...but the spammer's own IP, domain, and URL are.
    assert '45.92.72.99' in ips
    assert 'evil-spam.example' in domains
    assert any('evil-spam.example' in u for u in urls)


def test_injected_return_path_does_not_bypass_reporting(eml, captured_submissions):
    # Anti-evasion: SPF passed only for the spammer's own smtp.mailfrom
    # (evil-spam.example), but the message injects a second forged
    # Return-Path: <x@paypal.com>. Authentication must bind to the MTA-recorded
    # smtp.mailfrom, not the raw header — so paypal.com is NOT treated as
    # authenticated and the message is still reported.
    spam.process_message(eml('injected_return_path.eml'), _fresh_tracker())

    assert captured_submissions != [], 'injected Return-Path must not skip the message'
    domains = {obj for typ, obj in captured_submissions if typ == 'domain'}
    assert 'paypal.com' not in domains
    assert 'evil-spam.example' in domains


def test_allowlisted_url_host_is_not_submitted(eml, captured_submissions):
    spam.process_message(eml('allowlisted_url.eml'), _fresh_tracker())

    domains = {obj for typ, obj in captured_submissions if typ == 'domain'}
    urls    = {obj for typ, obj in captured_submissions if typ == 'url'}

    # The legitimate brand host linked inside the spam must not be reported,
    # neither as a URL nor as a landing domain.
    assert 'www.paypal.com' not in domains
    assert not any('paypal.com' in u for u in urls)

    # ...but the actual spam infrastructure still is.
    assert 'phish-bait.example' in domains
    assert any('phish-bait.example' in u for u in urls)


def test_spam_basic_submits_ip_domain_email_and_urls(eml, captured_submissions):
    spam.process_message(eml('spam_basic.eml'), _fresh_tracker())
    types = {typ for typ, _ in captured_submissions}
    assert {'ip', 'domain', 'email', 'url'} <= types

    objects = {obj for _, obj in captured_submissions}
    assert '45.92.72.11' in objects
    assert 'rewardsclaim.lat' in objects


def test_state_tracker_deduplicates_within_run(eml, captured_submissions):
    tracker = _fresh_tracker()
    spam.process_message(eml('spam_basic.eml'), tracker)
    first = len(captured_submissions)
    # Re-processing the same message in the same run should submit nothing new.
    spam.process_message(eml('spam_basic.eml'), tracker)
    assert len(captured_submissions) == first
