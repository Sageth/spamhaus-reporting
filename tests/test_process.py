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
