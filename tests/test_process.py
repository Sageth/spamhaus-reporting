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


def test_forwarded_spam_reports_sender_not_the_forwarding_path(eml, captured_submissions):
    # Spam sent to info@victim-forward.example, which forwards to the monitored
    # mailbox. The forwarder SRS-rewrote the envelope sender into its own domain
    # and its platform re-signed the message, so our MTA honestly records
    # spf=pass for victim-forward.example and dkim=pass for both it and
    # relay-forward.example. None of that is the spammer — only the DKIM signer
    # aligned with From is. The topmost Received-SPF is the forwarder's relay
    # too, so no IP is reportable at all.
    spam.process_message(eml('forwarded_srs.eml'), _fresh_tracker())

    domains = {obj for typ, obj in captured_submissions if typ == 'domain'}
    urls    = {obj for typ, obj in captured_submissions if typ == 'url'}
    ips     = {obj for typ, obj in captured_submissions if typ == 'ip'}

    assert 'victim-forward.example' not in domains, 'forwarding victim reported as spammer'
    assert 'relay-forward.example' not in domains, 'forwarding platform reported as spammer'
    assert ips == set(), 'forwarder relay IP must not be reported'

    # ...and the actual spammer still is, fully.
    assert 'webdesign-spam.example' in domains
    assert any('webdesign-spam.example' in u for u in urls)
    emails = {obj for typ, obj in captured_submissions if typ == 'email'}
    assert len(emails) == 1, 'the raw sample is still submitted, keyed on the sender'


def test_srs_shaped_return_path_does_not_suppress_reporting(eml, captured_submissions):
    # Anti-evasion mirror of the test above: the spammer injects an SRS-shaped
    # Return-Path naming a third party, hoping to be mistaken for a forwarder and
    # dropped. Forwarding is only ever read from the MTA-recorded smtp.mailfrom
    # (here a plain bounce@evil-spam.example), so nothing is suppressed.
    spam.process_message(eml('srs_shaped_return_path.eml'), _fresh_tracker())

    domains = {obj for typ, obj in captured_submissions if typ == 'domain'}
    ips     = {obj for typ, obj in captured_submissions if typ == 'ip'}
    assert 'evil-spam.example' in domains
    assert '45.92.72.99' in ips


def test_self_wrapped_srs_envelope_does_not_suppress_reporting(eml, captured_submissions):
    # The spammer SRS-shapes their *real* envelope sender, so even the trusted
    # smtp.mailfrom looks like a forward. It buys nothing: the SRS wrapper domain
    # is the same domain the message is DKIM-aligned for, so there is no separate
    # origin to fall back to and no domain is treated as a forwarding hop.
    spam.process_message(eml('srs_self_wrapped.eml'), _fresh_tracker())

    domains = {obj for typ, obj in captured_submissions if typ == 'domain'}
    ips     = {obj for typ, obj in captured_submissions if typ == 'ip'}
    assert 'evil-spam.example' in domains
    assert '45.92.72.99' in ips


def test_forwarded_unsigned_spam_still_spares_the_forwarding_victim(eml, captured_submissions):
    # Same forward as above, but the spam carries no DKIM of its own, so there is
    # no aligned signer to identify the forwarding platform's signature by. The
    # SRS wrapper alone still proves the forwarding domain and the relay IP are
    # not the sender, and both are dropped; the platform's own signing domain is
    # left in, because at this point it is indistinguishable from a spammer's ESP.
    spam.process_message(eml('forwarded_srs_unsigned.eml'), _fresh_tracker())

    domains = {obj for typ, obj in captured_submissions if typ == 'domain'}
    ips     = {obj for typ, obj in captured_submissions if typ == 'ip'}

    assert 'victim-forward.example' not in domains
    assert ips == set(), 'forwarder relay IP must not be reported'
    assert 'webdesign-spam.example' in domains
