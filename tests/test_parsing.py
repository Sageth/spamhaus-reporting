"""Unit tests for the pure parsing/extraction layer."""
import pytest

from conftest import spam


# ── _normalize_domain ──────────────────────────────────────────────

@pytest.mark.parametrize('raw, expected', [
    ('Example.COM', 'example.com'),
    ('  example.com  ', 'example.com'),
    ('', ''),
    ('xn--e1afmkfd.xn--p1ai', 'xn--e1afmkfd.xn--p1ai'),
])
def test_normalize_domain(raw, expected):
    assert spam._normalize_domain(raw) == expected


# ── _is_allowlisted ────────────────────────────────────────────────

@pytest.mark.parametrize('domain, allowed', [
    ('google.com', True),               # exact match
    ('mail.google.com', True),          # subdomain of an entry
    ('deep.sub.paypal.com', True),      # nested subdomain
    ('notgoogle.com', False),           # suffix without a dot boundary
    ('evil-paypal.com', False),         # brand string but not a subdomain
    ('example.com', False),             # not in the list
])
def test_is_allowlisted(domain, allowed):
    assert spam._is_allowlisted(domain) is allowed


# ── apply_custom_allowlist ─────────────────────────────────────────

@pytest.fixture
def restore_allowlist():
    """apply_custom_allowlist mutates the module-global DOMAIN_ALLOWLIST;
    snapshot and restore it so tests don't leak into one another."""
    original = spam.DOMAIN_ALLOWLIST
    yield
    spam.DOMAIN_ALLOWLIST = original


def test_custom_allowlist_adds_and_matches(restore_allowlist):
    assert not spam._is_allowlisted('mytownship.gov')
    added = spam.apply_custom_allowlist(['mytownship.gov'])
    assert added == 1
    assert spam._is_allowlisted('mytownship.gov')          # exact
    assert spam._is_allowlisted('hoa.mytownship.gov')      # subdomain covered


def test_custom_allowlist_normalizes_and_dedupes(restore_allowlist):
    # Case-folded, whitespace-trimmed, leading '*.'/'.' stripped, blanks dropped,
    # and entries already present (built-in or duplicate) don't inflate the count.
    added = spam.apply_custom_allowlist(
        ['  MyTownship.GOV ', '*.mytownship.gov', '.mytownship.gov', '', 'paypal.com'])
    assert added == 1
    assert spam._is_allowlisted('mytownship.gov')


def test_custom_allowlist_does_not_drop_builtins(restore_allowlist):
    spam.apply_custom_allowlist(['mytownship.gov'])
    assert spam._is_allowlisted('google.com')              # built-in still there


# ── _is_internal_ip ────────────────────────────────────────────────

@pytest.mark.parametrize('ip, internal', [
    ('45.92.72.11', False),
    ('8.8.8.8', False),
    ('192.168.1.1', True),
    ('10.0.0.5', True),
    ('127.0.0.1', True),
    ('169.254.1.1', True),
    ('not-an-ip', True),                # unparseable treated as internal/untrusted
])
def test_is_internal_ip(ip, internal):
    assert spam._is_internal_ip(ip) is internal


# ── normalize_url ──────────────────────────────────────────────────

def test_normalize_url_strips_tracking_params():
    out = spam.normalize_url('https://example.com/go?utm_source=x&id=42&fbclid=y')
    assert out == 'https://example.com/go?id=42'


def test_normalize_url_drops_default_port_and_lowercases_host():
    assert spam.normalize_url('https://Example.COM:443/p') == 'https://example.com/p'


def test_normalize_url_sorts_remaining_params():
    out = spam.normalize_url('https://example.com/?b=2&a=1')
    assert out == 'https://example.com/?a=1&b=2'


@pytest.mark.parametrize('bad', [
    'https://example.com:notaport/',    # malformed port → ValueError
    'not a url at all',                 # no hostname
    'mailto:someone@example.com',       # no hostname
])
def test_normalize_url_returns_none_on_garbage(bad):
    assert spam.normalize_url(bad) is None


# ── _is_unsubscribe_link (boundary-aware, not raw substring) ───────

@pytest.mark.parametrize('href, is_unsub', [
    ('https://x.com/unsubscribe?u=1', True),     # path segment
    ('https://x.com/manage/opt-out', True),      # hyphenated segment
    ('https://x.com/p?optout=1', True),          # query-key name
    ('https://optout.mailer.example/x', True),   # host label
    ('https://x.com/account/remove-hold?id=9', False),  # the false-skip we fixed
    ('https://x.com/remove-item', False),        # 'remove' is no longer a token
    ('https://x.com/go?action=continue', False), # ordinary CTA
])
def test_is_unsubscribe_link(href, is_unsub):
    assert spam._is_unsubscribe_link(href) is is_unsub


# ── header extraction (fixtures) ───────────────────────────────────

def test_extract_sending_ip_from_spf(eml):
    parsed = spam.parse_message(eml('spam_basic.eml'))
    assert parsed['ip'] == '45.92.72.11'


def test_internal_spf_ip_is_dropped(eml):
    parsed = spam.parse_message(eml('internal_ip_spf.eml'))
    assert parsed['ip'] is None


def test_missing_spf_yields_no_ip(eml):
    parsed = spam.parse_message(eml('no_spf.eml'))
    assert parsed['ip'] is None


def test_primary_domain_prefers_dkim(eml):
    parsed = spam.parse_message(eml('spam_basic.eml'))
    assert parsed['primary_domain'] == 'rewardsclaim.lat'


def test_envelope_domains(eml):
    parsed = spam.parse_message(eml('spam_basic.eml'))
    assert parsed['envelope_domains'] == {'rewardsclaim.lat'}


def test_auth_results(eml):
    parsed = spam.parse_message(eml('spam_basic.eml'))
    auth = parsed['auth']
    assert auth['spf'] == 'pass'
    assert auth['dkim'] == 'pass'
    assert auth['dmarc'] == 'pass'
    assert auth['dmarc_policy'] == 'none'


def test_cta_urls_strip_tracking_and_skip_unsubscribe(eml):
    parsed = spam.parse_message(eml('spam_basic.eml'))
    urls = set(parsed['urls'])
    assert 'https://rewardsclaim.lat/go?id=42' in urls
    assert 'https://track.rewardsclaim.lat/click' in urls
    assert not any('unsubscribe' in u for u in urls)


# ── verified DKIM domains (trust the MTA, not the raw signature) ────

def test_auth_results_capture_verified_dkim_domain(eml):
    parsed = spam.parse_message(eml('spam_basic.eml'))
    assert parsed['auth']['dkim_domains'] == {'rewardsclaim.lat'}


def test_forged_dkim_domain_on_failed_signature_is_not_used(eml):
    # The message carries a raw DKIM-Signature d=bigbank.com, but our MTA
    # recorded dkim=fail — so bigbank.com is unverified and must not appear.
    parsed = spam.parse_message(eml('dkim_poison.eml'))
    assert parsed['auth']['dkim_domains'] == set()
    assert 'bigbank.com' not in parsed['envelope_domains']
    assert parsed['envelope_domains'] == {'spammer-xyz.lat'}
    assert parsed['primary_domain'] == 'spammer-xyz.lat'


def test_dkim_domain_parsing_tolerates_semicolon_in_comment():
    raw = (
        b'Authentication-Results: mx.example.com; '
        b'dkim=pass (1024-bit key; unprotected) header.d=signed.example; '
        b'spf=pass smtp.mailfrom=signed.example\r\n'
        b'From: x@signed.example\r\n'
        b'Subject: t\r\n\r\nbody\r\n'
    )
    parsed = spam.parse_message(raw)
    assert parsed['auth']['dkim'] == 'pass'
    assert parsed['auth']['dkim_domains'] == {'signed.example'}
