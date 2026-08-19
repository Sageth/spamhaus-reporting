#!/usr/bin/env python3
"""
spam-automation.py — Automated spam analysis and Spamhaus submission

Monitors an IMAP Junk folder for spam, extracts infrastructure indicators,
and submits them to the Spamhaus API. Uses a custom IMAP flag for state
tracking — no local database or flat files required.

Required environment variables:
    SPAMHAUS_TOKEN   — your Spamhaus submission API token

    Single-mailbox mode (mutually exclusive with ACCOUNTS_CONFIG):
    IMAP_SERVER      — e.g. mail.example.com
    IMAP_PORT        — e.g. 993 (default)
    IMAP_USER        — your full email address
    IMAP_PASSWORD    — your IMAP password

    Multi-mailbox mode:
    ACCOUNTS_CONFIG  — path to a JSON file listing mailbox configs (see accounts.example.json).
                       An optional top-level "allowlist" array in that file adds
                       your own never-report domains (township, personal, etc.)
                       to the built-in set — see DOMAIN_ALLOWLIST / apply_custom_allowlist.

Optional environment variables:
    IMAP_FOLDER      — folder to watch (default: Junk); per-account override available in config file
    DRY_RUN          — set to "1" to parse without submitting (default: 0)
    DELAY            — seconds between API calls (default: 2)
    VERBOSE_LIST     — set to "1" to log every submission with its status (default: 0)

Usage:
    python3 spam-automation.py             # run once
    python3 spam-automation.py --daemon    # run continuously
    DRY_RUN=1 python3 spam-automation.py   # dry run
"""

import imaplib
import email
import email.policy
import json
import os
import re
import sys
import time
import logging
import argparse
import socket
import ipaddress
import requests
from collections import defaultdict
from email.utils import getaddresses
from functools import lru_cache
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────
# CONFIGURATION FROM ENVIRONMENT
# ─────────────────────────────────────────────

IMAP_SERVER    = os.environ.get('IMAP_SERVER', '')
IMAP_PORT      = int(os.environ.get('IMAP_PORT', 993))
IMAP_USER      = os.environ.get('IMAP_USER', '')
IMAP_PASSWORD  = os.environ.get('IMAP_PASSWORD', '')
SPAMHAUS_TOKEN = os.environ.get('SPAMHAUS_TOKEN', '')
IMAP_FOLDER    = os.environ.get('IMAP_FOLDER', 'Junk')
DRY_RUN        = os.environ.get('DRY_RUN', '0').strip() == '1'
DELAY          = float(os.environ.get('DELAY', '2'))
VERBOSE_LIST   = os.environ.get('VERBOSE_LIST', '0').strip() == '1'
ACCOUNTS_CONFIG = os.environ.get('ACCOUNTS_CONFIG', '')

SPAMHAUS_API    = 'https://submit.spamhaus.org/portal/api/v1'
RIR_API         = 'https://stat.ripe.net/data/whois/data.json'

# Custom IMAP keyword flag set on messages after processing.
# State lives on the mail server — no local files needed.
# Spamhaus 208 ("already reported") handles any indicator duplicates across runs.
PROCESSED_FLAG  = '$SpamhausProcessed'
CAPABILITY_FLAG = '$SpamhausCapabilityTest'
# Set when every parse attempt (strict → lenient → minimal) fails, so a poison
# message is not retried forever yet stays visibly distinct from clean mail.
FAILED_FLAG     = '$SpamhausFailed'

# Envelope-sender local parts written by the Sender Rewriting Scheme. A forwarder
# (mailing list, Cloudflare Email Routing, a .forward rule) rewrites the envelope
# sender into its own domain so SPF still passes after the extra hop — meaning a
# downstream spf=pass describes the *forwarder*, not the original sender.
# SRS0/SRS1 with the '=', '+' and '-' separators all appear in the wild.
_SRS_LOCAL = re.compile(r'^srs[01][=+-]', re.IGNORECASE)

# Tracking parameters appended by spam campaigns to generate unique URLs per recipient.
_TRACKING_PARAMS = frozenset({
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'msclkid', 'mc_eid', 'mc_cid',
})

# Well-known legitimate brands that should never be submitted to Spamhaus.
# Two independent protections use this set:
#   1. A message is skipped entirely when one of its *authenticated* domains
#      (MTA-verified DKIM signer, or SPF-passing envelope-from) matches an entry
#      here AND aligns with From — see extract_sender_domains / submit_parsed.
#      A merely *claimed* From/Reply-To domain is intentionally NOT enough, or a
#      forged From: x@paypal.com would let any spammer dodge reporting; an
#      unaligned authenticated domain is not enough either, or a forwarding hop
#      could veto the report for spam it only relayed.
#   2. An allowlisted domain is never reported as an indicator, even inside an
#      otherwise-reportable spam (e.g. a spoofed brand in the From line).
# Match is exact or on a subdomain (foo.paypal.com matches paypal.com).
#
# Only include a brand's OWN domains — the corporate domain a brand sends its
# own mail from. Never add the *sending or tracking* infrastructure of a shared
# platform (sendgrid.net, mailgun.org, sparkpostmail.com, ccsend.com, rs6.net,
# list-manage.com, hubspotemail.net, klclick.com, s3.amazonaws.com …). Real
# spammers send and host through those too, and because matching covers
# subdomains, one entry there blinds the URL and landing-domain checks for every
# campaign built on that platform. amazonaws.com is deliberately absent for
# exactly this reason: it would swallow every phishing page on an S3 bucket.
DOMAIN_ALLOWLIST = frozenset({
    # Consumer email providers. Note these are the one category where protection
    # #1 has real cost: spam sent from a genuine throwaway account at one of
    # these authenticates and aligns, so it is skipped rather than reported.
    'aol.com',
    'att.net',
    'charter.net',
    'comcast.net',
    'cox.net',
    'earthlink.net',
    'fastmail.com',
    'gmail.com',
    'gmx.com',
    'googlemail.com',
    'hey.com',
    'hotmail.com',
    'icloud.com',
    'live.com',
    'mail.com',
    'me.com',
    'msn.com',
    'outlook.com',
    'proton.me',
    'protonmail.com',
    'sbcglobal.net',
    'tuta.com',
    'tutanota.com',
    'verizon.net',
    'yahoo.com',
    'yandex.com',
    'ymail.com',
    'zoho.com',
    # Big tech / cloud / developer platforms
    'accounts.google.com',
    'adobe.com',
    'amazon.com',
    'apple.com',
    'atlassian.com',
    'cloudflare.com',
    'cloudflare-email.net',
    'dropbox.com',
    'github.com',
    'gitlab.com',
    'godaddy.com',
    'google.com',
    'ibm.com',
    'mail.google.com',
    'microsoft.com',
    'microsoftonline.com',
    'office.com',
    'okta.com',
    'oracle.com',
    'redhat.com',
    'salesforce.com',
    'slack.com',
    'zoom.us',
    # Email marketing platforms — CORPORATE domains only, for the mail these
    # companies send about themselves. Their customer campaigns go out under the
    # customer's own From and are unaffected. Their sending and link-tracking
    # domains are deliberately excluded (see the note above).
    'brevo.com',
    'constantcontact.com',
    'hubspot.com',
    'klaviyo.com',
    'mailchimp.com',
    'mailgun.com',
    'sendgrid.com',
    # Social / media / consumer services
    'discord.com',
    'facebook.com',
    'facebookmail.com',
    'instagram.com',
    'linkedin.com',
    'netflix.com',
    'pinterest.com',
    'reddit.com',
    'redditmail.com',
    'snapchat.com',
    'spotify.com',
    'tiktok.com',
    'twitch.tv',
    'x.com',
    'youtube.com',
    # Finance / payments / commerce
    'ally.com',
    'americanexpress.com',
    'bankofamerica.com',
    'capitalone.com',
    'cash.app',
    'chase.com',
    'citi.com',
    'coinbase.com',
    'discover.com',
    'ebay.com',
    'etsy.com',
    'fidelity.com',
    'intuit.com',
    'jpmorgan.com',
    'navyfederal.org',
    'paypal.com',
    'pnc.com',
    'robinhood.com',
    'schwab.com',
    'shopify.com',
    'squareup.com',
    'stripe.com',
    'truist.com',
    'usbank.com',
    'venmo.com',
    'wellsfargo.com',
    'wise.com',
    'zellepay.com',
    # Retail / travel / delivery services
    'airbnb.com',
    'bestbuy.com',
    'booking.com',
    'costco.com',
    'doordash.com',
    'instacart.com',
    'target.com',
    'uber.com',
    'walmart.com',
    # Telecom
    'att.com',
    't-mobile.com',
    'verizon.com',
    'xfinity.com',
    # Government, credit bureaus, identity and security vendors — the domains
    # most costly to report by mistake, and among the most forged
    '1password.com',
    'docusign.com',
    'docusign.net',
    'equifax.com',
    'experian.com',
    'irs.gov',
    'lastpass.com',
    'mcafee.com',
    'norton.com',
    'ssa.gov',
    'transunion.com',
    # Shipping / delivery (heavily spoofed — protection #1's auth gate matters
    # most here; a forged From: ups.com with no valid DKIM/SPF is still reported)
    'dhl.com',
    'fedex.com',
    'ups.com',
    'usps.com',
})

# Enforce a global socket timeout to prevent half-open TCP hangs
socket.setdefaulttimeout(60)

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────

def _normalize_domain(domain):
    """Normalize a domain using IDNA encoding to collapse internationalized variants."""
    if not domain:
        return ''
    try:
        return domain.strip().encode('idna').decode('ascii').lower()
    except Exception:
        return domain.strip().lower()

def _is_allowlisted(domain):
    """Return True if domain exactly matches or is a subdomain of any allowlist entry."""
    return any(domain == a or domain.endswith('.' + a) for a in DOMAIN_ALLOWLIST)

def apply_custom_allowlist(entries):
    """Merge user-supplied allowlist domains (the ACCOUNTS_CONFIG "allowlist"
    array) into the built-in set. Entries are IDNA-normalized and lowercased so
    they match subdomains exactly like the built-ins — 'mytownship.gov' also
    covers 'hoa.mytownship.gov'. A leading '*.' or '.' is tolerated. Custom
    domains ride the same auth gate as the built-ins: a forged From on one still
    gets reported unless the message is actually authenticated for it.
    Returns the number of domains added that were not already present."""
    global DOMAIN_ALLOWLIST
    extra = set()
    for e in entries:
        d = _normalize_domain(str(e).strip().lstrip('*').lstrip('.'))
        if d:
            extra.add(d)
    added = extra - DOMAIN_ALLOWLIST
    DOMAIN_ALLOWLIST = frozenset(DOMAIN_ALLOWLIST | extra)
    return len(added)

def _is_internal_ip(ip):
    """Return True if the IP string is loopback, private, link-local, or reserved."""
    try:
        return _is_internal_addr(ipaddress.ip_address(ip))
    except ValueError:
        return True

def _is_internal_addr(addr):
    """Return True if the ipaddress object is loopback, private, link-local, or reserved."""
    return (addr.is_private or addr.is_loopback or
            addr.is_link_local or addr.is_reserved)

# ─────────────────────────────────────────────
# EMAIL PARSING
# ─────────────────────────────────────────────

def extract_sending_ip(msg):
    """Extract sending IP from the topmost Received-SPF header.
    Only the topmost header is trusted — it was written by our MTA on arrival.
    Lower headers could be forged by the sender. If Received-SPF is absent,
    no IP is extracted rather than risk reporting a legitimate forwarding hop."""
    spf_headers = msg.get_all('Received-SPF') or []
    if spf_headers:
        match = re.search(r'client-ip=([0-9a-fA-F.:]+)', str(spf_headers[0]))
        if match:
            ip = match.group(1).strip()
            if not _is_internal_ip(ip):
                return ip
    return None

def _header_domains(msg, field):
    """IDNA-normalized domains from the addresses in a header field."""
    domains = set()
    # Cast to str — email.policy.default returns header objects not raw strings
    headers_raw = [str(h) for h in (msg.get_all(field) or [])]
    for _, addr in getaddresses(headers_raw):
        if '@' in addr:
            domain = _normalize_domain(addr.rsplit('@', 1)[1])
            if domain:
                domains.add(domain)
    return domains

def extract_envelope_domains(msg, dkim_domains):
    """Extract all unique IDNA-normalized sending domains.
    Combines the claimed envelope/header domains (From, Reply-To, Return-Path)
    with the DKIM signing domains our MTA actually verified (dkim_domains).
    Raw DKIM-Signature d= tags are intentionally not read — they are unverified
    and forgeable; see extract_auth_results."""
    domains = set(dkim_domains)
    for field in ('From', 'Reply-To', 'Return-Path'):
        domains |= _header_domains(msg, field)
    return domains

def _aligns_with(domain, others):
    """True when domain is one of others, or a sub/parent domain of one."""
    return any(domain == o or domain.endswith('.' + o) or o.endswith('.' + domain)
               for o in others)

def _aligned_dkim_domains(msg, dkim_domains):
    """The verified DKIM signers organizationally aligned with the From domain.
    An aligned signer vouched for the address the message claims to be from, so
    it is the accountable origin; unaligned signers belong to someone else on the
    delivery path (an ESP, or a forwarder — see extract_forwarder_domains)."""
    from_domains = _header_domains(msg, 'From')
    return {d for d in dkim_domains if _aligns_with(d, from_domains)}

def extract_primary_domain(msg, dkim_domains):
    """Extract the primary sending domain, preferring a DKIM signing domain our
    MTA verified (Authentication-Results dkim=pass header.d=) over the Return-Path
    claim. A verified signer is the accountable origin and cannot be a forged
    third party. When several signers verified, prefer the one aligned with the
    From domain, else pick deterministically. Falls back to Return-Path when
    nothing was DKIM-verified."""
    if dkim_domains:
        aligned = sorted(_aligned_dkim_domains(msg, dkim_domains))
        return aligned[0] if aligned else sorted(dkim_domains)[0]

    headers_raw = [str(h) for h in (msg.get_all('Return-Path') or [])]
    for _, addr in getaddresses(headers_raw):
        if '@' in addr:
            return _normalize_domain(addr.rsplit('@', 1)[1])

    return None

def extract_sender_domains(msg, auth):
    """Domains that authenticated *as the sender* — the only domains the
    allowlist is permitted to skip a whole message on.

    Two conditions, both required.

    First, the receiving MTA must actually have vouched for the domain. A brand
    name in From/Reply-To/Return-Path is a forgeable claim: without this gate,
    any spammer could dodge reporting by writing From: x@paypal.com. So we trust
    only two things our MTA verified:
      - DKIM signing domains it validated (dkim=pass header.d=), and
      - the envelope-from domain SPF validated (spf=pass smtp.mailfrom=…) — SPF
        authorizes the sending IP for that domain, so it cannot be forged from
        an unrelated network. We bind to the MTA-recorded smtp.mailfrom, NOT the
        raw Return-Path header, which a sender can inject a second copy of.

    Second, the domain must align with From. Authenticating is not the same as
    being the sender: every relay on the delivery path authenticates for itself.
    A Gmail account that forwards its mail to you produces spf=pass and dkim=pass
    for gmail.com on somebody else's spam — and gmail.com is allowlisted, so
    without alignment the forward would silently veto the report. Requiring the
    allowlisted identity to be the one in From is the same test DMARC applies,
    and it keeps the skip about who the mail is *from* rather than about which
    infrastructure carried it."""
    authed = set(auth.get('dkim_domains') or ())
    if auth.get('spf') == 'pass' and auth.get('spf_domain'):
        authed.add(auth['spf_domain'])
    return {d for d in authed if _aligns_with(d, _header_domains(msg, 'From'))}

def extract_forwarder_domains(msg, auth):
    """Domains that belong to a forwarding hop rather than to the sender.

    When spam is forwarded — a mailing list, Cloudflare Email Routing, a plain
    .forward — the forwarder SRS-rewrites the envelope sender into its own domain
    and re-signs the message with its own DKIM keys. Our MTA then honestly reports
    spf=pass for the forwarder and dkim=pass for the forwarding platform, and
    every one of those domains lands in envelope_domains. Submitting them reports
    the *victim's own domain* (and the forwarding platform) to Spamhaus for spam
    they merely relayed. The same hop supplies the topmost Received-SPF, so the
    sending IP is the forwarder's relay too — see parse_message.

    Detection never reads the raw Return-Path: a sender can inject a second copy
    of that header (see extract_sender_domains), so an SRS-shaped
    Return-Path would otherwise be a free way to shed a domain indicator. The SRS
    wrapper is read only from the MTA-recorded smtp.mailfrom, and it is ignored
    when it belongs to the sender themselves — a spammer who SRS-shapes their own
    envelope-from gains nothing, because the wrapper domain is then the very
    domain they claim in From/Reply-To (or sign for) and stays reportable.

    Re-signing domains are only subtracted when some signer *is* aligned with
    From, or when the signer is allowlisted. Without an aligned signer there is
    no way to tell a forwarding platform's signature from the spammer's own ESP,
    and guessing would drop real indicators — so on unsigned forwarded spam only
    the wrapper domain, allowlisted forwarding infrastructure, and (in
    parse_message) the relay IP are dropped."""
    if not _SRS_LOCAL.match(auth.get('spf_local') or ''):
        return set()
    wrapper = auth.get('spf_domain') or ''
    if not wrapper:
        return set()

    dkim_domains = set(auth.get('dkim_domains') or ())
    aligned = _aligned_dkim_domains(msg, dkim_domains)
    claimed = _header_domains(msg, 'From') | _header_domains(msg, 'Reply-To')
    if _aligns_with(wrapper, claimed | aligned):
        return set()

    forwarders = {wrapper}
    if aligned:
        # The origin signed for itself, so every other verified signer on the
        # message was added by the forwarding path.
        forwarders |= dkim_domains - aligned
    else:
        # No aligned signer, so a re-signing domain is ambiguous — except when it
        # is allowlisted, which no spammer's own ESP will be. Dropping it costs
        # nothing (an allowlisted domain is never reported as an indicator) and
        # buys something specific: left in, it would be the only candidate for
        # primary_domain, and an allowlisted primary_domain suppresses the raw
        # email sample in submit_parsed. Without this the sample silently goes
        # unsubmitted on every unsigned forward through allowlisted infra.
        forwarders |= {d for d in dkim_domains if _is_allowlisted(d)}
    return forwarders

def extract_auth_results(msg):
    """Extract SPF, DKIM, DMARC results from Authentication-Results header.
    Uses the top-most header (written by our MTA), strips line folding,
    and extracts the first result per type.

    Also returns 'dkim_domains': the set of signing domains our MTA actually
    verified (header.d= on a dkim=pass result). These are the only DKIM domains
    we trust — raw DKIM-Signature d= tags are unverified claims and can be forged
    to frame a third party, so they are deliberately not used."""
    empty = {'spf': 'unknown', 'dkim': 'unknown', 'dmarc': 'unknown',
             'dmarc_policy': 'unknown', 'dkim_domains': set(), 'spf_domain': '',
             'spf_local': ''}
    auth_headers = msg.get_all('Authentication-Results') or []
    if not auth_headers:
        return empty

    # Top-most header is from our MTA — flatten line folding
    auth = re.sub(r'\s+', ' ', str(auth_headers[0]))

    def extract(pattern):
        m = re.search(pattern, auth, re.IGNORECASE)
        return m.group(1).lower() if m else 'unknown'

    spf          = extract(r'\bspf=(pass|fail|softfail|neutral|none|permerror|temperror)\b')
    dkim         = extract(r'\bdkim=(pass|fail|none|policy|neutral|temperror|permerror)\b')
    dmarc        = extract(r'\bdmarc=(pass|fail|none|bestguesspass|temperror|permerror)\b')
    # p= legitimately lives inside the DMARC comment "(p=none ...)", so policy is
    # read from the comment-bearing string.
    dmarc_policy = extract(r'\b(?:policy\.[A-Za-z_-]*|p)=([A-Za-z]+)')

    # The envelope-from domain SPF actually validated, as our MTA recorded it.
    # Bind the SPF result to THIS domain, not to raw Return-Path headers a sender
    # can inject — see extract_sender_domains.
    # The value may be quoted when the local part contains specials, as SRS
    # wrappers do: smtp.mailfrom="SRS0=aB=cD=origin.example=user@forwarder.example".
    # spf_local keeps that local part so extract_forwarder_domains can spot SRS.
    mf = re.search(r'smtp\.mailfrom="?(?:([^@\s;"]*)@)?([a-zA-Z0-9.-]+)',
                   auth, re.IGNORECASE)
    spf_domain = _normalize_domain(mf.group(2).strip('.')) if mf else ''
    spf_local  = (mf.group(1) or '') if mf else ''

    # Strip parenthetical comments before splitting on ';' — comments may contain
    # ';' (e.g. "(1024-bit key; unprotected)") which would corrupt the split.
    dkim_domains = set()
    for chunk in re.sub(r'\([^)]*\)', ' ', auth).split(';'):
        if re.search(r'\bdkim=pass\b', chunk, re.IGNORECASE):
            dm = (re.search(r'header\.d=([a-zA-Z0-9.-]+)', chunk, re.IGNORECASE) or
                  re.search(r'header\.i=(?:[^@\s]*@)?([a-zA-Z0-9.-]+)', chunk, re.IGNORECASE))
            if dm:
                domain = _normalize_domain(dm.group(1).strip('.'))
                if domain:
                    dkim_domains.add(domain)

    return {'spf': spf, 'dkim': dkim, 'dmarc': dmarc,
            'dmarc_policy': dmarc_policy, 'dkim_domains': dkim_domains,
            'spf_domain': spf_domain, 'spf_local': spf_local}

def normalize_url(href):
    """Strip tracking parameters, sort remaining params, lowercase hostname,
    and strip default ports for consistent deduplication.
    Returns None if the URL is critically malformed so callers can discard it."""
    try:
        parsed = urlparse(href)
        port = parsed.port  # raises ValueError on malformed ports e.g. :abc
        clean_params = sorted(
            (k, v) for k, v in parse_qsl(parsed.query)
            if k.lower() not in _TRACKING_PARAMS
        )
        hostname = _normalize_domain(parsed.hostname or '')
        if not hostname:
            return None
        # Strip scheme-default ports
        if (parsed.scheme == 'https' and port == 443) or (parsed.scheme == 'http' and port == 80):
            port = None
        netloc = hostname if port is None else f'{hostname}:{port}'
        return urlunparse(parsed._replace(netloc=netloc, query=urlencode(clean_params)))
    except Exception:
        return None

# Tokens that mark a link as an unsubscribe/opt-out endpoint (structural, not a
# malicious payload). Matched against host labels, path segments, and query-key
# names only — not the raw href — so a path like /remove-hold is not mistaken for
# one. 'remove' is intentionally excluded: too generic, it false-matched here.
_UNSUB_TOKENS = ('unsub', 'optout', 'opt-out', 'opt_out')

def _is_unsubscribe_link(href):
    """True if the URL looks like an unsubscribe/opt-out endpoint, judged from its
    host labels, path segments, and query-parameter names (boundary-aware)."""
    try:
        parsed = urlparse(href)
    except ValueError:
        return False
    candidates = [label for label in (parsed.hostname or '').lower().split('.') if label]
    candidates += [seg.lower() for seg in parsed.path.split('/') if seg]
    candidates += [k.lower() for k, _ in parse_qsl(parsed.query)]
    return any(tok in cand for cand in candidates for tok in _UNSUB_TOKENS)

def extract_cta_urls(msg):
    """Extract action URLs from HTML body. Strips tracking parameters and skips
    unsubscribe/optout links which are structural, not malicious endpoints."""
    urls = set()
    for part in msg.walk():
        if part.get_content_type() == 'text/html':
            soup = None
            try:
                html = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                soup = BeautifulSoup(html, 'html.parser')
                for a in soup.find_all('a', href=True):
                    href = a['href'].strip()
                    if not href.startswith(('http://', 'https://')):
                        continue
                    if _is_unsubscribe_link(href):
                        continue
                    normalized = normalize_url(href)
                    if normalized:
                        urls.add(normalized)
            except Exception as e:
                log.debug(f'URL extraction error: {e}')
            finally:
                if soup:
                    soup.decompose()
    return list(urls)

@lru_cache(maxsize=2048)
def rir_lookup(ip):
    """Look up IP infrastructure details via RIPE Stat (aggregates all RIRs globally).
    Results cached with a fixed upper bound via lru_cache to prevent memory growth."""
    if not ip:
        return {}
    try:
        resp = requests.get(
            RIR_API,
            params={'resource': ip},
            headers={'Accept': 'application/json'},
            timeout=8
        )
        if not resp.ok:
            return {}
        records = resp.json().get('data', {}).get('records', [])
        result = {}
        for group in records:
            for record in group:
                key = record.get('key', '').lower()
                if key in ('netname', 'org', 'country', 'descr'):
                    result[key] = record.get('value', '')
        return result
    except Exception as e:
        log.debug(f'RIR lookup failed for {ip}: {e}')
        return {}

def parse_message(raw_bytes, policy=email.policy.default):
    """Parse a raw email and extract all indicators.
    policy is overridable so callers can retry malformed mail under the lenient
    compat32 policy (see the fallback ladder in process_message)."""
    msg = email.message_from_bytes(raw_bytes, policy=policy)

    # auth first — its MTA-verified dkim_domains feed domain extraction
    auth             = extract_auth_results(msg)
    # ...then forwarders, which subtract the relaying hop's domains from
    # everything below: they are authentic but they are not the sender.
    forwarders       = extract_forwarder_domains(msg, auth)
    # The topmost Received-SPF is written about the last hop, so on a forwarded
    # message it records the forwarder's relay IP. Reporting a shared forwarding
    # relay is worse than reporting nothing, and the origin IP behind it is only
    # attested by the sender's own hops — so no IP is extracted at all.
    ip               = None if forwarders else extract_sending_ip(msg)
    envelope_domains = extract_envelope_domains(msg, auth['dkim_domains']) - forwarders
    urls             = extract_cta_urls(msg)
    primary_domain   = extract_primary_domain(msg, auth['dkim_domains'] - forwarders)
    sender_domains   = extract_sender_domains(msg, auth) - forwarders

    return {
        'ip':               ip,
        'primary_domain':   primary_domain,
        'envelope_domains': envelope_domains,
        'sender_domains':   sender_domains,
        'forwarder_domains': forwarders,
        'urls':             urls,
        'auth':             auth,
        'subject':          str(msg.get('Subject', '')),
        'rspamd':           str(msg.get('X-Rspamd-Score', 'N/A')),
    }

# ─────────────────────────────────────────────
# SPAMHAUS API
# ─────────────────────────────────────────────

# Threat types validated against GET /lookup/threats-types.
# Conservative defaults — stronger assertions require stronger evidence.
THREAT_IP     = 'spam'   # bulletproof requires ASN-level evidence we don't have
THREAT_DOMAIN = 'spam'   # phish requires confirmed credential harvesting
THREAT_URL    = 'scam'   # scam fits reward/credential harvesting lures
THREAT_EMAIL  = 'spam'

REASON_IP = lambda ripe, auth: (
    f'Spam source. RIR: netname={ripe.get("netname","unknown")} '
    f'org={ripe.get("org", ripe.get("descr","unknown"))} '
    f'country={ripe.get("country","unknown")}. '
    f'Auth: spf={auth.get("spf")} dkim={auth.get("dkim")} '
    f'dmarc={auth.get("dmarc")} (p={auth.get("dmarc_policy","unknown")}). '
    f'Found in Junk folder.'
)
REASON_DOMAIN = 'Spam domain found in Junk folder.'
REASON_URL    = 'Scam URL extracted from spam email body.'
REASON_EMAIL  = 'Spam email found in Junk folder.'

def spamhaus_request(endpoint, payload=None, method='POST', rate_limit_retries=3):
    """Pure HTTP function. Makes a Spamhaus API call with retry on 429."""
    url     = f'{SPAMHAUS_API}/{endpoint}'
    headers = {'Authorization': f'Bearer {SPAMHAUS_TOKEN}'}
    for attempt in range(1, rate_limit_retries + 1):
        try:
            resp = requests.request(
                method, url,
                headers=headers,
                json=payload if payload is not None else None,
                timeout=30
            )
            if resp.status_code == 429:
                log.warning(f'Rate limited — waiting 60s (attempt {attempt}/{rate_limit_retries})')
                time.sleep(60)
                continue
            elif resp.status_code == 208:
                return 208, resp.json() if resp.text else {}
            elif not resp.ok:
                try:
                    err_payload = resp.json()
                except Exception:
                    err_payload = {'error': resp.text}
                log.error(f'HTTP {resp.status_code}: {err_payload}')
                return resp.status_code, err_payload
            return resp.status_code, resp.json() if resp.text else {}
        except Exception as e:
            log.error(f'Request error: {e}')
            return 0, {}
    return 429, {'message': 'rate limit retries exhausted'}

def submit(submission_type, key, object_value, threat_type, reason):
    """Submit a single indicator to Spamhaus. Handles dry run and logging.
    Deduplication is handled at the run level via state_tracker.
    Spamhaus 208 handles indicator duplicates across runs."""
    label = key.replace('email:', '') if submission_type == 'email' else key
    if DRY_RUN:
        log.info(f'  [DRY RUN] Would submit {submission_type.upper()}: {label}')
        return
    status, body = spamhaus_request(f'submissions/add/{submission_type}', {
        'threat_type': threat_type,
        'reason': reason,
        'source': {'object': object_value}
    })
    if status in (200, 208):
        log.info(f'  {submission_type.upper()} {label} — {"OK" if status == 200 else "already reported"}')
        if status == 200:
            time.sleep(DELAY)
    else:
        log.warning(f'  {submission_type.upper()} {label} — failed ({status}): {body}')

def check_submission_count():
    """Log submission count, breakdown by type, and optionally full submission list."""
    status, data = spamhaus_request('submissions/count', method='GET')
    if status != 200:
        log.warning(f'Could not fetch submission count: HTTP {status}')
        return

    total       = data.get('total', 0)
    matched     = data.get('matched', 0)
    new         = total - matched
    pct_matched = int(matched / total * 100) if total else 0
    pct_new     = int(new / total * 100) if total else 0
    log.info(
        f'Spamhaus totals (30 days): {total} submitted — '
        f'{matched} corroborated ({pct_matched}%), '
        f'{new} new intelligence ({pct_new}%)'
    )

    status, items = spamhaus_request('submissions/list?items=10000', method='GET')
    if status != 200:
        log.warning(f'Could not fetch submissions list: HTTP {status}')
        return

    groups = defaultdict(lambda: {'listed': 0, 'checked': 0, 'pending': 0})
    for item in items:
        t = item.get('submission_type', 'unknown')
        if item.get('listed'):
            groups[t]['listed'] += 1
        elif item.get('last_check'):
            groups[t]['checked'] += 1
        else:
            groups[t]['pending'] += 1

    for t, counts in sorted(groups.items()):
        log.info(
            f'  {t.upper()}: {counts["listed"]} listed, '
            f'{counts["checked"]} checked/not listed, '
            f'{counts["pending"]} pending'
        )

    if VERBOSE_LIST:
        log.info('--- Verbose submission list ---')
        for item in items:
            stype = item.get('submission_type', '?')
            if stype == 'email':
                obj = item.get('attributes', {}).get('subject', '(no subject)')
            else:
                obj = item.get('source', {}).get('object', '?')
            listed = item.get('listed')
            if listed:
                status_str = f'listed: {", ".join(listed)}'
            elif item.get('last_check'):
                status_str = 'checked, not listed'
            else:
                status_str = 'pending review'
            log.info(f'  {stype.upper()} {obj} — {status_str}')

# ─────────────────────────────────────────────
# PROCESSING
# ─────────────────────────────────────────────

def submit_parsed(parsed, raw_bytes, state_tracker):
    """Submit the indicators from an already-parsed message to Spamhaus.
    Messages whose allowlisted sender domain authenticated are skipped entirely;
    allowlisted domains are never reported as indicators either way.
    state_tracker deduplicates indicators across messages within a single run."""
    auth   = parsed['auth']

    # Skip the whole message only when an allowlisted domain authenticated as the
    # sender. Matching a claimed From/Reply-To/Return-Path would let any spammer
    # bypass reporting with a forged From: x@paypal.com; matching any authenticated
    # domain would let a forwarding hop veto the report for spam it merely carried.
    # See extract_sender_domains for both halves.
    allowlisted = {d for d in parsed['sender_domains'] if _is_allowlisted(d)}
    if allowlisted:
        log.info(f'  Skipping — allowlisted sender domain(s): {", ".join(sorted(allowlisted))}')
        return

    forwarders = parsed.get('forwarder_domains') or set()
    if forwarders:
        log.info(f'  Forwarded message — ignoring relay domains and relay IP: '
                 f'{", ".join(sorted(forwarders))}')

    log.info(f'  IP={parsed["ip"]} primary_domain={parsed["primary_domain"]}')
    log.info(f'  Subject: {parsed["subject"]}')
    log.info(f'  Rspamd: {parsed["rspamd"]}')
    log.info(f'  Auth: spf={auth.get("spf")} dkim={auth.get("dkim")} dmarc={auth.get("dmarc")} (p={auth.get("dmarc_policy")})')

    if parsed['ip'] and parsed['ip'] not in state_tracker['ips']:
        state_tracker['ips'].add(parsed['ip'])
        # Defer RIR lookup until after dedup check — no network I/O for already-seen IPs
        ripe = rir_lookup(parsed['ip'])
        if ripe:
            log.info(f'  RIR: netname={ripe.get("netname")} country={ripe.get("country")}')
        submit('ip', parsed['ip'], parsed['ip'], THREAT_IP, REASON_IP(ripe, auth))

    # Never report an allowlisted brand domain as an indicator, even inside an
    # otherwise-reportable spam (e.g. a forged From: paypal.com that wasn't
    # authenticated enough to skip the whole message above).
    for domain in parsed['envelope_domains']:
        if _is_allowlisted(domain):
            log.info(f'  Skipping allowlisted domain indicator: {domain}')
            continue
        if domain not in state_tracker['domains']:
            state_tracker['domains'].add(domain)
            submit('domain', domain, domain, THREAT_DOMAIN, REASON_DOMAIN)

    # One raw email sample per primary domain per run
    if (parsed['primary_domain'] and not _is_allowlisted(parsed['primary_domain'])
            and parsed['primary_domain'] not in state_tracker['emails']):
        state_tracker['emails'].add(parsed['primary_domain'])
        key = f'email:{parsed["primary_domain"]}'
        MAX_EMAIL_BYTES = 1024 * 1024  # 1MB cap — truncate bytes before decoding
        email_sample = raw_bytes[:MAX_EMAIL_BYTES].decode('utf-8', errors='replace')
        submit('email', key, email_sample, THREAT_EMAIL, REASON_EMAIL)

    for url in parsed['urls']:
        try:
            hostname = _normalize_domain(urlparse(url).hostname or '')
        except Exception as e:
            log.debug(f'Could not extract hostname from URL: {e}')
            hostname = ''

        # Allowlisted hosts (real brand sites, redirectors, CDNs that legit mail
        # also links to) must not be reported — skip the URL and its landing domain.
        if hostname and _is_allowlisted(hostname):
            log.info(f'  Skipping allowlisted URL host: {hostname}')
            continue

        if url not in state_tracker['urls']:
            state_tracker['urls'].add(url)
            submit('url', url, url, THREAT_URL, REASON_URL)

        # Submit landing domain from URL if not already seen
        if hostname and hostname not in parsed['envelope_domains'] and hostname not in state_tracker['domains']:
            state_tracker['domains'].add(hostname)
            submit('domain', hostname, hostname, THREAT_DOMAIN,
                   f'Landing domain extracted from spam URL. {REASON_DOMAIN}')


def _salvage_ip(raw_bytes):
    """Pull the sending IP straight from raw bytes when structured parsing fails.
    Matches the topmost Received-SPF header (including folded continuation lines)
    and extracts its client-ip, mirroring extract_sending_ip's trust model."""
    text = raw_bytes.decode('utf-8', errors='replace')
    header = re.search(r'^Received-SPF:[^\n]*(?:\n[ \t][^\n]*)*', text,
                       re.IGNORECASE | re.MULTILINE)
    if not header:
        return None
    match = re.search(r'client-ip=([0-9a-fA-F.:]+)', header.group(0))
    if match:
        ip = match.group(1).strip()
        if not _is_internal_ip(ip):
            return ip
    return None


def _attempt_strict(raw_bytes, state_tracker):
    submit_parsed(parse_message(raw_bytes, policy=email.policy.default),
                  raw_bytes, state_tracker)


def _attempt_lenient(raw_bytes, state_tracker):
    submit_parsed(parse_message(raw_bytes, policy=email.policy.compat32),
                  raw_bytes, state_tracker)


def _attempt_minimal(raw_bytes, state_tracker):
    """Last resort: salvage only the sending IP via regex on the raw bytes."""
    parsed = {
        'ip':               _salvage_ip(raw_bytes),
        'primary_domain':   None,
        'envelope_domains': set(),
        'sender_domains':   set(),
        'forwarder_domains': set(),
        'urls':             [],
        'auth':             {'spf': 'unknown', 'dkim': 'unknown',
                             'dmarc': 'unknown', 'dmarc_policy': 'unknown',
                             'dkim_domains': set(), 'spf_domain': '',
                             'spf_local': ''},
        'subject':          '',
        'rspamd':           'N/A',
    }
    submit_parsed(parsed, raw_bytes, state_tracker)


def process_message(raw_bytes, state_tracker):
    """Parse a message and submit its indicators, escalating through the fallback
    ladder on failure. Returns 'processed' if any attempt completed (even if it
    salvaged nothing), or 'failed' if every attempt raised — the caller flags
    failures distinctly so they are not retried forever.

    Escalating ladder: strict parse → lenient (compat32) parse → raw-bytes IP
    salvage, each tolerating more malformation than the last. dedup via
    state_tracker means a step that partially submitted before raising is not
    re-submitted by the next step."""
    attempts = (
        ('strict',  _attempt_strict),
        ('lenient', _attempt_lenient),
        ('minimal', _attempt_minimal),
    )
    for name, attempt in attempts:
        try:
            attempt(raw_bytes, state_tracker)
            if name != 'strict':
                log.warning(f'  Parsed via {name} fallback')
            return 'processed'
        except Exception as e:
            log.warning(f'  {name} parse attempt failed: {e}')
    log.error('  All parse attempts failed — flagging message as failed')
    return 'failed'

# ─────────────────────────────────────────────
# IMAP
# ─────────────────────────────────────────────

def load_accounts():
    """Return (spamhaus_token, accounts) from ACCOUNTS_CONFIG file, or fall back to env vars."""
    if ACCOUNTS_CONFIG:
        try:
            with open(os.path.expandvars(os.path.expanduser(ACCOUNTS_CONFIG))) as f:
                config = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            log.error(f'Could not load ACCOUNTS_CONFIG {ACCOUNTS_CONFIG}: {e}')
            sys.exit(1)
        if not isinstance(config, dict):
            log.error(f'ACCOUNTS_CONFIG must be a JSON object with "spamhaus_token" and "accounts" keys: {ACCOUNTS_CONFIG}')
            sys.exit(1)
        token    = config.get('spamhaus_token') or SPAMHAUS_TOKEN
        accounts = config.get('accounts', [])
        if not token:
            log.error('No spamhaus_token in config file and SPAMHAUS_TOKEN env var is not set.')
            sys.exit(1)
        if not isinstance(accounts, list) or not accounts:
            log.error(f'ACCOUNTS_CONFIG "accounts" must be a non-empty array: {ACCOUNTS_CONFIG}')
            sys.exit(1)
        for i, acct in enumerate(accounts):
            for key in ('imap_server', 'imap_user', 'imap_password'):
                if not acct.get(key):
                    log.error(f'Account {i + 1} missing required field: {key}')
                    sys.exit(1)
        custom_allowlist = config.get('allowlist', [])
        if not isinstance(custom_allowlist, list):
            log.error(f'ACCOUNTS_CONFIG "allowlist" must be an array of domains: {ACCOUNTS_CONFIG}')
            sys.exit(1)
        added = apply_custom_allowlist(custom_allowlist)
        if added:
            log.info(f'Loaded {added} custom allowlist domain(s) from ACCOUNTS_CONFIG.')
        return token, accounts

    if not all([IMAP_SERVER, IMAP_USER, IMAP_PASSWORD]):
        log.error('Missing required environment variables: IMAP_SERVER, IMAP_USER, IMAP_PASSWORD '
                  '(or set ACCOUNTS_CONFIG to a JSON config file).')
        sys.exit(1)
    return SPAMHAUS_TOKEN, [{'imap_server': IMAP_SERVER, 'imap_port': IMAP_PORT,
                              'imap_user': IMAP_USER, 'imap_password': IMAP_PASSWORD,
                              'imap_folder': IMAP_FOLDER}]


def connect_imap(account):
    """Connect to IMAP server with explicit timeout to prevent half-open TCP hangs."""
    server   = account['imap_server']
    port     = int(account.get('imap_port', 993))
    user     = account['imap_user']
    password = account['imap_password']
    conn = imaplib.IMAP4_SSL(server, port, timeout=60)
    conn.login(user, password)
    log.info(f'Connected to {server}:{port} as {user}')
    return conn


def _parse_flag_line(line):
    """Pull (uid, {flags}) out of one FETCH FLAGS response line."""
    uid_match   = re.search(rb'UID (\d+)', line)
    flags_match = re.search(rb'FLAGS \(([^)]*)\)', line)
    if not uid_match or not flags_match:
        return None, set()
    return uid_match.group(1), {f.decode('ascii', 'replace')
                                for f in flags_match.group(1).split()}


def fetch_flags(conn, uid_set='1:*'):
    """Return {uid: {flag, ...}} for uid_set, or None if the FETCH failed."""
    status, data = conn.uid('fetch', uid_set, '(FLAGS)')
    if status != 'OK':
        return None
    flags = {}
    for item in data or []:
        line = item[0] if isinstance(item, tuple) else item
        if not isinstance(line, bytes):
            continue
        uid, message_flags = _parse_flag_line(line)
        if uid:
            flags[uid] = message_flags
    return flags


def store_flag(conn, uid, flag, remove=False):
    """Add or remove one keyword on a message, returning imaplib's (status, data).

    The flag goes in a parenthesised list. That is the canonical STORE form and
    the only one iCloud accepts — a bare '+FLAGS $Keyword' earns a BAD Parse
    Error there. A BAD reply makes imaplib raise rather than return a status, so
    translate it back into a status the callers already degrade on gracefully.
    """
    try:
        return conn.uid('store', uid, '-FLAGS' if remove else '+FLAGS', f'({flag})')
    except imaplib.IMAP4.error as e:
        return 'BAD', [str(e).encode()]


def unprocessed_uids(conn):
    """UIDs in the selected folder not yet flagged processed or failed.

    State is read by fetching flags and filtering here rather than by asking the
    server for 'NOT KEYWORD $SpamhausProcessed'. iCloud stores custom keywords
    and hands them back from FETCH, but its SEARCH ignores any keyword outside
    its own advertised set: the filter matches every message, so the folder would
    be reprocessed every cycle with no error to show for it. FETCH FLAGS behaves
    the same on every server, so this is one path for all of them.
    """
    flags = fetch_flags(conn)
    if flags is None:
        return None
    return sorted((uid for uid, message_flags in flags.items()
                   if PROCESSED_FLAG not in message_flags and FAILED_FLAG not in message_flags),
                  key=int)


def custom_keywords_supported(conn, uid):
    """Set a test keyword, read it back, remove it — does state survive here?

    Reading it back is the point: a server can answer OK to the STORE and retain
    nothing, which would silently reprocess the mailbox forever.
    """
    if store_flag(conn, uid, CAPABILITY_FLAG)[0] != 'OK':
        return False
    flags  = fetch_flags(conn, uid)
    stored = flags is not None and CAPABILITY_FLAG in flags.get(uid, set())
    store_flag(conn, uid, CAPABILITY_FLAG, remove=True)  # best effort
    return stored


def run_account(account):
    """Process one mailbox: connect, process unprocessed messages, flag, disconnect. Returns count."""
    folder = account.get('imap_folder', 'Junk')
    conn   = None
    total_processed = 0
    flagged_ok      = 0
    flag_failures   = 0
    fetch_skips     = 0

    try:
        conn = connect_imap(account)

        if conn.select(f'"{folder}"', readonly=False)[0] != 'OK':
            log.error(f'Could not select folder: {folder}')
            return 0

        uids = unprocessed_uids(conn)
        if uids is None:
            log.error(f'Could not read message flags in folder: {folder}')
            return 0
        if not uids:
            log.info(f'Folder {folder}: No unprocessed messages.')
            return 0

        log.info(f'Folder {folder}: {len(uids)} unprocessed message(s)')

        # Functional capability check — fails fast rather than looping forever on
        # a server that cannot hold the state this tool runs on.
        if not DRY_RUN and not custom_keywords_supported(conn, uids[0]):
            log.critical('IMAP server will not retain custom keyword flags — '
                         'cannot track state. Skipping account.')
            return 0

        # State tracker deduplicates indicators across all messages in this run
        state_tracker = {'ips': set(), 'domains': set(), 'urls': set(), 'emails': set()}

        for uid in uids:
            # BODY[], not the RFC822 alias: iCloud answers an RFC822 fetch with a
            # bare '1 (UID 1)' and no body at all, while BODY[] is core IMAP4rev1
            # and behaves identically everywhere. Neither is a PEEK, so the \Seen
            # side effect this relies on as a processed-indicator is unchanged.
            status, msg_data = conn.uid('fetch', uid, '(BODY[])')
            # The body is the literal half of a (header, body) tuple, but servers
            # differ on where that tuple sits, so take the first tuple carrying a
            # literal rather than trusting a fixed position.
            raw_bytes = next((part[1] for part in msg_data or []
                              if isinstance(part, tuple) and len(part) > 1
                              and isinstance(part[1], (bytes, bytearray))), None)
            if status != 'OK' or not raw_bytes:
                # Fetch never delivered the body, so this UID gets neither \Seen
                # (the non-peek RFC822 fetch would have set it) nor a keyword flag,
                # and will be retried next cycle — log it as a distinct stuck path.
                fetch_skips += 1
                log.warning(f'  Skipped UID {uid.decode()} — fetch returned {status} '
                            f'(no body); message stays unread and will be retried next cycle')
                continue

            log.info(f'Processing message UID {uid.decode()}')

            try:
                result = process_message(raw_bytes, state_tracker)
                total_processed += 1
                if not DRY_RUN:
                    # Flag once examined, regardless of individual submission outcomes.
                    # Design choice: a message is "examined" once parsed, not "successfully
                    # submitted" — this prevents reprocessing on transient API failures and
                    # avoids duplicate submissions on retry (Spamhaus 208 handles re-submits).
                    # A message whose every parse attempt failed gets FAILED_FLAG instead, so
                    # it is not retried forever yet stays distinct from cleanly-processed mail.
                    flag = PROCESSED_FLAG if result == 'processed' else FAILED_FLAG
                    # A non-OK store (without an exception) leaves the message
                    # unflagged, so it is re-fetched and reprocessed every cycle —
                    # surface it loudly rather than silently looping on it.
                    store_status, store_data = store_flag(conn, uid, flag)
                    if store_status == 'OK':
                        flagged_ok += 1
                        log.info(f'  Flagged message UID {uid.decode()} as {result}')
                    else:
                        flag_failures += 1
                        log.warning(f'  Could not flag message UID {uid.decode()} as {result} '
                                    f'({store_status}): {store_data} — it will be reprocessed next cycle')
            except Exception as e:
                log.error(f'  Failed to process message UID {uid.decode()}: {e}')

    finally:
        log.info(f'Done. {total_processed} processed, {flagged_ok} flagged, '
                 f'{flag_failures} flag-failure(s), {fetch_skips} fetch-skip(s).')
        if conn:
            try:
                conn.logout()
            except Exception:
                pass

    return total_processed


def run_once():
    """Process all configured mailboxes once."""
    if DRY_RUN:
        log.info('*** DRY RUN mode — no submissions or flags will be applied ***')

    token, accounts = load_accounts()
    if not token:
        log.error('Missing Spamhaus token — set SPAMHAUS_TOKEN or add "spamhaus_token" to ACCOUNTS_CONFIG.')
        sys.exit(1)

    # Allow the resolved token to be used by spamhaus_request() which reads SPAMHAUS_TOKEN
    global SPAMHAUS_TOKEN
    SPAMHAUS_TOKEN = token

    grand_total = 0
    for account in accounts:
        try:
            grand_total += run_account(account)
        except Exception as e:
            log.error(f'Account {account.get("imap_user", "?")} failed: {e} '
                      f'— continuing with remaining accounts')

    if grand_total and not DRY_RUN:
        try:
            check_submission_count()
        except Exception as e:
            log.error(f'Could not fetch submission count: {e}')

def run_daemon(interval=300):
    """Run continuously, checking every interval seconds."""
    log.info(f'Daemon mode — checking every {interval}s')
    while True:
        try:
            run_once()
        except Exception as e:
            log.error(f'Error in run loop: {e}')
        log.info(f'Sleeping {interval}s...')
        time.sleep(interval)

# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Spam monitor and Spamhaus submitter')
    parser.add_argument('--daemon', action='store_true', help='Run continuously')
    parser.add_argument('--interval', type=int, default=300,
                        help='Daemon check interval in seconds (default: 300)')
    args = parser.parse_args()

    if args.daemon:
        run_daemon(args.interval)
    else:
        run_once()
