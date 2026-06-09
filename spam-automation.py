#!/usr/bin/env python3
"""
spam-monitor.py — Automated spam analysis and Spamhaus submission

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
    ACCOUNTS_CONFIG  — path to a JSON file listing mailbox configs (see accounts.example.json)

Optional environment variables:
    IMAP_FOLDER      — folder to watch (default: Junk); per-account override available in config file
    DRY_RUN          — set to "1" to parse without submitting (default: 0)
    DELAY            — seconds between API calls (default: 2)
    VERBOSE_LIST     — set to "1" to log every submission with its status (default: 0)

Usage:
    python3 spam-monitor.py             # run once
    python3 spam-monitor.py --daemon    # run continuously
    DRY_RUN=1 python3 spam-monitor.py   # dry run
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

# Tracking parameters appended by spam campaigns to generate unique URLs per recipient.
_TRACKING_PARAMS = frozenset({
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'msclkid', 'mc_eid', 'mc_cid',
})

# Domains that should never be submitted to Spamhaus. Messages whose primary
# domain or envelope domains match (or are a subdomain of) any entry here are
# skipped entirely — flagged as processed but not submitted.
DOMAIN_ALLOWLIST = frozenset({
    'accounts.google.com',
    'amazon.com',
    'amazonaws.com',
    'apple.com',
    'bankofamerica.com',
    'capitalone.com',
    'chase.com',
    'cloudflare.com',
    'github.com',
    'gmail.com',
    'google.com',
    'googlemail.com',
    'hotmail.com',
    'icloud.com',
    'jpmorgan.com',
    'live.com',
    'mail.google.com',
    'me.com',
    'microsoft.com',
    'outlook.com',
    'paypal.com',
    'reddit.com',
    'stripe.com',
    'wellsfargo.com',
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

def extract_envelope_domains(msg):
    """Extract all unique IDNA-normalized domains from envelope headers and DKIM signature.
    Uses email.utils.getaddresses for RFC-compliant address parsing.
    DKIM d= is often the most reliable indicator — identifies signing domain
    regardless of what From claims."""
    domains = set()

    for field in ('From', 'Reply-To', 'Return-Path'):
        # Cast to str — email.policy.default returns header objects not raw strings
        headers_raw = [str(h) for h in (msg.get_all(field) or [])]
        for _, addr in getaddresses(headers_raw):
            if '@' in addr:
                domain = _normalize_domain(addr.rsplit('@', 1)[1])
                if domain:
                    domains.add(domain)

    for dkim_header in msg.get_all('DKIM-Signature') or []:
        flat = re.sub(r'\s+', '', str(dkim_header))
        match = re.search(r'\bd=([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', flat, re.IGNORECASE)
        if match:
            domains.add(_normalize_domain(match.group(1)))

    return domains

def extract_primary_domain(msg):
    """Extract the primary sending domain, preferring DKIM d= over Return-Path.
    DKIM d= identifies the signing domain regardless of what From claims.
    Falls back to Return-Path domain if no DKIM signature is present."""
    for dkim_header in msg.get_all('DKIM-Signature') or []:
        flat = re.sub(r'\s+', '', str(dkim_header))
        match = re.search(r'\bd=([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', flat, re.IGNORECASE)
        if match:
            return _normalize_domain(match.group(1))

    headers_raw = [str(h) for h in (msg.get_all('Return-Path') or [])]
    for _, addr in getaddresses(headers_raw):
        if '@' in addr:
            return _normalize_domain(addr.rsplit('@', 1)[1])

    return None

def extract_auth_results(msg):
    """Extract SPF, DKIM, DMARC results from Authentication-Results header.
    Uses the top-most header (written by our MTA), strips line folding,
    and extracts the first result per type."""
    auth_headers = msg.get_all('Authentication-Results') or []
    if not auth_headers:
        return {'spf': 'unknown', 'dkim': 'unknown', 'dmarc': 'unknown', 'dmarc_policy': 'unknown'}

    # Top-most header is from our MTA — flatten line folding
    auth = re.sub(r'\s+', ' ', str(auth_headers[0]))

    def extract(pattern):
        m = re.search(pattern, auth, re.IGNORECASE)
        return m.group(1).lower() if m else 'unknown'

    spf          = extract(r'\bspf=(pass|fail|softfail|neutral|none|permerror|temperror)\b')
    dkim         = extract(r'\bdkim=(pass|fail|none|policy|neutral|temperror|permerror)\b')
    dmarc        = extract(r'\bdmarc=(pass|fail|none|bestguesspass|temperror|permerror)\b')
    dmarc_policy = extract(r'\b(?:policy\.[A-Za-z_-]*|p)=([A-Za-z]+)')

    return {'spf': spf, 'dkim': dkim, 'dmarc': dmarc, 'dmarc_policy': dmarc_policy}

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
                    if any(s in href.lower() for s in ('unsub', 'optout', 'opt-out', 'remove', 'list-unsubscribe')):
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

def parse_message(raw_bytes):
    """Parse a raw email and extract all indicators."""
    msg = email.message_from_bytes(raw_bytes, policy=email.policy.default)

    ip               = extract_sending_ip(msg)
    envelope_domains = extract_envelope_domains(msg)
    urls             = extract_cta_urls(msg)
    auth             = extract_auth_results(msg)

    primary_domain = extract_primary_domain(msg)

    return {
        'ip':               ip,
        'primary_domain':   primary_domain,
        'envelope_domains': envelope_domains,
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

def process_message(raw_bytes, state_tracker):
    """Parse a message and submit indicators to Spamhaus.
    state_tracker deduplicates indicators across messages within a single run."""
    parsed = parse_message(raw_bytes)
    auth   = parsed['auth']

    all_domains = parsed['envelope_domains'] | (
        {parsed['primary_domain']} if parsed['primary_domain'] else set()
    )
    allowlisted = {d for d in all_domains if _is_allowlisted(d)}
    if allowlisted:
        log.info(f'  Skipping — allowlisted domain(s): {", ".join(sorted(allowlisted))}')
        return

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

    for domain in parsed['envelope_domains']:
        if domain not in state_tracker['domains']:
            state_tracker['domains'].add(domain)
            submit('domain', domain, domain, THREAT_DOMAIN, REASON_DOMAIN)

    # One raw email sample per primary domain per run
    if parsed['primary_domain'] and parsed['primary_domain'] not in state_tracker['emails']:
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


def run_account(account):
    """Process one mailbox: connect, process unprocessed messages, flag, disconnect. Returns count."""
    folder = account.get('imap_folder', 'Junk')
    conn   = None
    total_processed = 0

    try:
        conn = connect_imap(account)

        if conn.select(f'"{folder}"', readonly=False)[0] != 'OK':
            log.error(f'Could not select folder: {folder}')
            return 0

        status, data = conn.uid('search', None, f'NOT KEYWORD {PROCESSED_FLAG}')
        if status != 'OK' or not data[0]:
            log.info(f'Folder {folder}: No unprocessed messages.')
            return 0

        uids = data[0].split()
        log.info(f'Folder {folder}: {len(uids)} unprocessed message(s)')

        # Functional capability check — attempt to set and immediately remove a test flag.
        # Fails fast if the server doesn't support custom IMAP keywords.
        if not DRY_RUN:
            test_status, _ = conn.uid('store', uids[0], '+FLAGS', CAPABILITY_FLAG)
            if test_status != 'OK':
                log.critical('IMAP server rejected custom keyword flags — cannot track state. Skipping account.')
                return 0
            try:
                conn.uid('store', uids[0], '-FLAGS', CAPABILITY_FLAG)
            except Exception:
                pass  # Non-fatal — flag will be ignored by processing logic

        # State tracker deduplicates indicators across all messages in this run
        state_tracker = {'ips': set(), 'domains': set(), 'urls': set(), 'emails': set()}

        for uid in uids:
            status, msg_data = conn.uid('fetch', uid, '(RFC822)')
            if status != 'OK' or not msg_data or not msg_data[0]:
                continue

            raw_bytes = msg_data[0][1]
            log.info(f'Processing message UID {uid.decode()}')

            try:
                process_message(raw_bytes, state_tracker)
                total_processed += 1
                if not DRY_RUN:
                    # Flag the message as processed regardless of individual submission outcomes.
                    # Design choice: a message is considered "examined" once parsed, not
                    # "successfully submitted". This prevents reprocessing on transient API
                    # failures and avoids duplicate submissions when the script retries.
                    # Spamhaus 208 handles any re-submitted indicators gracefully.
                    conn.uid('store', uid, '+FLAGS', PROCESSED_FLAG)
                    log.info(f'  Flagged message UID {uid.decode()} as processed')
            except Exception as e:
                log.error(f'  Failed to process message UID {uid.decode()}: {e}')

    finally:
        log.info(f'Done. {total_processed} message(s) processed.')
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
        grand_total += run_account(account)

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
