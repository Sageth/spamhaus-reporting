# spamhaus-reporting

Automated spam analysis and Spamhaus submission. Watches your IMAP Junk folder, extracts infrastructure indicators from each message, and submits them to the Spamhaus Threat Intel Community API.

No local database or flat files required — state is tracked via a custom IMAP keyword flag (`$SpamhausProcessed`) set directly on each message after processing.

---

## What it does

For each unprocessed message in your Junk folder, the script:

- Extracts the sending IP from the topmost `Received-SPF` header
- Extracts sending domains from `From`, `Reply-To`, `Return-Path`, and the DKIM signing domain your MTA *verified* (`Authentication-Results` `dkim=pass header.d=`)
- Extracts and normalizes CTA URLs from the HTML body
- Skips any indicator (sending domain, URL, or URL landing domain) matching the built-in domain allowlist
- Looks up the sending IP against RIPE Stat for infrastructure context
- Submits IP, domains, URLs, and a raw email sample to the Spamhaus API
- Flags the message as processed on the mail server (or as failed if it can't be parsed)
- Deduplicates indicators within each run via an in-memory state tracker
- Logs a grouped submission summary after each run that processes messages

---

## Requirements

- Python 3.9+
- A Spamhaus Threat Intel Community account and API token
- An IMAP mail account with Junk folder access
- IMAP server that supports custom keyword flags (Dovecot, Cyrus, Gmail — most modern providers)

```bash
pip install bs4 requests
```

---

## Configuration

**Required for all setups:**

| Variable | Description |
|---|---|
| `SPAMHAUS_TOKEN` | Spamhaus submission API token |

**Single-mailbox setup** — set these environment variables directly:

| Variable | Required | Default | Description |
|---|---|---|---|
| `IMAP_SERVER` | Yes | — | IMAP server hostname |
| `IMAP_PORT` | No | `993` | IMAP port |
| `IMAP_USER` | Yes | — | Your full email address |
| `IMAP_PASSWORD` | Yes | — | Your IMAP password |
| `IMAP_FOLDER` | No | `Junk` | Folder to watch |

**Multi-mailbox setup** — point `ACCOUNTS_CONFIG` at a JSON file outside the repository:

| Variable | Description |
|---|---|
| `ACCOUNTS_CONFIG` | Absolute path to a JSON config file (see `accounts.example.json`) |

Copy `accounts.example.json` to a location outside the repository (e.g. `~/.config/spamhaus-reporting/accounts.json`), fill in your credentials, and set `ACCOUNTS_CONFIG` to that path. The file must never be committed — keep it outside the repo entirely. When `ACCOUNTS_CONFIG` is set, `SPAMHAUS_TOKEN` does not need to be set as an env var.

```json
{
  "spamhaus_token": "your_spamhaus_api_token",
  "accounts": [
    {
      "imap_server": "mail.example.com",
      "imap_port": 993,
      "imap_user": "you@example.com",
      "imap_password": "your_imap_password",
      "imap_folder": "Junk"
    }
  ]
}
```

Each account entry supports `imap_server`, `imap_port`, `imap_user`, `imap_password`, and `imap_folder`. `imap_port` and `imap_folder` are optional and default to `993` and `Junk`.

**Behavior flags** (apply to all modes):

| Variable | Default | Description |
|---|---|---|
| `DRY_RUN` | `0` | Set to `1` to parse without submitting or flagging |
| `DELAY` | `2` | Seconds between new API submissions |
| `VERBOSE_LIST` | `0` | Set to `1` to log every submission with its status |

**Getting a Spamhaus API token:**

Register at [submit.spamhaus.org](https://submit.spamhaus.org), then go to [auth.spamhaus.org/account](https://auth.spamhaus.org/account), scroll to "API Key Creation", and create a key. Copy it immediately — it's only shown once.

Verify the threat type codes valid for your account tier before running:

```bash
curl -s -H "Authorization: Bearer $SPAMHAUS_TOKEN" \
  https://submit.spamhaus.org/portal/api/v1/lookup/threats-types
```

---

## Usage

**Always dry run first:**

```bash
DRY_RUN=1 python3 spam-automation.py
```

This parses every unprocessed message and logs what would be submitted without touching the API or setting any flags. Check the output before running live.

**Single run:**

```bash
python3 spam-automation.py
```

**Daemon mode (checks every 5 minutes):**

```bash
python3 spam-automation.py --daemon --interval 300
```

**Cron job (every 10 minutes):**

```
*/10 * * * * cd /path/to/spamhaus-reporting && python3 spam-automation.py
```

**Full submission detail:**

```bash
VERBOSE_LIST=1 python3 spam-automation.py
```

---

## Testing

Unit tests cover the parsing/extraction layer and the allowlist gating in `process_message`. They use synthetic `.eml` fixtures under `tests/fixtures/` and patch out all network calls, so they run offline in well under a second.

```bash
pip install pytest      # or: pipenv install --dev
python3 -m pytest tests/ -q
```

---

## Running as a systemd service

For production use on Linux, systemd is cleaner than cron or a manual daemon. Since this runs under your own account, use a user-level service rather than a system-wide one.

Create the service file at `~/.config/systemd/user/spamhaus-reporting.service`:

```ini
[Unit]
Description=Spamhaus Reporting — automated spam submission
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/path/to/spamhaus-reporting
ExecStart=/usr/bin/python3 spam-automation.py --daemon --interval 300
Restart=on-failure
RestartSec=30
EnvironmentFile=%h/.config/spamhaus-reporting/env

[Install]
WantedBy=default.target
```

Create the environment file at `~/.config/spamhaus-reporting/env`.

Single-mailbox:

```bash
IMAP_SERVER=mail.example.com
IMAP_PORT=993
IMAP_USER=you@example.com
IMAP_PASSWORD=your_imap_password
SPAMHAUS_TOKEN=your_spamhaus_api_token
IMAP_FOLDER=Junk
DELAY=2
```

Multi-mailbox (copy `accounts.example.json` to this location and fill in credentials — token lives in the file):

```bash
ACCOUNTS_CONFIG=/home/you/.config/spamhaus-reporting/accounts.json
DELAY=2
```

Lock down the permissions so credentials aren't readable by other users:

```bash
chmod 700 ~/.config/spamhaus-reporting
chmod 600 ~/.config/spamhaus-reporting/env
```

Enable and start:

```bash
systemctl --user daemon-reload
systemctl --user enable spamhaus-reporting
systemctl --user start spamhaus-reporting
```

Check it's running:

```bash
systemctl --user status spamhaus-reporting
journalctl --user -u spamhaus-reporting -f
```

To have the service start automatically at boot even when you're not logged in:

```bash
sudo loginctl enable-linger $USER
```

---

The script uses a custom IMAP keyword flag (`$SpamhausProcessed`) instead of a local database or flat file. This means:

- No local files to manage or back up
- State survives the script being moved to a different machine
- Processed messages are visible in any mail client that shows keyword flags

On startup, the script runs a functional capability test — it attempts to set and immediately remove a test flag (`$SpamhausCapabilityTest`) on the first available message. If the server rejects custom keywords, the script aborts cleanly.

A message is flagged as processed once examined, regardless of whether individual API submissions succeeded. Spamhaus returns HTTP 208 for already-known indicators, which handles any cross-run duplicates gracefully.

A message that cannot be parsed is retried through an escalating fallback ladder within the same run — strict parse, then the lenient `compat32` parse, then a last-resort attempt that salvages just the sending IP straight from the raw bytes. If every step fails, the message is flagged `$SpamhausFailed` rather than `$SpamhausProcessed`, so it is excluded from future runs (no infinite reprocessing) yet stays visibly distinct from cleanly-processed mail for inspection.

---

## Sample output

```
2026-06-03 14:22:01 INFO Connected to mail.example.com:993 as you@example.com
2026-06-03 14:22:01 INFO Folder Junk: 12 unprocessed message(s)
2026-06-03 14:22:02 INFO Processing message UID 4821
2026-06-03 14:22:02 INFO   IP=45.92.72.11 primary_domain=rewardsclaim.lat
2026-06-03 14:22:02 INFO   Subject: You have been selected
2026-06-03 14:22:02 INFO   Auth: spf=pass dkim=pass dmarc=pass (p=none)
2026-06-03 14:22:02 INFO   RIR: netname=NEW-AMUSER-HOUSING-NET2 country=IT
2026-06-03 14:22:03 INFO   IP 45.92.72.11 — OK
2026-06-03 14:22:05 INFO   DOMAIN rewardsclaim.lat — OK
2026-06-03 14:22:05 INFO   EMAIL rewardsclaim.lat — OK
2026-06-03 14:22:07 INFO   URL https://rewardsclaim.lat/go — OK
2026-06-03 14:22:07 INFO   Flagged message UID 4821 as processed
...
2026-06-03 14:23:14 INFO Done. 12 message(s) processed.
2026-06-03 14:23:14 INFO Spamhaus totals (30 days): 312 submitted — 187 corroborated (59%), 125 new intelligence (40%)
2026-06-03 14:23:14 INFO   DOMAIN: 84 listed, 12 checked/not listed, 7 pending
2026-06-03 14:23:14 INFO   EMAIL: 41 listed, 8 checked/not listed, 3 pending
2026-06-03 14:23:14 INFO   IP: 73 listed, 11 checked/not listed, 5 pending
2026-06-03 14:23:14 INFO   URL: 35 listed, 6 checked/not listed, 4 pending
```

---

## Known limitations

**IP extraction requires `Received-SPF`.** The script reads `client-ip=` from the topmost `Received-SPF` header — the SPF evaluation your inbound MX recorded for the host that actually connected to it. For directly-delivered mail this is the true sending source; for mail relayed through a forwarder it is the forwarder's IP (where SPF has usually already failed), so the script can surface forwarding infrastructure on forwarded spam. The IP is submitted regardless of the SPF result. If the header is absent, no IP is submitted, and the lower `Received` chain is deliberately not used as a fallback — those hops are both forgeable and more likely to be legitimate relays.

**Header trust assumes your MX sanitizes inbound headers.** Both the IP and the SPF/DKIM/DMARC results are read from the *topmost* `Received-SPF` and `Authentication-Results` headers on the assumption they were stamped by your own inbound MX. That assumption holds only if your MX strips or overwrites any pre-existing copies of those headers; if it does not, a sender can forge a top header and influence what is extracted. The script does not validate the `authserv-id` against your domain.

**`From` / `Reply-To` / `Return-Path` domains are unverified claims.** These header domains are reported as-is, so a message spoofing a well-known brand in `From` (on mail that fails or lacks DMARC) can lead the script to report that brand's domain. The built-in allowlist (`DOMAIN_ALLOWLIST`) is the safety net for known brands — it is matched against sending domains, URLs, and URL landing domains and skips them entirely; for other brands, Spamhaus's analyst review handles false positives.

**DKIM signing domains are taken only from your MTA's verified result.** The signing domain is read from `Authentication-Results` `dkim=pass header.d=` — i.e. a signature your MX *cryptographically verified* — never from the raw `DKIM-Signature` header. A raw `d=` tag is an unverified claim that anyone can forge (e.g. stapling `d=yourbank.com` with a bogus signature to frame a third party); trusting only verified results closes that poisoning vector while still capturing the spammer's real signing domain.

**With multiple verified signers, the "primary" domain is a tie-break, not a ranking.** When a message carries several `dkim=pass` signatures (e.g. an author domain plus an ESP re-signer), the primary domain prefers the signer aligned with `From`, and otherwise picks the alphabetically-first one. This choice only determines which domain the single raw email sample is grouped under per run; every verified signer and header domain is still submitted independently, so nothing is dropped by the tie-break.

**Authentication status is not used to exclude submissions.** A message passing SPF/DKIM/DMARC is *authenticated*, not *legitimate* — spammers routinely authenticate mail sent from their own throwaway domains. A verified domain is in fact the most confidently-reportable indicator (it is provably accountable and cannot be a framed victim). The "unwanted" signal here is simply that the message is in the Junk folder; legitimacy is handled by the allowlist, not by auth results.

**URL landing domains may be legitimate redirectors.** CDN hostnames, link shorteners, and ESP tracking domains sometimes appear in spam. The script submits them — unless they match the allowlist — so whether a non-allowlisted redirector adds intelligence value depends on the campaign.

**Allowlisting is exact-or-subdomain only.** A domain is skipped when it equals an allowlist entry or is a subdomain of one (e.g. `mail.google.com` matches `google.com`). Lookalikes such as `evil-paypal.com` are intentionally not matched. Edit `DOMAIN_ALLOWLIST` in the script to tune it.

**IMAP keyword support varies.** Most modern servers support custom keywords. Some hosted providers don't. The script tests for support at startup and aborts if the server rejects the flag.

---

## Background

Full write-up:

* [The Counteroffensive: Automated Spam Reporting with Spamhaus](https://dev.to/battlehardened/the-counteroffensive-automated-spam-reporting-with-spamhaus-j6e)

* See also: [Why Your Email Is an Open Door for Spammers — And How to Lock It](https://dev.to/battlehardened/why-your-email-is-an-open-door-for-spammers-and-how-to-lock-it-1k1n)

---

## License

MIT