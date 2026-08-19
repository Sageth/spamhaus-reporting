"""Tests for reading processed-state off the server (#15).

The response bytes here are real captures: iCloud is the reason this code path
exists, since it stores custom keywords and returns them from FETCH while its
SEARCH ignores them entirely.
"""
import imaplib

from conftest import spam


class FakeConn:
    """Minimal IMAP4 stand-in recording uid() calls and replaying canned replies."""

    def __init__(self, replies=None, raises=None):
        self.replies = replies or {}
        self.raises  = raises
        self.calls   = []

    def uid(self, command, *args):
        self.calls.append((command, *args))
        if self.raises:
            raise self.raises
        return self.replies.get(command, ('OK', []))


# ── _parse_flag_line ───────────────────────────────────────────────

def test_parses_uid_and_flags():
    uid, flags = spam._parse_flag_line(rb'1 (UID 1 FLAGS (\Seen $SpamhausProcessed))')
    assert uid == b'1'
    assert flags == {r'\Seen', '$SpamhausProcessed'}


def test_parses_empty_flag_list():
    uid, flags = spam._parse_flag_line(rb'7 (UID 42 FLAGS ())')
    assert (uid, flags) == (b'42', set())


def test_parses_flags_before_uid():
    """Servers may order the data items either way round."""
    uid, flags = spam._parse_flag_line(rb'1 (FLAGS (\Seen) UID 9)')
    assert (uid, flags) == (b'9', {r'\Seen'})


def test_line_without_uid_yields_nothing():
    assert spam._parse_flag_line(rb'1 (FLAGS (\Seen))') == (None, set())


def test_line_without_flags_yields_nothing():
    assert spam._parse_flag_line(rb'1 (UID 1 RFC822.SIZE 15134)') == (None, set())


# ── fetch_flags ────────────────────────────────────────────────────

def test_fetch_flags_maps_uids_to_flags():
    conn = FakeConn({'fetch': ('OK', [rb'1 (UID 1 FLAGS (\Seen))',
                                      rb'2 (UID 2 FLAGS ($SpamhausProcessed))'])})
    assert spam.fetch_flags(conn) == {b'1': {r'\Seen'}, b'2': {'$SpamhausProcessed'}}


def test_fetch_flags_skips_non_bytes_and_none_entries():
    """An empty mailbox comes back as ('OK', [None]) on some servers."""
    assert spam.fetch_flags(FakeConn({'fetch': ('OK', [None])})) == {}


def test_fetch_flags_returns_none_on_failure():
    assert spam.fetch_flags(FakeConn({'fetch': ('NO', [b'nope'])})) is None


# ── unprocessed_uids ───────────────────────────────────────────────

def test_unprocessed_excludes_processed_and_failed():
    conn = FakeConn({'fetch': ('OK', [rb'1 (UID 1 FLAGS ($SpamhausProcessed))',
                                      rb'2 (UID 2 FLAGS (\Seen))',
                                      rb'3 (UID 3 FLAGS ($SpamhausFailed))',
                                      rb'4 (UID 4 FLAGS ())'])})
    assert spam.unprocessed_uids(conn) == [b'2', b'4']


def test_unprocessed_sorts_numerically_not_lexically():
    conn = FakeConn({'fetch': ('OK', [rb'1 (UID 10 FLAGS ())',
                                      rb'2 (UID 9 FLAGS ())'])})
    assert spam.unprocessed_uids(conn) == [b'9', b'10']


def test_unprocessed_is_none_when_flags_unreadable():
    assert spam.unprocessed_uids(FakeConn({'fetch': ('NO', [b'nope'])})) is None


# ── store_flag ─────────────────────────────────────────────────────

def test_store_flag_parenthesises_the_keyword():
    """iCloud BADs a bare '+FLAGS $Keyword'; the list form works everywhere."""
    conn = FakeConn({'store': ('OK', [rb'1 (UID 1 FLAGS ($SpamhausProcessed))'])})
    spam.store_flag(conn, b'1', '$SpamhausProcessed')
    assert conn.calls == [('store', b'1', '+FLAGS', '($SpamhausProcessed)')]


def test_store_flag_removes_with_minus():
    spam.store_flag(conn := FakeConn(), b'1', '$X', remove=True)
    assert conn.calls == [('store', b'1', '-FLAGS', '($X)')]


def test_store_flag_translates_bad_into_a_status():
    """A BAD reply makes imaplib raise; callers degrade on a status instead."""
    conn = FakeConn(raises=imaplib.IMAP4.error("UID command error: BAD [b'Parse Error']"))
    status, data = spam.store_flag(conn, b'1', '$X')
    assert status == 'BAD'
    assert b'Parse Error' in data[0]


# ── custom_keywords_supported ──────────────────────────────────────

def test_capability_requires_the_keyword_to_come_back():
    """A server may answer OK to the STORE and retain nothing."""
    conn = FakeConn({'store': ('OK', []),
                     'fetch': ('OK', [rb'1 (UID 1 FLAGS (\Seen))'])})
    assert spam.custom_keywords_supported(conn, b'1') is False


def test_capability_passes_when_keyword_persists():
    conn = FakeConn({'store': ('OK', []),
                     'fetch': ('OK', [rb'1 (UID 1 FLAGS ($SpamhausCapabilityTest))'])})
    assert spam.custom_keywords_supported(conn, b'1') is True


def test_capability_fails_when_store_is_rejected():
    conn = FakeConn(raises=imaplib.IMAP4.error('BAD'))
    assert spam.custom_keywords_supported(conn, b'1') is False
