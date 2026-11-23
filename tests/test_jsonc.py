"""Tests for JSONC parsing of ACCOUNTS_CONFIG."""
import json

import pytest

from conftest import spam


def test_plain_json_unchanged():
    assert spam.parse_jsonc('{"a": [1, 2], "b": "x"}') == {'a': [1, 2], 'b': 'x'}


def test_line_and_block_comments():
    text = '{\n  // off for now\n  "a": 1, /* inline */ "b": 2\n}'
    assert spam.parse_jsonc(text) == {'a': 1, 'b': 2}


def test_commented_out_account_with_trailing_comma():
    text = '''{
      "accounts": [
        {"imap_user": "a"},
        // {"imap_user": "b"},
      ]
    }'''
    assert spam.parse_jsonc(text) == {'accounts': [{'imap_user': 'a'}]}


def test_comment_markers_inside_strings_preserved():
    text = '{"u": "http://x/*y*/", "p": "a//b", "q": "say \\"//\\"", "c": "a,]"}'
    assert spam.parse_jsonc(text) == {
        'u': 'http://x/*y*/', 'p': 'a//b', 'q': 'say "//"', 'c': 'a,]'}


def test_unterminated_block_comment_raises():
    with pytest.raises(json.JSONDecodeError):
        spam.parse_jsonc('{"a": 1 /* oops }')


def test_invalid_json_still_raises():
    with pytest.raises(json.JSONDecodeError):
        spam.parse_jsonc('{"a": }')


def test_load_accounts_reads_jsonc_file(tmp_path, monkeypatch):
    cfg = tmp_path / 'accounts.jsonc'
    cfg.write_text('''{
      "spamhaus_token": "tok",
      "accounts": [
        {"imap_server": "a", "imap_user": "u", "imap_password": "p"},
        // {"imap_server": "b", "imap_user": "u2", "imap_password": "p2"},
      ]
    }''')
    monkeypatch.setattr(spam, 'ACCOUNTS_CONFIG', str(cfg))
    token, accounts = spam.load_accounts()
    assert token == 'tok'
    assert [a['imap_server'] for a in accounts] == ['a']
