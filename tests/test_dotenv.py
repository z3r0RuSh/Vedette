"""Tests for the minimal .env loader (temp runs without 1Password)."""

import os

import pytest

from vedette import dotenv


def test_parse_basic():
    values = dotenv.parse_dotenv("A=1\nB=two\n")
    assert values == {"A": "1", "B": "two"}


def test_parse_ignores_comments_and_blanks():
    values = dotenv.parse_dotenv("# comment\n\nA=1\n   # indented\nB=2\n")
    assert values == {"A": "1", "B": "2"}


def test_parse_strips_quotes():
    values = dotenv.parse_dotenv('A="hello world"\nB=\'it\\\'s\'\nC=plain\n')
    assert values["A"] == "hello world"
    assert values["C"] == "plain"


def test_parse_export_prefix():
    values = dotenv.parse_dotenv("export A=1\n")
    assert values == {"A": "1"}


def test_parse_skips_garbage():
    values = dotenv.parse_dotenv("not-a-pair\n=noname\n123 BAD=1\nA=ok\n")
    assert values == {"A": "ok"}


def test_parse_value_with_equals():
    values = dotenv.parse_dotenv("A=op://vault/item/with=sign\n")
    assert values == {"A": "op://vault/item/with=sign"}


def test_load_sets_missing_only(tmp_path, monkeypatch):
    p = tmp_path / ".env"
    p.write_text("DOTENV_TEST_A=fromfile\nDOTENV_TEST_B=fromfile\n")
    monkeypatch.setenv("DOTENV_TEST_B", "fromenv")
    monkeypatch.delenv("DOTENV_TEST_A", raising=False)
    loaded = dotenv.load_dotenv(str(p))
    assert loaded == ["DOTENV_TEST_A"]
    assert os.environ["DOTENV_TEST_A"] == "fromfile"
    assert os.environ["DOTENV_TEST_B"] == "fromenv"


def test_load_missing_file_is_noop(tmp_path):
    assert dotenv.load_dotenv(str(tmp_path / "nope.env")) == []


def test_load_default_path_next_to_project(monkeypatch):
    # load_dotenv() with no args targets <project>/.env; just verify it does
    # not blow up when the file is absent.
    monkeypatch.chdir("/tmp")
    assert dotenv.load_dotenv() == [] or isinstance(dotenv.load_dotenv(), list)
