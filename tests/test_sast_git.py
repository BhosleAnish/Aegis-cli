"""Tests for the SAST git source: the clone helper and the --git CLI wiring.

All offline — git is never actually invoked. The clone helper takes an injectable
`runner`, and the CLI tests monkeypatch the helper, so no network or real repo is
touched.
"""
from __future__ import annotations

import subprocess
from datetime import date
from pathlib import Path

import pytest

from aegis import git_source
from aegis.git_source import ClonedRepo, GitError, clone_argv, cloned_repo, repo_name


# --- clone_argv ------------------------------------------------------------ #
def test_clone_argv_is_shallow_by_default():
    argv = clone_argv("https://example.test/o/r.git", "/dest")
    assert argv[:3] == ["git", "-c", "credential.interactive=false"]
    assert "clone" in argv
    assert "--depth" in argv and "1" in argv
    # url and dest are passed positionally after a `--` guard, never interpolated
    assert argv[-3:] == ["--", "https://example.test/o/r.git", "/dest"]
    assert "--branch" not in argv


def test_clone_argv_branch_ref_uses_branch_and_stays_shallow():
    argv = clone_argv("https://example.test/o/r.git", "/dest", ref="develop")
    assert "--branch" in argv
    assert argv[argv.index("--branch") + 1] == "develop"
    assert "--depth" in argv


def test_clone_argv_commit_sha_is_full_clone():
    sha = "0" * 40
    argv = clone_argv("https://example.test/o/r.git", "/dest", ref=sha)
    # a shallow --branch cannot select an arbitrary commit, so no depth/branch
    assert "--depth" not in argv
    assert "--branch" not in argv


# --- repo_name ------------------------------------------------------------- #
@pytest.mark.parametrize("url,expected", [
    ("https://github.com/org/myrepo.git", "myrepo"),
    ("https://github.com/org/myrepo", "myrepo"),
    ("git@github.com:org/myrepo.git", "myrepo"),
    ("https://host/org/myrepo/", "myrepo"),
])
def test_repo_name_derives_project(url, expected):
    assert repo_name(url) == expected


# --- cloned_repo context manager ------------------------------------------- #
class _FakeGit:
    """Records git argv and returns canned results; fails any cmd containing
    `fail_on`."""

    def __init__(self, head="a" * 40, fail_on=None):
        self.calls: list[list[str]] = []
        self.head = head
        self.fail_on = fail_on

    def __call__(self, cmd):
        self.calls.append(cmd)
        if self.fail_on and self.fail_on in cmd:
            return subprocess.CompletedProcess(cmd, 1, "", "fatal: boom")
        out = self.head if "rev-parse" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")


def test_cloned_repo_clones_and_reports_commit(monkeypatch):
    monkeypatch.setattr(git_source, "_git_available", lambda: True)
    fake = _FakeGit(head="deadbeef" + "0" * 32)
    with cloned_repo("https://example.test/o/r.git", runner=fake) as repo:
        assert isinstance(repo, ClonedRepo)
        assert repo.path.is_dir()          # clone dir exists during the scan
        assert repo.commit == "deadbeef" + "0" * 32
        assert repo.project == "r"
        inside = repo.path
    assert not inside.exists()             # cleaned up afterwards
    assert any("clone" in c for c in fake.calls)


def test_cloned_repo_checks_out_a_commit_sha(monkeypatch):
    monkeypatch.setattr(git_source, "_git_available", lambda: True)
    fake = _FakeGit()
    sha = "1" * 40
    with cloned_repo("https://example.test/o/r.git", ref=sha, runner=fake):
        pass
    assert any("checkout" in c and sha in c for c in fake.calls)


def test_cloned_repo_raises_and_cleans_up_on_clone_failure(monkeypatch):
    monkeypatch.setattr(git_source, "_git_available", lambda: True)
    fake = _FakeGit(fail_on="clone")
    captured = {}
    with pytest.raises(GitError):
        with cloned_repo("https://example.test/o/r.git", runner=fake) as repo:
            captured["path"] = repo.path  # pragma: no cover - clone fails first
    # nothing leaks: no path yielded, and no temp dir left behind
    assert "path" not in captured


def test_cloned_repo_keep_retains_the_directory(monkeypatch):
    monkeypatch.setattr(git_source, "_git_available", lambda: True)
    fake = _FakeGit()
    with cloned_repo("https://example.test/o/r.git", keep=True, runner=fake) as repo:
        kept = repo.path
    try:
        assert kept.exists()               # kept for inspection
    finally:
        import shutil
        shutil.rmtree(kept, ignore_errors=True)


def test_cloned_repo_requires_git_installed(monkeypatch):
    monkeypatch.setattr(git_source, "_git_available", lambda: False)
    with pytest.raises(GitError, match="git"):
        with cloned_repo("https://example.test/o/r.git", runner=_FakeGit()):
            pass  # pragma: no cover


# --- CLI wiring: `aegis sast --git` ---------------------------------------- #
from aegis.cli import _cmd_sast, build_parser  # noqa: E402


def test_parser_rejects_path_and_git_together():
    with pytest.raises(SystemExit):
        build_parser().parse_args(
            ["sast", "--path", "x", "--git", "https://e.test/r.git", "--auth", "a"])


def test_parser_requires_a_source():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["sast", "--auth", "a"])


class _Args:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def test_cmd_sast_git_scans_the_clone(tmp_path, monkeypatch):
    # a throwaway "clone" on disk the fake context manager hands back
    clone = tmp_path / "clone"
    clone.mkdir()
    scanned = {}

    class _FakeCtx:
        def __enter__(self):
            return ClonedRepo(path=clone, url="https://e.test/o/proj.git",
                              ref=None, commit="c0ffee")
        def __exit__(self, *a):
            return False

    monkeypatch.setattr("aegis.cli._load_authorization", lambda p: object())
    monkeypatch.setattr("aegis.cli.cloned_repo",
                        lambda *a, **k: _FakeCtx())

    def _fake_run_sast(eng, path, project=None, logger=None):
        scanned["path"] = path
        scanned["project"] = project
        return "REPORT"

    monkeypatch.setattr("aegis.cli.run_sast", _fake_run_sast)
    monkeypatch.setattr("aegis.cli._write_outputs",
                        lambda eng, report, out, pdf=False: 0)

    args = _Args(git="https://e.test/o/proj.git", path=None, ref=None,
                 keep_clone=False, auth="a", out="runs", pdf=False)
    rc = _cmd_sast(args)
    assert rc == 0
    assert scanned["path"] == str(clone)
    assert scanned["project"] == "proj"
