"""Fetch a git repository into a throwaway working tree for SAST.

The ``sast`` command can scan either a local ``--path`` or a ``--git`` URL. For
``--git`` the repository is cloned fresh into a temp directory, scanned there,
and removed afterwards (unless kept for inspection).

Authentication is delegated entirely to git: whatever the ambient credential
helper, the SSH agent, or a token embedded in the URL provides. aegis stores and
handles no credentials. ``credential.interactive=false`` + ``GIT_TERMINAL_PROMPT=0``
make a missing credential fail fast instead of hanging on a prompt.

The clone is treated as untrusted data: the SAST adapters read the code, they do
not build or execute it.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional

Runner = Callable[[list[str]], "subprocess.CompletedProcess"]
Logger = Callable[[str], None]

_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")


class GitError(RuntimeError):
    """A git clone/checkout failed, or git is unavailable."""


@dataclass
class ClonedRepo:
    """A cloned repository: where it is on disk and what was fetched."""

    path: Path
    url: str
    ref: Optional[str]
    commit: str

    @property
    def project(self) -> str:
        return repo_name(self.url)


def repo_name(url: str) -> str:
    """Derive a short project name from a clone URL.

    Handles https and scp-like (``git@host:org/repo.git``) forms; strips a
    trailing ``.git``. Falls back to ``repo`` if nothing usable remains.
    """
    tail = re.split(r"[/:]", url.rstrip("/"))[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    return tail or "repo"


def clone_argv(url: str, dest: str, ref: Optional[str] = None) -> list[str]:
    """Build the ``git clone`` argv.

    A branch/tag ref clones shallow with ``--branch``; a full commit SHA needs a
    non-shallow clone (``--branch`` cannot select an arbitrary commit) and is
    checked out separately. ``url`` and ``dest`` are passed positionally after a
    ``--`` guard so they are never mistaken for options.
    """
    base = ["git", "-c", "credential.interactive=false", "clone"]
    if ref and not _SHA_RE.match(ref):
        return base + ["--depth", "1", "--branch", ref, "--", url, dest]
    if ref:  # commit SHA
        return base + ["--", url, dest]
    return base + ["--depth", "1", "--", url, dest]


def _git_available() -> bool:
    return shutil.which("git") is not None


def _default_runner(cmd: list[str]) -> "subprocess.CompletedProcess":
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)


def _run(runner: Runner, cmd: list[str], what: str) -> "subprocess.CompletedProcess":
    proc = runner(cmd)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[:500]
        raise GitError(f"{what} failed: {detail}" if detail else f"{what} failed")
    return proc


@contextmanager
def cloned_repo(url: str, ref: Optional[str] = None, keep: bool = False,
                runner: Optional[Runner] = None,
                log: Optional[Logger] = None) -> Iterator[ClonedRepo]:
    """Clone ``url`` into a temp dir and yield a :class:`ClonedRepo`.

    The directory is removed when the context exits unless ``keep`` is set.
    Raises :class:`GitError` if git is unavailable or a clone/checkout fails.
    """
    runner = runner or _default_runner
    log = log or (lambda _m: None)
    if not _git_available():
        raise GitError("git is not installed or not on PATH — install git to use --git")

    dest = Path(tempfile.mkdtemp(prefix="aegis-sast-"))
    try:
        log(f"Cloning {url}" + (f" @ {ref}" if ref else "") + " ...")
        _run(runner, clone_argv(url, str(dest), ref), "git clone")
        if ref and _SHA_RE.match(ref):
            _run(runner, ["git", "-C", str(dest), "checkout", "--detach", ref],
                 "git checkout")
        head = runner(["git", "-C", str(dest), "rev-parse", "HEAD"])
        commit = (head.stdout or "").strip() if head.returncode == 0 else ""
        log(f"Cloned at {commit[:12] or '?'}")
        yield ClonedRepo(path=dest, url=url, ref=ref, commit=commit)
    finally:
        if keep:
            log(f"Keeping clone at {dest}")
        else:
            shutil.rmtree(dest, ignore_errors=True)
