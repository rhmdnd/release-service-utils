"""Test the ``check_maintainer_ldap_group`` module."""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import pytest

import release_service_utils.tasks.managed.check_maintainer_ldap_group.check_maintainer_ldap_group as mod  # noqa: E501


@pytest.fixture(autouse=True)
def _propagate_release_logger():
    """Allow caplog to capture records from the 'release' logger."""
    release_logger = logging.getLogger("release")
    release_logger.propagate = True
    yield
    release_logger.propagate = False


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #
class _FakeAttr:
    """Mimic an ldap3 entry attribute exposing a ``.values`` list."""

    def __init__(self, values: list[str]) -> None:
        self.values = values


class _FakeEntry:
    """Mimic an ldap3 entry supporting ``attr in entry`` and ``entry[attr]``."""

    def __init__(self, attrs: dict[str, list[str]]) -> None:
        self._attrs = attrs

    def __contains__(self, key: str) -> bool:
        return key in self._attrs

    def __getitem__(self, key: str) -> _FakeAttr:
        return _FakeAttr(self._attrs[key])


class _FakeConnection:
    """Mimic the subset of ldap3.Connection used by the module."""

    def __init__(self, entries_by_cn: dict[str, _FakeEntry]) -> None:
        self._entries_by_cn = entries_by_cn
        self.entries: list[_FakeEntry] = []
        self.unbound = False

    def search(self, *, search_filter: str, **_kwargs) -> None:
        # search_filter looks like "(cn=alice)"
        cn = search_filter.strip("()").split("=", 1)[1]
        entry = self._entries_by_cn.get(cn)
        self.entries = [entry] if entry is not None else []

    def unbind(self) -> None:
        self.unbound = True


def _completed(
    stdout: str, returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=["skopeo"], returncode=returncode, stdout=stdout, stderr=stderr
    )


def _write_snapshot(path: Path, components: list[dict]) -> None:
    path.write_text(
        json.dumps({"application": "myapp", "components": components}),
        encoding="utf-8",
    )


# --------------------------------------------------------------------------- #
# extract_email
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value,expected",
    [
        ("alice@example.com", "alice@example.com"),
        ("Alice <alice@example.com>", "alice@example.com"),
        ("Team Alice team-alice@example.com", "team-alice@example.com"),
        ("Example, Inc.", None),
        ("", None),
        (None, None),
    ],
)
def test_extract_email(value, expected):
    assert mod.extract_email(value) == expected


# --------------------------------------------------------------------------- #
# _escape_filter_chars
# --------------------------------------------------------------------------- #
def test_escape_filter_chars():
    assert mod._escape_filter_chars("a*b(c)\\d") == "a\\2ab\\28c\\29\\5cd"
    assert mod._escape_filter_chars("plain") == "plain"


# --------------------------------------------------------------------------- #
# count_unique_group_members
# --------------------------------------------------------------------------- #
def test_count_unique_group_members_dedupes_across_attrs():
    entry = _FakeEntry(
        {
            "member": ["uid=a,dc=x", "uid=b,dc=x"],
            "uniqueMember": ["uid=B,dc=x"],  # duplicate of b (case-insensitive)
            "memberUid": ["c"],
        }
    )
    conn = _FakeConnection({"alice": entry})
    assert mod.count_unique_group_members(conn, "ou=g", "alice") == 3


def test_count_unique_group_members_missing_group_returns_none():
    conn = _FakeConnection({})
    assert mod.count_unique_group_members(conn, "ou=g", "nope") is None


# --------------------------------------------------------------------------- #
# End-to-end via check_maintainer_ldap_group
# --------------------------------------------------------------------------- #
def _patch_skopeo(monkeypatch, maintainer_by_image: dict[str, str | None]) -> None:
    def fake_inspect(image_ref: str, **_kwargs):
        maintainer = maintainer_by_image.get(image_ref)
        labels = {} if maintainer is None else {"maintainer": maintainer}
        return _completed(json.dumps({"Labels": labels}))

    monkeypatch.setattr(mod.skopeo, "inspect", fake_inspect)


def _run(tmp_path, monkeypatch, components, entries_by_cn, *, enforce, min_members=2):
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(snapshot, components)
    conn = _FakeConnection(entries_by_cn)
    monkeypatch.setattr(mod, "connect_ldap", lambda *a, **k: conn)
    mod.check_maintainer_ldap_group(
        snapshot_path=snapshot,
        ldap_uri="ldaps://ldap.example.com",
        bind_dn="cn=svc",
        bind_password="pw",
        group_base_dn="ou=Groups,dc=example,dc=com",
        min_members=min_members,
        enforce=enforce,
    )
    return conn


def test_valid_group_passes(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": "alice@redhat.com"})
    entry = _FakeEntry({"member": ["uid=a", "uid=b"]})
    conn = _run(
        tmp_path,
        monkeypatch,
        [{"name": "c1", "containerImage": "registry.io/app@sha256:1"}],
        {"alice": entry},
        enforce=True,
    )
    assert conn.unbound is True


def test_non_matching_domain_email_raises_in_enforce(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": "alice@example.com"})
    with pytest.raises(mod.MaintainerValidationError):
        _run(
            tmp_path,
            monkeypatch,
            [{"name": "c1", "containerImage": "registry.io/app@sha256:1"}],
            {},
            enforce=True,
        )


def test_non_matching_domain_email_warns_when_not_enforced(tmp_path, monkeypatch, caplog):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": "alice@example.com"})
    with caplog.at_level(logging.WARNING):
        _run(
            tmp_path,
            monkeypatch,
            [{"name": "c1", "containerImage": "registry.io/app@sha256:1"}],
            {},
            enforce=False,
        )
    assert "not a '@redhat.com'" in caplog.text


def test_missing_group_raises_in_enforce(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": "alice@redhat.com"})
    with pytest.raises(mod.MaintainerValidationError):
        _run(
            tmp_path,
            monkeypatch,
            [{"name": "c1", "containerImage": "registry.io/app@sha256:1"}],
            {},  # no group for 'alice'
            enforce=True,
        )


def test_too_few_members_raises_in_enforce(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": "alice@redhat.com"})
    entry = _FakeEntry({"member": ["uid=a"]})
    with pytest.raises(mod.MaintainerValidationError):
        _run(
            tmp_path,
            monkeypatch,
            [{"name": "c1", "containerImage": "registry.io/app@sha256:1"}],
            {"alice": entry},
            enforce=True,
            min_members=2,
        )


def test_too_few_members_warns_when_not_enforced(tmp_path, monkeypatch, caplog):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": "alice@redhat.com"})
    entry = _FakeEntry({"member": ["uid=a"]})
    with caplog.at_level(logging.WARNING):
        _run(
            tmp_path,
            monkeypatch,
            [{"name": "c1", "containerImage": "registry.io/app@sha256:1"}],
            {"alice": entry},
            enforce=False,
            min_members=2,
        )
    assert "fewer than the required minimum" in caplog.text


def test_ldap_connection_failure_is_always_fatal(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": "alice@redhat.com"})
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(snapshot, [{"name": "c1", "containerImage": "registry.io/app@sha256:1"}])

    def boom(*_a, **_k):
        raise mod.LDAPConnectionError("cannot connect")

    monkeypatch.setattr(mod, "connect_ldap", boom)
    # Fatal even with enforce=False.
    with pytest.raises(mod.LDAPConnectionError):
        mod.check_maintainer_ldap_group(
            snapshot_path=snapshot,
            ldap_uri="ldaps://ldap.example.com",
            bind_dn="cn=svc",
            bind_password="pw",
            group_base_dn="ou=Groups,dc=example,dc=com",
            min_members=2,
            enforce=False,
        )


def test_skopeo_failure_is_hard_error(tmp_path, monkeypatch):
    def fake_inspect(image_ref: str, **_kwargs):
        return _completed("", returncode=1, stderr="boom")

    monkeypatch.setattr(mod.skopeo, "inspect", fake_inspect)
    with pytest.raises(mod.MaintainerValidationError):
        _run(
            tmp_path,
            monkeypatch,
            [{"name": "c1", "containerImage": "registry.io/app@sha256:1"}],
            {},
            enforce=False,
        )
