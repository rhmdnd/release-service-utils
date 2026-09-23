"""Test the ``check_jira_project_component`` module."""

from __future__ import annotations

import json
import logging
import re
import subprocess
from pathlib import Path

import pytest
import requests

import release_service_utils.tasks.managed.check_jira_project_component.check_jira_project_component as mod  # noqa: E501


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
class _FakeResponse:
    def __init__(self, status_code: int, json_data=None) -> None:
        self.status_code = status_code
        self._json = json_data

    def json(self):
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class _FakeSession:
    """Fake requests.Session routing /myself and /project/<key>/components.

    ``projects`` maps a project key to its list of component names. A key
    absent from the mapping yields a 404 (project not found).
    """

    def __init__(
        self,
        *,
        myself_status: int = 200,
        projects: dict[str, list[str]] | None = None,
        raise_on: str | None = None,
    ) -> None:
        self.myself_status = myself_status
        self.projects = projects or {}
        self.raise_on = raise_on

    def get(self, url, auth=None, timeout=None):
        if self.raise_on and self.raise_on in url:
            raise requests.ConnectionError("boom")
        if url.endswith("/rest/api/2/myself"):
            return _FakeResponse(self.myself_status, {"name": "svc"})
        match = re.search(r"/rest/api/2/project/([^/]+)/components$", url)
        if match:
            key = match.group(1)
            if key not in self.projects:
                return _FakeResponse(404, {"errorMessages": ["no project"]})
            return _FakeResponse(200, [{"name": n} for n in self.projects[key]])
        return _FakeResponse(404)


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


def _patch_skopeo(monkeypatch, labels_by_image: dict[str, dict[str, str]]) -> None:
    def fake_inspect(image_ref: str, **_kwargs):
        labels = labels_by_image.get(image_ref, {})
        return _completed(json.dumps({"Labels": labels}))

    monkeypatch.setattr(mod.skopeo, "inspect", fake_inspect)


def _write_secret(tmp_path: Path) -> Path:
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "email").write_text("svc@example.com", encoding="utf-8")
    (secret / "token").write_text("t0ken", encoding="utf-8")
    return secret


def _run(tmp_path, monkeypatch, components, session, *, enforce):
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(snapshot, components)
    secret = _write_secret(tmp_path)
    monkeypatch.setattr(mod.http_client, "get_retry_session", lambda **_k: session)
    mod.check_jira_project_component(
        snapshot_path=snapshot, secret_path=secret, enforce=enforce
    )


def _component(image="registry.io/app@sha256:1", name="c1"):
    return {"name": name, "containerImage": image}


def _labels(project="EXAMPLE", component="api-server"):
    labels = {}
    if project is not None:
        labels[mod.ISSUE_TRACKER_PROJECT_LABEL] = project
    if component is not None:
        labels[mod.ISSUE_TRACKER_COMPONENT_LABEL] = component
    return labels


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #
def test_valid_project_and_component_passes(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels()})
    session = _FakeSession(projects={"EXAMPLE": ["api-server", "central"]})
    _run(tmp_path, monkeypatch, [_component()], session, enforce=True)


def test_component_match_is_case_insensitive(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels(component="api-server")})
    session = _FakeSession(projects={"EXAMPLE": ["API-Server"]})
    _run(tmp_path, monkeypatch, [_component()], session, enforce=True)


def test_lowercase_project_key_is_normalized(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels(project="example")})
    session = _FakeSession(projects={"EXAMPLE": ["api-server"]})
    _run(tmp_path, monkeypatch, [_component()], session, enforce=True)


def test_missing_project_raises_in_enforce(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels()})
    session = _FakeSession(projects={})  # EXAMPLE not present -> 404
    with pytest.raises(mod.TrackerValidationError):
        _run(tmp_path, monkeypatch, [_component()], session, enforce=True)


def test_missing_project_warns_when_not_enforced(tmp_path, monkeypatch, caplog):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels()})
    session = _FakeSession(projects={})
    with caplog.at_level(logging.WARNING):
        _run(tmp_path, monkeypatch, [_component()], session, enforce=False)
    assert "does not exist on" in caplog.text


def test_component_mismatch_raises_in_enforce(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels(component="api-server")})
    session = _FakeSession(projects={"EXAMPLE": ["central"]})
    with pytest.raises(mod.TrackerValidationError):
        _run(tmp_path, monkeypatch, [_component()], session, enforce=True)


def test_project_with_no_components_raises_in_enforce(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels()})
    session = _FakeSession(projects={"EXAMPLE": []})
    with pytest.raises(mod.TrackerValidationError):
        _run(tmp_path, monkeypatch, [_component()], session, enforce=True)


def test_missing_issue_tracker_project_label_is_skipped(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels(project=None)})
    session = _FakeSession(projects={})
    _run(tmp_path, monkeypatch, [_component()], session, enforce=True)


def test_missing_issue_tracker_component_label_raises_in_enforce(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels(component=None)})
    session = _FakeSession(projects={"EXAMPLE": ["api-server"]})
    with pytest.raises(mod.TrackerValidationError):
        _run(tmp_path, monkeypatch, [_component()], session, enforce=True)


def test_bugzilla_component_label_does_not_satisfy_the_check(tmp_path, monkeypatch):
    """Reject an image that only carries the Bugzilla-specific component label."""
    labels = _labels(component=None) | {"com.redhat.component": "api-server"}
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": labels})
    session = _FakeSession(projects={"EXAMPLE": ["api-server"]})
    with pytest.raises(mod.TrackerValidationError):
        _run(tmp_path, monkeypatch, [_component()], session, enforce=True)


def test_auth_failure_is_always_fatal(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels()})
    session = _FakeSession(myself_status=401, projects={"EXAMPLE": ["api-server"]})
    # Fatal even with enforce=False.
    with pytest.raises(mod.JiraConnectionError):
        _run(tmp_path, monkeypatch, [_component()], session, enforce=False)


def test_unreachable_jira_is_always_fatal(tmp_path, monkeypatch):
    _patch_skopeo(monkeypatch, {"registry.io/app@sha256:1": _labels()})
    session = _FakeSession(raise_on="/myself", projects={"EXAMPLE": ["api-server"]})
    with pytest.raises(mod.JiraConnectionError):
        _run(tmp_path, monkeypatch, [_component()], session, enforce=False)


def test_skopeo_failure_is_hard_error(tmp_path, monkeypatch):
    def fake_inspect(image_ref: str, **_kwargs):
        return _completed("", returncode=1, stderr="boom")

    monkeypatch.setattr(mod.skopeo, "inspect", fake_inspect)
    session = _FakeSession(projects={"EXAMPLE": ["api-server"]})
    with pytest.raises(mod.TrackerValidationError):
        _run(tmp_path, monkeypatch, [_component()], session, enforce=False)
