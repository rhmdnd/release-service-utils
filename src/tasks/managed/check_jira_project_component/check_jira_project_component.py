#!/usr/bin/env python3
"""Validate that image issue-tracker labels map to valid Jira projects.

For every container image component in the snapshot this script:

1. Reads the ``com.redhat.issue-tracker-project`` and
   ``com.redhat.issue-tracker-component`` labels from the image (via
   ``skopeo inspect``).
2. Confirms the Jira project named by ``com.redhat.issue-tracker-project``
   exists.
3. Confirms ``com.redhat.issue-tracker-component`` matches a component of that
   project.

The Jira server is fixed (``redhat.atlassian.net``), so the label carries only
the project key (e.g. ``OCPBUGS``) rather than a full URL.

Note that ``com.redhat.component`` is deliberately not consulted: that label is
Bugzilla specific, so the Jira component is carried by its own label instead.

With ``--enforce true`` (the default) any validation failure causes a non-zero
exit. Without it, failures are logged as warnings and the script exits
successfully. A failure to reach or authenticate to Jira is always fatal,
regardless of the enforce setting.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth

from release_service_utils.helpers import http_client, skopeo
from release_service_utils.helpers.file import load_json_dict
from release_service_utils.helpers.jira import (
    SUPPORTED_JIRA_SERVER,
    read_jira_credentials,
)
from release_service_utils.helpers.logger import logger

PROG = "check_jira_project_component.py"

ISSUE_TRACKER_PROJECT_LABEL = "com.redhat.issue-tracker-project"
ISSUE_TRACKER_COMPONENT_LABEL = "com.redhat.issue-tracker-component"

REQUEST_TIMEOUT = 60.0


class TrackerValidationError(Exception):
    """Raise when tracker/project/component validation fails in enforce mode."""


class JiraConnectionError(Exception):
    """Raise when Jira cannot be reached or authenticated to.

    This is always fatal, independent of the enforce setting, because the
    script cannot make any determination without a working connection.
    """


def get_image_labels(image_ref: str) -> dict[str, str]:
    """Return the labels of an image as a dict.

    Raise ``TrackerValidationError`` when the image cannot be inspected, as
    that is a hard data error rather than a policy violation.
    """
    result = skopeo.inspect(image_ref, no_tags=True)
    if result.returncode != 0:
        raise TrackerValidationError(
            f"skopeo inspect failed for '{image_ref}': {result.stderr.strip()}"
        )
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise TrackerValidationError(
            f"could not parse skopeo inspect output for '{image_ref}': {exc}"
        ) from exc
    return metadata.get("Labels") or {}


def verify_jira_connection(
    session: requests.Session, auth: HTTPBasicAuth, server: str
) -> None:
    """Verify Jira is reachable and the credentials authenticate.

    Raise ``JiraConnectionError`` on any connection or authentication failure
    so the caller can treat it as fatal.
    """
    url = f"https://{server}/rest/api/2/myself"
    try:
        response = session.get(url, auth=auth, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise JiraConnectionError(f"unable to reach Jira at '{server}': {exc}") from exc
    if response.status_code in (401, 403):
        raise JiraConnectionError(
            f"Jira authentication failed ({response.status_code}) for '{server}'"
        )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise JiraConnectionError(
            f"Jira connection check failed for '{server}': {exc}"
        ) from exc


def fetch_project_components(
    session: requests.Session, auth: HTTPBasicAuth, server: str, project_key: str
) -> list[str] | None:
    """Return the component names of a Jira project.

    Return ``None`` when the project does not exist (HTTP 404). Raise
    ``JiraConnectionError`` on auth/network/other errors (always fatal).
    """
    url = f"https://{server}/rest/api/2/project/{quote(project_key)}/components"
    try:
        response = session.get(url, auth=auth, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise JiraConnectionError(
            f"unable to query Jira project '{project_key}': {exc}"
        ) from exc
    if response.status_code == 404:
        return None
    if response.status_code in (401, 403):
        raise JiraConnectionError(
            f"Jira authorization failed ({response.status_code}) for project "
            f"'{project_key}'"
        )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise JiraConnectionError(
            f"Jira query failed for project '{project_key}': {exc}"
        ) from exc
    data = response.json()
    return [c["name"] for c in data if isinstance(c, dict) and c.get("name")]


def _classify_component(component: dict[str, Any]) -> tuple[str, Any]:
    """Classify a single snapshot component without contacting Jira.

    Return a ``(status, payload)`` tuple where ``status`` is one of:

    - ``"skip"``: nothing to validate (no issue-tracker-project label);
      ``payload`` is None.
    - ``"violation"``: a violation detectable without a Jira lookup (an
      issue-tracker-project is set but the issue-tracker-component label is
      missing); ``payload`` is the message string.
    - ``"validate"``: needs a Jira lookup; ``payload`` is a
      ``(comp_name, project_key, component_label)`` tuple.
    """
    comp_name = component.get("name", "<unknown>")
    image_ref = (component.get("containerImage") or "").strip()
    if not image_ref:
        raise TrackerValidationError(f"Component '{comp_name}' is missing 'containerImage'")

    labels = get_image_labels(image_ref)
    project_key = (labels.get(ISSUE_TRACKER_PROJECT_LABEL) or "").strip().upper()
    if not project_key:
        logger.info(
            "Component '%s' has no '%s' label; skipping (label presence is "
            "enforced separately).",
            comp_name,
            ISSUE_TRACKER_PROJECT_LABEL,
        )
        return ("skip", None)

    component_label = (labels.get(ISSUE_TRACKER_COMPONENT_LABEL) or "").strip()
    if not component_label:
        return (
            "violation",
            f"Snapshot component '{comp_name}' sets '{ISSUE_TRACKER_PROJECT_LABEL}' "
            f"to '{project_key}' but is missing the "
            f"'{ISSUE_TRACKER_COMPONENT_LABEL}' label.",
        )

    return ("validate", (comp_name, project_key, component_label))


def _validate_jira_component(
    session: requests.Session,
    auth: HTTPBasicAuth,
    comp_name: str,
    project_key: str,
    component_label: str,
) -> str | None:
    """Look up a Jira project and confirm it has the required component.

    Return a violation message, or None when the component passes.
    """
    component_names = fetch_project_components(
        session, auth, SUPPORTED_JIRA_SERVER, project_key
    )
    if component_names is None:
        return (
            f"Jira project '{project_key}' does not exist on "
            f"{SUPPORTED_JIRA_SERVER} (required by snapshot component "
            f"'{comp_name}')."
        )
    if not component_names:
        return (
            f"Jira project '{project_key}' has no components defined, so it "
            f"cannot contain '{component_label}' (required by snapshot "
            f"component '{comp_name}')."
        )
    if component_label.lower() not in {name.strip().lower() for name in component_names}:
        return (
            f"Jira project '{project_key}' does not contain the component "
            f"'{component_label}' (required by snapshot component '{comp_name}'; "
            f"existing components: {sorted(component_names)})."
        )

    logger.info(
        "Jira project '%s' contains component '%s' (snapshot component '%s').",
        project_key,
        component_label,
        comp_name,
    )
    return None


def check_jira_project_component(
    snapshot_path: Path,
    secret_path: Path,
    enforce: bool,
) -> None:
    """Validate the issue-tracker labels for all image components.

    Raise ``JiraConnectionError`` if Jira cannot be reached (always fatal).
    Raise ``TrackerValidationError`` when validation fails and ``enforce`` is
    True, or on hard data errors. Jira is only contacted when at least one
    component actually needs a project lookup.
    """
    snapshot = load_json_dict(snapshot_path)
    components = snapshot.get("components") or []

    violations: list[str] = []
    to_validate: list[tuple[str, str, str]] = []
    for component in components:
        status, payload = _classify_component(component)
        if status == "violation":
            violations.append(payload)
        elif status == "validate":
            to_validate.append(payload)

    if to_validate:
        email, token = read_jira_credentials(secret_path)
        auth = HTTPBasicAuth(email, token)
        session = http_client.get_retry_session(
            total=5,
            connect=3,
            read=3,
            status=5,
            backoff_factor=1.0,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
        )
        verify_jira_connection(session, auth, SUPPORTED_JIRA_SERVER)
        for comp_name, project_key, component_label in to_validate:
            error = _validate_jira_component(
                session, auth, comp_name, project_key, component_label
            )
            if error is not None:
                violations.append(error)

    if not violations:
        logger.info("All components passed Jira project/component validation.")
        return

    for violation in violations:
        if enforce:
            logger.error(violation)
        else:
            logger.warning(violation)

    if enforce:
        raise TrackerValidationError(
            f"{len(violations)} component(s) failed Jira project/component " f"validation."
        )


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse CLI arguments for the check-jira-project-component script."""
    p = argparse.ArgumentParser(prog=PROG, description=__doc__)
    p.add_argument(
        "--snapshot-file",
        required=True,
        help="Path to the mapped snapshot JSON file",
    )
    p.add_argument(
        "--jira-secret-path",
        required=True,
        help=(
            "Path to the mounted secret directory containing 'email' and "
            "'token' files for Jira basic authentication"
        ),
    )
    p.add_argument(
        "--enforce",
        type=lambda s: s.strip().lower() == "true",
        default=True,
        help="Set to 'true' to treat validation failures as errors (default: 'true')",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the Jira project/component checks."""
    args = parse_args(argv[1:] if argv is not None else None)
    check_jira_project_component(
        snapshot_path=Path(args.snapshot_file),
        secret_path=Path(args.jira_secret_path),
        enforce=args.enforce,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
