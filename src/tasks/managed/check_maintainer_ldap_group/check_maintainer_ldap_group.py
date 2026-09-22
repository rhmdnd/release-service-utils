#!/usr/bin/env python3
"""Validate that each image's ``maintainer`` label maps to a valid LDAP group.

For every container image component in the snapshot this script:

1. Reads the ``maintainer`` label from the image (via ``skopeo inspect``).
2. Parses an email address out of the label value.
3. Requires the email to be a ``@redhat.com`` address.
4. Treats the email's local part as an LDAP group ``cn`` and looks it up.
5. Ensures the group has at least ``--min-members`` unique members.

With ``--enforce true`` any of the above validation failures cause a non-zero
exit. Without it, the failures are logged as warnings and the script exits
successfully. A failure to establish or bind the LDAP connection is always
fatal, regardless of the enforce setting.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
from pathlib import Path
from typing import Any

from ldap3 import ALL, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException

from release_service_utils.helpers import skopeo
from release_service_utils.helpers.file import load_json_dict
from release_service_utils.helpers.logger import logger

PROG = "check_maintainer_ldap_group.py"

REQUIRED_DOMAIN = "redhat.com"

# LDAP attributes that may hold group membership, depending on the schema.
MEMBER_ATTRIBUTES = ("member", "uniqueMember", "memberUid")

# RFC 4515 special characters that must be escaped inside an LDAP filter value.
_FILTER_ESCAPES = {
    "\\": "\\5c",
    "*": "\\2a",
    "(": "\\28",
    ")": "\\29",
    "\x00": "\\00",
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _escape_filter_chars(value: str) -> str:
    """Escape RFC 4515 special characters in an LDAP filter assertion value."""
    return "".join(_FILTER_ESCAPES.get(ch, ch) for ch in value)


class MaintainerValidationError(Exception):
    """Raise when maintainer validation fails in enforce mode."""


class LDAPConnectionError(Exception):
    """Raise when the LDAP server cannot be reached or bound to.

    This is always fatal, independent of the enforce setting, because the
    script cannot make any determination without a working connection.
    """


def extract_email(maintainer: str | None) -> str | None:
    """Return the first email address found in a maintainer label value.

    Return ``None`` when the label is absent or contains no email address.
    """
    if not maintainer:
        return None
    match = _EMAIL_RE.search(maintainer)
    return match.group(0) if match else None


def get_maintainer_label(image_ref: str) -> str | None:
    """Return the ``maintainer`` label of an image, or ``None`` if unset.

    Raise ``MaintainerValidationError`` when the image cannot be inspected,
    as that is a hard data error rather than a policy violation.
    """
    result = skopeo.inspect(image_ref, no_tags=True)
    if result.returncode != 0:
        raise MaintainerValidationError(
            f"skopeo inspect failed for '{image_ref}': {result.stderr.strip()}"
        )
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise MaintainerValidationError(
            f"could not parse skopeo inspect output for '{image_ref}': {exc}"
        ) from exc
    labels = metadata.get("Labels") or {}
    value = labels.get("maintainer")
    return str(value).strip() if value is not None else None


def connect_ldap(uri: str, bind_dn: str, bind_password: str) -> Connection:
    """Open and bind an LDAPS connection.

    Raise ``LDAPConnectionError`` on any connection or bind failure so the
    caller can treat it as fatal.
    """
    try:
        tls = Tls(validate=ssl.CERT_REQUIRED)
        server = Server(uri, use_ssl=True, tls=tls, get_info=ALL)
        return Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
    except LDAPException as exc:
        raise LDAPConnectionError(
            f"unable to establish LDAP connection to '{uri}': {exc}"
        ) from exc


def count_unique_group_members(conn: Connection, base_dn: str, cn: str) -> int | None:
    """Return the number of unique members of the group with the given ``cn``.

    Return ``None`` when no group with that ``cn`` exists under ``base_dn``.
    Members are collected across the ``member``, ``uniqueMember`` and
    ``memberUid`` attributes and de-duplicated case-insensitively.
    """
    search_filter = f"(cn={_escape_filter_chars(cn)})"
    conn.search(
        search_base=base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=list(MEMBER_ATTRIBUTES),
    )
    if not conn.entries:
        return None

    members: set[str] = set()
    for entry in conn.entries:
        for attr in MEMBER_ATTRIBUTES:
            values = entry[attr].values if attr in entry else []
            for value in values:
                members.add(str(value).strip().lower())
    members.discard("")
    return len(members)


def _validate_component(
    component: dict[str, Any],
    conn: Connection,
    base_dn: str,
    min_members: int,
) -> str | None:
    """Validate a single component. Return an error message or ``None``.

    A returned string describes a policy violation (missing/invalid
    maintainer, missing LDAP group, or insufficient membership). ``None``
    means the component passed all checks.
    """
    comp_name = component.get("name", "<unknown>")
    image_ref = (component.get("containerImage") or "").strip()
    if not image_ref:
        raise MaintainerValidationError(f"Component '{comp_name}' is missing 'containerImage'")

    maintainer = get_maintainer_label(image_ref)
    email = extract_email(maintainer)
    if email is None:
        return (
            f"Component '{comp_name}' has no email address in its "
            f"'maintainer' label (value: '{maintainer}')."
        )

    domain = email.split("@", 1)[1].lower()
    if domain != REQUIRED_DOMAIN:
        return (
            f"Component '{comp_name}' maintainer email '{email}' is not a "
            f"'@{REQUIRED_DOMAIN}' address."
        )

    local_part = email.split("@", 1)[0]
    member_count = count_unique_group_members(conn, base_dn, local_part)
    if member_count is None:
        return (
            f"Component '{comp_name}' maintainer '{email}': no LDAP group "
            f"with cn='{local_part}' exists under '{base_dn}'."
        )

    if member_count < min_members:
        return (
            f"Component '{comp_name}' maintainer LDAP group '{local_part}' "
            f"has {member_count} unique member(s), fewer than the required "
            f"minimum of {min_members}."
        )

    logger.info(
        "Component '%s' maintainer group '%s' has %d unique member(s).",
        comp_name,
        local_part,
        member_count,
    )
    return None


def check_maintainer_ldap_group(
    snapshot_path: Path,
    ldap_uri: str,
    bind_dn: str,
    bind_password: str,
    group_base_dn: str,
    min_members: int,
    enforce: bool,
) -> None:
    """Validate maintainer labels for all image components against LDAP.

    Raise ``LDAPConnectionError`` if the LDAP server cannot be reached
    (always fatal). Raise ``MaintainerValidationError`` when validation
    fails and ``enforce`` is True, or on hard data errors.
    """
    snapshot = load_json_dict(snapshot_path)
    components = snapshot.get("components") or []

    conn = connect_ldap(ldap_uri, bind_dn, bind_password)
    try:
        violations: list[str] = []
        for component in components:
            error = _validate_component(component, conn, group_base_dn, min_members)
            if error is not None:
                violations.append(error)
    finally:
        conn.unbind()

    if not violations:
        logger.info("All components passed maintainer LDAP group validation.")
        return

    for violation in violations:
        if enforce:
            logger.error(violation)
        else:
            logger.warning(violation)

    if enforce:
        raise MaintainerValidationError(
            f"{len(violations)} component(s) failed maintainer LDAP " f"group validation."
        )


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse CLI arguments for the check-maintainer-ldap-group script."""
    p = argparse.ArgumentParser(prog=PROG, description=__doc__)
    p.add_argument(
        "--snapshot-file",
        required=True,
        help="Path to the mapped snapshot JSON file",
    )
    p.add_argument(
        "--ldap-uri",
        required=True,
        help="LDAPS connection string, e.g. 'ldaps://ldap.corp.example.com:636'",
    )
    p.add_argument(
        "--ldap-secret-path",
        required=True,
        help=(
            "Path to the mounted secret directory containing 'bind_dn' and "
            "'bind_password' files for the LDAP service account"
        ),
    )
    p.add_argument(
        "--group-base-dn",
        required=True,
        help="LDAP search base under which group CNs are looked up",
    )
    p.add_argument(
        "--min-members",
        type=int,
        default=2,
        help="Minimum number of unique members a group must have (default: 2)",
    )
    p.add_argument(
        "--enforce",
        type=lambda s: s.strip().lower() == "true",
        default=True,
        help="Set to 'true' to treat validation failures as errors (default: 'true')",
    )
    return p.parse_args(argv)


def _read_secret(secret_path: Path, key: str) -> str:
    """Read a single secret value from ``<secret_path>/<key>``."""
    path = secret_path / key
    if not path.is_file():
        raise MaintainerValidationError(
            f"LDAP secret is missing the required key '{key}' at '{path}'"
        )
    return path.read_text(encoding="utf-8").strip()


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and run the maintainer LDAP group checks."""
    args = parse_args(argv[1:] if argv is not None else None)
    secret_path = Path(args.ldap_secret_path)
    bind_dn = _read_secret(secret_path, "bind_dn")
    bind_password = _read_secret(secret_path, "bind_password")

    check_maintainer_ldap_group(
        snapshot_path=Path(args.snapshot_file),
        ldap_uri=args.ldap_uri,
        bind_dn=bind_dn,
        bind_password=bind_password,
        group_base_dn=args.group_base_dn,
        min_members=args.min_members,
        enforce=args.enforce,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
