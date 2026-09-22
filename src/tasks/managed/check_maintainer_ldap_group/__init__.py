"""Validate image ``maintainer`` labels against LDAP group membership.

For each container image component the ``maintainer`` label is read, an email
address is parsed out of it, and the email's local part is looked up as an LDAP
group ``cn``. The group must exist and have at least the required number of
unique members.

With ``--enforce true`` validation failures cause a non-zero exit. Without it,
failures are logged as warnings and the script exits successfully. A failure to
connect to LDAP is always fatal.
"""

from .check_maintainer_ldap_group import (  # noqa: F401
    MEMBER_ATTRIBUTES,
    PROG,
    REQUIRED_DOMAIN,
    LDAPConnectionError,
    MaintainerValidationError,
    connect_ldap,
    count_unique_group_members,
    extract_email,
    get_maintainer_label,
    main,
    parse_args,
)
