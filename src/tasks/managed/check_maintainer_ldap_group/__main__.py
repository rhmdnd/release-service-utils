"""Entry point for check_maintainer_ldap_group task."""

from __future__ import annotations

from release_service_utils.tasks.managed.check_maintainer_ldap_group.check_maintainer_ldap_group import (  # noqa: E501
    main,
)

if __name__ == "__main__":
    raise SystemExit(main())
