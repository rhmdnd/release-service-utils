"""Validate image issue-tracker labels against Jira projects and components.

For each container image component the ``com.redhat.issue-tracker-project``
label is read as a Jira project key, the project is confirmed to exist, and it
is confirmed to have a component matching
``com.redhat.issue-tracker-component``.

With ``--enforce true`` validation failures cause a non-zero exit. Without it,
failures are logged as warnings and the script exits successfully. A failure to
reach or authenticate to Jira is always fatal.
"""

from .check_jira_project_component import (  # noqa: F401
    ISSUE_TRACKER_COMPONENT_LABEL,
    ISSUE_TRACKER_PROJECT_LABEL,
    PROG,
    JiraConnectionError,
    TrackerValidationError,
    fetch_project_components,
    get_image_labels,
    main,
    parse_args,
    verify_jira_connection,
)
