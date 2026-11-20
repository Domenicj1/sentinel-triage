"""Placeholder test to satisfy pytest collection until real tests arrive in Stage 2.

Stage 2 will add real tests for the parser and clusterer modules. Until then,
this file ensures the CI pipeline passes on `pytest` runs.
"""


def test_project_imports():
    """Smoke test: the log generator module imports cleanly.
    The in-line comment below is actually a directive to the linter, forcing it to ignore rule F401 on that line (noqa=no quality assurance)
    """
    import generate_logs  # noqa: F401 — imported for side-effect of catching syntax/import errors
