"""firedrill -- prove a Postgres backup actually restores."""

from importlib.metadata import PackageNotFoundError, version as _installed

try:
    # Read from the installed distribution rather than repeating the number
    # here. pyproject.toml is the single declaration, and this can no longer
    # disagree with it, because it *is* it.
    #
    # It used to be a literal, and the literal drifted: 0.1.1 was tagged with
    # pyproject bumped and this left at 0.1.0, so the wheel was version 0.1.1
    # and `firedrill --version` said 0.1.0. A tool whose whole argument is that
    # software misreports its own state should not misreport its own version.
    __version__ = _installed("firedrill")
except PackageNotFoundError:
    # A source checkout that was never installed genuinely has no version, and
    # saying so is better than inventing one that will rot.
    __version__ = "0+source"
