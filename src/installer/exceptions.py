"""Errors raised from this package."""


class InstallerError(Exception):
    """All exceptions raised from this package's code."""


class InvalidWheelSource(InstallerError):
    """When a wheel source violates a contract, or is not supported."""


class InstallationPlanError(InstallerError):
    """When an installation plan cannot be built or safely executed.

    A plan fails to build when the wheel cannot be installed without clobbering
    another file, escaping the trusted installation root, or following an
    untrusted symbolic link. Plans also raise this when presented for execution
    against a different wheel source or destination configuration than the one
    they were built for.
    """


class PathTraversalError(InstallationPlanError, ValueError):
    """When a planned file would be written outside its scheme root.

    This covers archive members, generated entry-point scripts and generated
    metadata whose (possibly ``..``-containing) path escapes the target scheme
    directory after normalisation.

    Inherits :class:`ValueError` for compatibility with earlier releases,
    which raised ``ValueError`` for traversal attempts.
    """


class DestinationCollisionError(InstallationPlanError):
    """When two planned outputs would land on the same file.

    The colliding outputs may be any combination of archive members (including
    ``.data`` relocations), generated entry-point scripts, additional
    dist-info metadata and the final ``RECORD`` file.
    """


class CaseAliasCollisionError(InstallationPlanError):
    """When two planned outputs only differ by case on a case-insensitive target."""


class FileDirectoryConflictError(InstallationPlanError):
    """When a planned file's path is also needed as a directory (or vice versa)."""


class ExistingLinkError(InstallationPlanError):
    """When a planned target already exists as a symbolic link.

    Symbolic links inside the trusted installation root are never followed or
    overwritten, because they can redirect writes to arbitrary locations.
    """


class ExistingFileError(InstallationPlanError):
    """When a planned target already exists as a non-link file and overwriting is not enabled."""


class StalePlanError(InstallationPlanError):
    """When a plan is executed against a different source or destination."""
