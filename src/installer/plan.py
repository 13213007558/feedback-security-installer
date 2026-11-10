"""Installation planning: decide every output path before writing anything.

Planning turns a wheel source plus a destination configuration into an ordered
list of concrete filesystem targets. All conflict, traversal and symbolic-link
checking happens in this phase, so an invalid plan fails before the first file
is written. A plan is bound to the wheel identity and the destination
configuration it was computed for and refuses to run against anything else.

These checks assume the installation roots (the scheme directories, or the
``destdir`` staging directory) are trusted and not writable by unrelated
processes. They do not attempt to defend against symlinks that appear between
planning and execution.
"""

import posixpath
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

from installer.destinations import ResolvedTarget, SchemeDictionaryDestination
from installer.exceptions import (
    CaseAliasCollisionError,
    DestinationCollisionError,
    ExistingFileError,
    ExistingLinkError,
    FileDirectoryConflictError,
    StalePlanError,
)
from installer.records import RecordEntry
from installer.scripts import get_script_name
from installer.utils import SCHEME_NAMES, Scheme, parse_entrypoints

if TYPE_CHECKING:
    from installer.sources import WheelSource

__all__ = [
    "InstallationPlan",
    "PlannedFile",
    "build_installation_plan",
    "process_WHEEL_file",
    "determine_scheme",
]

SourceKind = Literal["archive", "script", "metadata", "record"]
"""What produced a planned file.

``archive``: a member of the wheel (including ``.data`` relocations).
``script``: a launcher generated from ``entry_points.txt``.
``metadata``: caller-supplied additional dist-info metadata.
``record``: the final ``RECORD`` file.
"""


@dataclass(frozen=True)
class PlannedFile:
    """A single file that installation will write."""

    kind: SourceKind
    """Where the file's bytes come from."""

    source: str
    """Human-readable origin of the file (archive member name, script name, ...)."""

    scheme: Scheme
    """Scheme the file lands in."""

    path: str
    """Scheme-relative logical path (POSIX separators)."""

    target: ResolvedTarget
    """Fully resolved filesystem target."""


@dataclass(frozen=True)
class InstallationPlan:
    """A complete, validated description of what an installation will write.

    Instances must be created through
    :func:`build_installation_plan`, which performs all the safety checks.
    """

    source_identity: tuple[str, str, int]
    """``(distribution, version, id(source))`` of the wheel this plan is for."""

    destination_fingerprint: tuple[object, ...]
    """Fingerprint of the destination configuration this plan is for."""

    root_scheme: Scheme
    """Scheme the archive root and dist-info land in."""

    record_file_path: str
    """Scheme-relative path of the ``RECORD`` file."""

    files: tuple[PlannedFile, ...]
    """All planned files, in the order they will be written (RECORD last)."""

    entry_points: tuple[tuple[str, str, str, str], ...] = field(default=())
    """Parsed ``(name, module, attr, section)`` entry points to generate."""

    @property
    def targets(self) -> tuple[Path, ...]:
        """Absolute write path of every planned file, in plan order."""
        return tuple(planned.target.write_path for planned in self.files)

    def check_matches(
        self, source: "WheelSource", destination: SchemeDictionaryDestination
    ) -> None:
        """Ensure this plan was built for exactly this source and destination.

        :raises StalePlanError: if the wheel identity or the destination path
            configuration differs from the ones captured when planning.
        """
        current_identity = (source.distribution, source.version, id(source))
        if current_identity != self.source_identity:
            raise StalePlanError(
                "Installation plan was built for a different wheel source "
                f"{self.source_identity[:2]!r}, cannot use it for "
                f"{(source.distribution, source.version)!r}."
            )
        current_fingerprint = destination.planning_fingerprint()
        if current_fingerprint != self.destination_fingerprint:
            raise StalePlanError(
                "Installation plan was built for a different destination "
                "configuration (scheme_dict / destdir / platform case rules), "
                "rebuild the plan before installing."
            )


def process_WHEEL_file(source: "WheelSource") -> Scheme:  # noqa: N802
    """Process the WHEEL file, from ``source``.

    Returns the scheme that the archive root should go in.
    """
    from installer.exceptions import InvalidWheelSource
    from installer.utils import parse_metadata_file

    stream = source.read_dist_info("WHEEL")
    metadata = parse_metadata_file(stream)

    # Ensure compatibility with this wheel version.
    if not (metadata["Wheel-Version"] and metadata["Wheel-Version"].startswith("1.")):
        message = "Incompatible Wheel-Version {}, only support version 1.x wheels."
        raise InvalidWheelSource(source, message.format(metadata["Wheel-Version"]))

    # Determine where archive root should go.
    if metadata["Root-Is-Purelib"] == "true":
        return cast("Scheme", "purelib")
    return cast("Scheme", "platlib")


def determine_scheme(
    path: str, source: "WheelSource", root_scheme: Scheme
) -> tuple[Scheme, str]:
    """Determine which scheme to place given path in, from source."""
    from installer.exceptions import InvalidWheelSource

    data_dir = source.data_dir

    # If it's in not `{distribution}-{version}.data`, then it's in root_scheme.
    if posixpath.commonpath([data_dir, path]) != data_dir:
        return root_scheme, path

    # Figure out which scheme this goes to.
    parts: list[str] = []
    scheme_name: str | None = None
    left = path
    while True:
        left, right = posixpath.split(left)
        parts.append(right)
        if left == source.data_dir:
            scheme_name = right
            break

    if scheme_name not in SCHEME_NAMES:
        msg_fmt = "{path} is not contained in a valid .data subdirectory."
        raise InvalidWheelSource(source, msg_fmt.format(path=path))

    return cast("Scheme", scheme_name), posixpath.join(*reversed(parts[:-1]))


def _add_file(
    planned: list[PlannedFile],
    destination: SchemeDictionaryDestination,
    *,
    kind: SourceKind,
    source: str,
    scheme: Scheme,
    path: str,
) -> None:
    target = destination.resolve_target(scheme, path)
    planned.append(
        PlannedFile(
            kind=kind,
            source=source,
            scheme=scheme,
            path=path,
            target=target,
        )
    )


def _existing_case_alias(target: ResolvedTarget) -> Path | None:
    """Find an existing entry that only differs from the target by case.

    An entry with the exact same name is reported separately by the caller and
    is therefore not considered an alias here.
    """
    if target.case_sensitive:
        return None

    parent = target.write_path.parent
    try:
        entries = list(parent.iterdir())
    except (FileNotFoundError, NotADirectoryError):
        return None

    wanted_lower = target.write_path.name.lower()
    for entry in entries:
        if entry.name.lower() == wanted_lower and entry.name != target.write_path.name:
            return entry
    return None


def _check_existing_state(
    planned_files: list[PlannedFile],
    destination: SchemeDictionaryDestination,
) -> None:
    """Check every unique target against the current filesystem state.

    Symbolic links *inside* a trusted install root are always rejected (never
    followed or overwritten). Pre-existing regular files are only acceptable
    when ``overwrite_existing`` is enabled.
    """
    seen: set[Path] = set()
    for planned_file in planned_files:
        target = planned_file.target
        if target.write_path in seen:
            continue
        seen.add(target.write_path)

        root = target.install_root
        # Walk the lexical components that live inside the trusted root. Links
        # above the root are part of the trusted root itself and not ours to
        # police; links below it would redirect the write and are rejected.
        current = root
        for part in target.relative_path.parts:
            current = current / part
            if current.is_symlink():
                raise ExistingLinkError(
                    f"Refusing to write through symbolic link {current} "
                    f"(planned by {planned_file.source}); symbolic links inside "
                    "the installation root are never followed."
                )

        if target.write_path.is_symlink():
            raise ExistingLinkError(
                f"Refusing to overwrite symbolic link {target.write_path} "
                f"(planned by {planned_file.source})."
            )

        alias = _existing_case_alias(target)
        if alias is not None:
            if alias.is_symlink():
                raise ExistingLinkError(
                    f"Refusing to write {target.write_path}: case-insensitive "
                    f"alias {alias} is a symbolic link."
                )
            raise CaseAliasCollisionError(
                f"{target.write_path} collides on a case-insensitive target "
                f"with existing path {alias} (planned by {planned_file.source})."
            )

        if target.write_path.is_dir():
            raise FileDirectoryConflictError(
                f"{target.write_path} already exists as a directory but "
                f"{planned_file.source} would write a file there."
            )

        if target.write_path.exists() and not destination.overwrite_existing:
            raise ExistingFileError(
                f"File already exists: {target.write_path} "
                f"(planned by {planned_file.source})."
            )


def _check_internal_conflicts(planned_files: list[PlannedFile]) -> None:
    """Check the planned outputs against each other."""
    exact: dict[Path, PlannedFile] = {}
    case_keys: dict[tuple[str, ...], PlannedFile] = {}
    # Every path that another planned file needs to exist as a directory.
    directory_uses: dict[Path, PlannedFile] = {}

    for planned_file in planned_files:
        target = planned_file.target
        lexical = target.lexical_path

        previous = exact.get(lexical)
        if previous is not None:
            raise DestinationCollisionError(
                f"{planned_file.source!r} and {previous.source!r} both install "
                f"to {target.write_path}."
            )
        exact[lexical] = planned_file

        key = target.case_key()
        previous_case = case_keys.get(key)
        if previous_case is not None:
            raise CaseAliasCollisionError(
                f"{planned_file.source!r} and {previous_case.source!r} install "
                f"to case-insensitive aliases ({target.write_path} vs "
                f"{previous_case.target.write_path})."
            )
        case_keys[key] = planned_file

        parent = lexical.parent
        while parent != target.install_root and target.install_root in parent.parents:
            directory_uses.setdefault(parent, planned_file)
            parent = parent.parent

    for planned_file in planned_files:
        target = planned_file.target
        directory_owner = directory_uses.get(target.lexical_path)
        if directory_owner is not None:
            raise FileDirectoryConflictError(
                f"{planned_file.source!r} would write a file at "
                f"{target.write_path} but {directory_owner.source!r} requires "
                "that path to be a directory."
            )


def build_installation_plan(
    source: "WheelSource",
    destination: SchemeDictionaryDestination,
    additional_metadata: dict[str, bytes],
) -> InstallationPlan:
    """Compute and validate every filesystem target of an installation.

    The plan covers archive members (including ``.data`` relocations), the
    launchers generated from ``entry_points.txt``, additional dist-info
    metadata and the final ``RECORD`` file.

    :param source: wheel to install.
    :param destination: where the wheel would be written.
    :param additional_metadata: additional metadata files the caller generates.
    :raises InstallationPlanError: if the wheel cannot be installed without
        overwriting, escaping the trusted roots or following a symbolic link.
    :return: a bound, validated :class:`InstallationPlan`.
    """
    root_scheme = process_WHEEL_file(source)
    record_file_path = posixpath.join(source.dist_info_dir, "RECORD")
    planned_files: list[PlannedFile] = []

    # The launchers generated from entry_points.txt.
    entry_points: list[tuple[str, str, str, str]] = []
    if "entry_points.txt" in source.dist_info_filenames:
        entrypoints_text = source.read_dist_info("entry_points.txt")
        for name, module, attr, section in parse_entrypoints(entrypoints_text):
            entry_points.append((name, module, attr, section))
            script_name = get_script_name(name, destination.script_kind)
            _add_file(
                planned_files,
                destination,
                kind="script",
                source=f"entry point {name!r}",
                scheme=Scheme("scripts"),
                path=script_name,
            )

    # Everything carried by the archive itself.
    for record_elements, _stream, _is_executable in source.get_contents():
        source_record = RecordEntry.from_elements(*record_elements)
        path = source_record.path
        # RECORD is regenerated at the end and planned separately.
        if path == record_file_path:
            continue

        if "__pycache__" in path.split("/")[:-1]:
            warnings.warn(
                (
                    f"Skip installing {path} from {source.distribution}."
                    " Installing files in a __pycache__ directory poses a"
                    " security risk. __pycache__ directories should not be"
                    " included in wheels."
                    f" This is probably an issue in the build process of"
                    f" '{source.distribution}'."
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        scheme, destination_path = determine_scheme(
            path=path,
            source=source,
            root_scheme=root_scheme,
        )
        _add_file(
            planned_files,
            destination,
            kind="archive",
            source=f"archive member {path!r}",
            scheme=scheme,
            path=destination_path,
        )

    # Installation-specific metadata the caller asked to generate.
    for filename in additional_metadata:
        path = posixpath.join(source.dist_info_dir, filename)
        _add_file(
            planned_files,
            destination,
            kind="metadata",
            source=f"additional metadata {filename!r}",
            scheme=root_scheme,
            path=path,
        )

    # The final RECORD itself.
    _add_file(
        planned_files,
        destination,
        kind="record",
        source="generated RECORD",
        scheme=root_scheme,
        path=record_file_path,
    )

    _check_internal_conflicts(planned_files)
    _check_existing_state(planned_files, destination)

    return InstallationPlan(
        source_identity=(source.distribution, source.version, id(source)),
        destination_fingerprint=destination.planning_fingerprint(),
        root_scheme=root_scheme,
        record_file_path=record_file_path,
        files=tuple(planned_files),
        entry_points=tuple(entry_points),
    )
