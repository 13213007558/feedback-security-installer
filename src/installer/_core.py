"""Core wheel installation logic."""

import posixpath
import warnings
from io import BytesIO
from typing import cast

from installer.destinations import WheelDestination
from installer.exceptions import InvalidWheelSource
from installer.policies import (
    PTH_IMPORT,
    PTH_PATH,
    EntryCategory,
    LaunchEntry,
    LaunchEntryPolicy,
    classify_pth_line,
    is_pth_launch_file,
)
from installer.records import RecordEntry
from installer.sources import WheelSource
from installer.utils import SCHEME_NAMES, Scheme, parse_entrypoints, parse_metadata_file

__all__ = ["install"]

# Schemes that correspond to site directories scanned by the ``site`` module.
_SITE_SCHEMES = (Scheme("purelib"), Scheme("platlib"))


def _process_WHEEL_file(source: WheelSource) -> Scheme:  # noqa: N802
    """Process the WHEEL file, from ``source``.

    Returns the scheme that the archive root should go in.
    """
    stream = source.read_dist_info("WHEEL")
    metadata = parse_metadata_file(stream)

    # Ensure compatibility with this wheel version.
    if not (metadata["Wheel-Version"] and metadata["Wheel-Version"].startswith("1.")):
        message = "Incompatible Wheel-Version {}, only support version 1.x wheels."
        raise InvalidWheelSource(source, message.format(metadata["Wheel-Version"]))

    # Determine where archive root should go.
    if metadata["Root-Is-Purelib"] == "true":
        return cast("Scheme", "purelib")
    else:
        return cast("Scheme", "platlib")


def _determine_scheme(
    path: str, source: WheelSource, root_scheme: Scheme
) -> tuple[Scheme, str]:
    """Determine which scheme to place given path in, from source."""
    data_dir = source.data_dir

    # If it's in not `{distribution}-{version}.data`, then it's in root_scheme.
    if posixpath.commonpath([data_dir, path]) != data_dir:
        return root_scheme, path

    # Figure out which scheme this goes to.
    parts = []
    scheme_name = None
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


def _archive_label(source: WheelSource) -> str:
    """Stable identifier of the archive, for policy violation reports."""
    zipfile = getattr(source, "_zipfile", None)
    filename = getattr(zipfile, "filename", None)
    if isinstance(filename, str):
        return posixpath.basename(filename)
    return f"{source.distribution}-{source.version}"


def _normalize_destination_path(path: str) -> str:
    """Normalize a POSIX destination path for classification.

    This collapses redundant separators and ``..`` segments so that a wheel
    cannot make an entry appear outside of the site directory (or hide its
    ``.pth`` suffix) through path tricks.
    """
    return posixpath.normpath(path)


def _pth_entries(
    *,
    archive_label: str,
    scheme: Scheme,
    source_path: str,
    destination_path: str,
    content: bytes,
) -> list[LaunchEntry]:
    """Classify the launch entries inside one ``.pth`` file."""
    text = content.decode("utf-8-sig", errors="replace")

    line_numbers: dict[str, list[int]] = {PTH_IMPORT: [], PTH_PATH: []}
    for line_number, line in enumerate(text.splitlines(), start=1):
        kind = classify_pth_line(line)
        if kind in line_numbers:
            line_numbers[kind].append(line_number)

    entries = []
    name = posixpath.basename(destination_path)
    for kind, category in (
        (PTH_IMPORT, EntryCategory.PTH_IMPORT),
        (PTH_PATH, EntryCategory.PTH_PATH),
    ):
        if line_numbers[kind]:
            entries.append(
                LaunchEntry(
                    category=category,
                    archive=archive_label,
                    source_path=source_path,
                    scheme=scheme,
                    destination_path=destination_path,
                    name=name,
                    line_numbers=tuple(line_numbers[kind]),
                )
            )
    return entries


def _collect_launch_entries(
    source: WheelSource,
    root_scheme: Scheme,
    additional_metadata: dict[str, bytes],
) -> list[LaunchEntry]:
    """Enumerate every launch entry, using final post-relocation destinations.

    No file is written while this runs; wheel contents are only read for
    classification. Every code-execution or ``sys.path`` entry described by
    the wheel -- including those hidden behind ``.data`` relocation,
    additional metadata or case/path tricks -- is represented here so that
    the policy can reject them before installation starts.
    """
    archive_label = _archive_label(source)
    entries: list[LaunchEntry] = []

    # Launchers generated from entry_points.txt.
    if "entry_points.txt" in source.dist_info_filenames:
        entrypoints_text = source.read_dist_info("entry_points.txt")
        for name, module, attr, _section in parse_entrypoints(entrypoints_text):
            entries.append(
                LaunchEntry(
                    category=EntryCategory.ENTRY_POINT,
                    archive=archive_label,
                    source_path=posixpath.join(
                        source.dist_info_dir, "entry_points.txt"
                    ),
                    scheme=Scheme("scripts"),
                    destination_path=name,
                    name=name,
                    module=f"{module}:{attr}",
                )
            )

    # Files shipped inside the wheel archive.
    for record_elements, stream, _is_executable in source.get_contents():
        source_record = RecordEntry.from_elements(*record_elements)
        source_path = source_record.path
        if source_path == posixpath.join(source.dist_info_dir, "RECORD"):
            continue
        if "__pycache__" in source_path.split("/")[:-1]:
            continue

        scheme, raw_destination_path = _determine_scheme(
            path=source_path,
            source=source,
            root_scheme=root_scheme,
        )
        destination_path = _normalize_destination_path(raw_destination_path)

        if scheme == Scheme("scripts"):
            entries.append(
                LaunchEntry(
                    category=EntryCategory.SCRIPT,
                    archive=archive_label,
                    source_path=source_path,
                    scheme=scheme,
                    destination_path=destination_path,
                    name=posixpath.basename(destination_path),
                )
            )
        elif scheme in _SITE_SCHEMES and is_pth_launch_file(destination_path):
            entries.extend(
                _pth_entries(
                    archive_label=archive_label,
                    scheme=scheme,
                    source_path=source_path,
                    destination_path=destination_path,
                    content=stream.read(),
                )
            )

    # Additional metadata written by the caller is subject to the same rules,
    # so an entry cannot bypass the policy by being generated at install time.
    for filename, content in additional_metadata.items():
        source_path = posixpath.join(source.dist_info_dir, filename)
        destination_path = _normalize_destination_path(filename)
        if root_scheme in _SITE_SCHEMES and is_pth_launch_file(destination_path):
            entries.extend(
                _pth_entries(
                    archive_label=archive_label,
                    scheme=root_scheme,
                    source_path=source_path,
                    destination_path=destination_path,
                    content=content,
                )
            )

    return entries


def install(
    source: WheelSource,
    destination: WheelDestination,
    additional_metadata: dict[str, bytes],
    *,
    launch_entry_policy: LaunchEntryPolicy | None = None,
) -> None:
    """Install wheel described by ``source`` into ``destination``.

    :param source: wheel to install.
    :param destination: where to write the wheel.
    :param additional_metadata: additional metadata files to generate, usually
                                generated by the caller.
    :param launch_entry_policy: optional policy reviewed against every launch
                                entry (``.pth`` files, bundled scripts and
                                entry-point launchers) before any file is
                                written. When :data:`None`, installation keeps
                                its historical, policy-free behaviour.

    """
    root_scheme = _process_WHEEL_file(source)

    # Review all launch entries first; a denial must never leave files behind.
    if launch_entry_policy is not None:
        entries = _collect_launch_entries(source, root_scheme, additional_metadata)
        launch_entry_policy.evaluate(entries)

    # RECORD handling
    record_file_path = posixpath.join(source.dist_info_dir, "RECORD")
    written_records = []

    # Write the entry_points based scripts.
    if "entry_points.txt" in source.dist_info_filenames:
        entrypoints_text = source.read_dist_info("entry_points.txt")
        for name, module, attr, section in parse_entrypoints(entrypoints_text):
            record = destination.write_script(
                name=name,
                module=module,
                attr=attr,
                section=section,
            )
            written_records.append((Scheme("scripts"), record))

    # Write all the files from the wheel.
    for record_elements, stream, is_executable in source.get_contents():
        source_record = RecordEntry.from_elements(*record_elements)
        path = source_record.path
        # Skip the RECORD, which is written at the end, based on this info.
        if path == record_file_path:
            continue

        if "__pycache__" in path.split("/")[:-1]:
            warnings.warn(
                (
                    f"Skip installing {path} from {source.distribution}."
                    " Installing files in a __pycache__ directory poses a security risk."
                    " __pycache__ directories should not be included in wheels."
                    f" This is probably an issue in the build process of '{source.distribution}'."
                ),
                RuntimeWarning,
                stacklevel=2,
            )
            continue

        # Figure out where to write this file.
        scheme, destination_path = _determine_scheme(
            path=path,
            source=source,
            root_scheme=root_scheme,
        )
        record = destination.write_file(
            scheme=scheme,
            path=destination_path,
            stream=stream,
            is_executable=is_executable,
        )
        written_records.append((scheme, record))

    # Write all the installation-specific metadata
    for filename, contents in additional_metadata.items():
        path = posixpath.join(source.dist_info_dir, filename)

        with BytesIO(contents) as other_stream:
            record = destination.write_file(
                scheme=root_scheme,
                path=path,
                stream=other_stream,
                is_executable=False,
            )
        written_records.append((root_scheme, record))

    written_records.append((root_scheme, RecordEntry(record_file_path, None, None)))
    destination.finalize_installation(
        scheme=root_scheme,
        record_file_path=record_file_path,
        records=written_records,
    )
