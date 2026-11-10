"""Core wheel installation logic."""

import warnings
from io import BytesIO
from typing import TYPE_CHECKING, cast

from installer import plan as _plan
from installer.destinations import SchemeDictionaryDestination, WheelDestination
from installer.plan import InstallationPlan, determine_scheme, process_WHEEL_file
from installer.records import RecordEntry
from installer.sources import WheelSource
from installer.utils import Scheme, parse_entrypoints

# Re-exported as part of the public API (see installer/__init__.py).
build_installation_plan = _plan.build_installation_plan

if TYPE_CHECKING:
    from installer.scripts import ScriptSection

__all__ = ["build_installation_plan", "install"]


def _install_without_plan(
    source: WheelSource,
    destination: WheelDestination,
    additional_metadata: dict[str, bytes],
) -> None:
    """Legacy execution path for destinations without planning support."""
    root_scheme = process_WHEEL_file(source)

    # RECORD handling
    record_file_path = source.dist_info_dir + "/RECORD"
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

        # Figure out where to write this file.
        scheme, destination_path = determine_scheme(
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
        path = source.dist_info_dir + "/" + filename

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


def _install_with_plan(
    source: WheelSource,
    destination: SchemeDictionaryDestination,
    additional_metadata: dict[str, bytes],
    plan: InstallationPlan,
) -> None:
    """Execute a previously built and validated plan."""
    plan.check_matches(source, destination)

    written_records: list[tuple[Scheme, RecordEntry]] = []
    planned_archive = {
        (planned.scheme, planned.path): planned
        for planned in plan.files
        if planned.kind == "archive"
    }
    planned_metadata = {
        planned.path: planned for planned in plan.files if planned.kind == "metadata"
    }

    # Write the entry_points based scripts.
    for name, module, attr, section in plan.entry_points:
        record = destination.write_script(
            name=name,
            module=module,
            attr=attr,
            section=cast("ScriptSection", section),
        )
        written_records.append((Scheme("scripts"), record))

    # Write all the files from the wheel.
    for record_elements, stream, is_executable in source.get_contents():
        source_record = RecordEntry.from_elements(*record_elements)
        path = source_record.path
        # Skip the RECORD, which is written at the end, based on this info.
        if path == plan.record_file_path:
            continue

        if "__pycache__" in path.split("/")[:-1]:
            # The warning was already emitted while building the plan.
            continue

        scheme, destination_path = determine_scheme(
            path=path,
            source=source,
            root_scheme=plan.root_scheme,
        )
        planned_file = planned_archive.pop((scheme, destination_path))
        record = destination.write_file(
            scheme=scheme,
            path=planned_file.path,
            stream=stream,
            is_executable=is_executable,
        )
        written_records.append((scheme, record))

    if planned_archive:
        unplanned = ", ".join(
            f"{planned.scheme}:{planned.path}" for planned in planned_archive.values()
        )
        message = f"Wheel contents changed after planning; unplanned files: {unplanned}"
        raise AssertionError(message)

    # Write all the installation-specific metadata.
    for filename, contents in additional_metadata.items():
        path = source.dist_info_dir + "/" + filename
        planned_file = planned_metadata.pop(path)
        with BytesIO(contents) as other_stream:
            record = destination.write_file(
                scheme=plan.root_scheme,
                path=planned_file.path,
                stream=other_stream,
                is_executable=False,
            )
        written_records.append((plan.root_scheme, record))

    if planned_metadata:
        unplanned = ", ".join(planned_metadata)
        message = f"Additional metadata changed after planning: {unplanned}"
        raise AssertionError(message)

    written_records.append(
        (plan.root_scheme, RecordEntry(plan.record_file_path, None, None))
    )
    destination.finalize_installation(
        scheme=plan.root_scheme,
        record_file_path=plan.record_file_path,
        records=written_records,
    )


def install(
    source: WheelSource,
    destination: WheelDestination,
    additional_metadata: dict[str, bytes],
    *,
    plan: InstallationPlan | None = None,
) -> InstallationPlan | None:
    """Install wheel described by ``source`` into ``destination``.

    :param source: wheel to install.
    :param destination: where to write the wheel.
    :param additional_metadata: additional metadata files to generate, usually
                                generated by the caller.
    :param plan: a pre-built :class:`~installer.plan.InstallationPlan`, e.g. one
                 produced earlier to preview the final file layout. When given,
                 it must match ``source`` and ``destination`` exactly. When
                 omitted and the destination supports planning, a plan is built
                 (and validated) immediately before writing.
    :return: the validated plan used for the installation, or ``None`` when the
             destination does not support installation planning.

    Planning-capable destinations fail before writing the first file whenever
    two outputs collide, a path escapes the trusted installation root, or a
    target is reachable through a symbolic link.
    """
    if isinstance(destination, SchemeDictionaryDestination):
        if plan is None:
            plan = build_installation_plan(source, destination, additional_metadata)
        _install_with_plan(source, destination, additional_metadata, plan)
        return plan

    if plan is not None:
        message = (
            "An installation plan was provided but the destination "
            f"{type(destination).__name__!r} does not support planning."
        )
        raise TypeError(message)
    _install_without_plan(source, destination, additional_metadata)
    return None
