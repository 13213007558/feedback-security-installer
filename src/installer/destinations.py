"""Handles all file writing and post-installation processing."""

import io
import os
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    BinaryIO,
    ClassVar,
    Union,
)

from installer.records import Hash, RecordEntry
from installer.scripts import Script
from installer.utils import (
    _WINDOWS,
    Scheme,
    construct_record_file,
    copyfileobj_with_hashing,
    fix_shebang,
    make_file_executable,
)

if TYPE_CHECKING:
    from installer.scripts import LauncherKind, ScriptSection


@dataclass(frozen=True)
class ResolvedTarget:
    """The fully resolved location of a single file to be installed.

    The object describes where bytes will be written *and* how that location
    relates to the trusted installation root, without performing any write or
    following any symbolic link.

    :param scheme: scheme the file belongs to.
    :param path: scheme-relative logical path, using POSIX separators.
    :param write_path: absolute path the bytes are actually written to, with
        ``destdir`` staging applied but without resolving symbolic links.
    :param install_root: canonical (``realpath``) trusted root that contains
        the file. With ``destdir`` this is the staging directory, otherwise the
        scheme directory.
    :param relative_path: lexical path of the file within ``install_root``.
        Symbolic links inside the root are deliberately *not* resolved here.
    :param case_sensitive: whether two names differing only in case denote
        distinct files at this target.
    """

    scheme: Scheme
    path: str
    write_path: Path
    install_root: Path
    relative_path: Path
    case_sensitive: bool

    @property
    def lexical_path(self) -> Path:
        """Absolute path with only the trusted root itself canonicalised."""
        return self.install_root / self.relative_path

    def case_key(self) -> tuple[str, ...]:
        """Key that collapses names that are aliases on this target."""
        parts = (str(self.install_root), *self.relative_path.parts)
        if self.case_sensitive:
            return tuple(parts)
        return tuple(part.lower() for part in parts)


class WheelDestination:
    """Handles writing the unpacked files, script generation and ``RECORD`` generation.

    Subclasses provide the concrete script generation logic, as well as the RECORD file
    (re)writing.
    """

    supports_installation_planning: ClassVar[bool] = False
    """Whether this destination can resolve and validate targets before writing."""

    def resolve_target(self, scheme: Scheme, path: str) -> ResolvedTarget:
        """Resolve a scheme-relative path to a concrete, write-independent target.

        :param scheme: scheme the file belongs to (like "purelib", "scripts").
        :param path: path within that scheme.
        :raises installer.exceptions.PathTraversalError: if ``path`` escapes
            the scheme's target directory after normalisation.
        """
        raise NotImplementedError

    def is_case_sensitive(self) -> bool:
        """Whether two paths differing only in case are distinct files here."""
        raise NotImplementedError

    def planning_fingerprint(self) -> tuple[object, ...]:
        """Return a stable fingerprint of the destination's path configuration.

        A plan is only valid for a destination whose fingerprint matches the
        one it was built with.
        """
        raise NotImplementedError

    def write_script(
        self, name: str, module: str, attr: str, section: "ScriptSection"
    ) -> RecordEntry:
        """Write a script in the correct location to invoke given entry point.

        :param name: name of the script
        :param module: module path, to load the entry point from
        :param attr: final attribute access, for the entry point
        :param section: Denotes the "entry point section" where this was specified.
            Valid values are ``"gui"`` and ``"console"``.
        :type section: str

        Example usage/behaviour::

            >>> dest.write_script("pip", "pip._internal.cli", "main", "console")

        """
        raise NotImplementedError

    def write_file(
        self,
        scheme: Scheme,
        path: Union[str, "os.PathLike[str]"],
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write a file to correct ``path`` within the ``scheme``.

        :param scheme: scheme to write the file in (like "purelib", "platlib" etc).
        :param path: path within that scheme
        :param stream: contents of the file
        :param is_executable: whether the file should be made executable

        The stream would be closed by the caller, after this call.

        Example usage/behaviour::

            >>> with open("__init__.py") as stream:
            ...     dest.write_file("purelib", "pkg/__init__.py", stream)

        """
        raise NotImplementedError

    def finalize_installation(
        self,
        scheme: Scheme,
        record_file_path: str,
        records: Iterable[tuple[Scheme, RecordEntry]],
    ) -> None:
        """Finalize installation, after all the files are written.

        Handles (re)writing of the ``RECORD`` file.

        :param scheme: scheme to write the ``RECORD`` file in
        :param record_file_path: path of the ``RECORD`` file with that scheme
        :param records: entries to write to the ``RECORD`` file

        Example usage/behaviour::

            >>> dest.finalize_installation("purelib")

        """
        raise NotImplementedError


@dataclass
class SchemeDictionaryDestination(WheelDestination):
    """Destination, based on a mapping of {scheme: file-system-path}."""

    supports_installation_planning: ClassVar[bool] = True

    scheme_dict: dict[str, str]
    """A mapping of {scheme: file-system-path}"""

    interpreter: str
    """The interpreter to use for generating scripts."""

    script_kind: "LauncherKind"
    """The "kind" of launcher script to use."""

    hash_algorithm: str = "sha256"
    """
    The hashing algorithm to use, which is a member of
    :any:`hashlib.algorithms_available` (ideally from
    :any:`hashlib.algorithms_guaranteed`).
    """

    bytecode_optimization_levels: Collection[int] = ()
    """
    Compile cached bytecode for installed .py files with these optimization
    levels. The bytecode is specific to the minor version of Python (e.g. 3.10)
    used to generate it.
    """

    destdir: str | None = None
    """
    A staging directory in which to write all files. This is expected to be the
    filesystem root at runtime, so embedded paths will be written as though
    this was the root.
    """

    overwrite_existing: bool = False
    """Silently overwrite existing files."""

    def is_case_sensitive(self) -> bool:
        """Whether target file names are case-sensitive.

        Case rules follow the target platform implied by ``script_kind``:
        Windows targets are case-insensitive (with case-preserving file
        systems), while POSIX targets are case-sensitive.
        """
        return self.script_kind == "posix"

    def planning_fingerprint(self) -> tuple[object, ...]:
        """Fingerprint of the scheme directories and staging configuration."""
        return (
            tuple(
                sorted(
                    (
                        scheme,
                        os.path.abspath(path),  # noqa: PTH100
                        os.path.realpath(path),  # noqa: PTH100
                    )
                    for scheme, path in self.scheme_dict.items()
                )
            ),
            None
            if self.destdir is None
            else (
                os.path.abspath(self.destdir),  # noqa: PTH100
                os.path.realpath(self.destdir),  # noqa: PTH100
            ),
            self.is_case_sensitive(),
        )

    def _install_root(self, scheme: Scheme) -> Path:
        if self.destdir is not None:
            # All staged writes share the destdir as their trusted root.
            return Path(os.path.realpath(self.destdir))  # noqa: PTH100
        return Path(os.path.realpath(self.scheme_dict[scheme]))  # noqa: PTH100

    def resolve_target(self, scheme: Scheme, path: str) -> ResolvedTarget:
        """Resolve ``path`` within ``scheme``, applying destdir and case rules.

        The scheme directory itself (and the ``destdir`` staging root, if any)
        is canonicalised with ``realpath``; components inside that trusted root
        are kept lexical, so symbolic links there remain visible to the
        planning checks instead of being silently followed.
        """
        # See https://docs.python.org/3/library/zipfile.html#zipfile.Path:
        #  When handling untrusted archives,
        #  consider resolving filenames using os.path.abspath()
        #  and checking against the target directory with os.path.commonpath().
        #
        # Attention: Path.absolute() is not sufficient because it does not
        #  normalize, i.e. does not remove "..".
        #
        # We want to avoid Path.resolve() because it is significantly slower
        # than os.path.abspath()!
        lexical_scheme_root = Path(
            os.path.abspath(self.scheme_dict[scheme])  # noqa: PTH100
        )
        file = Path(os.path.abspath(lexical_scheme_root / path))  # noqa: PTH100

        if not file.is_relative_to(lexical_scheme_root):
            from installer.exceptions import PathTraversalError

            raise PathTraversalError(
                f"Attempting to write {path} outside of the target directory"
            )

        if self.destdir is not None:
            # Drop the mount anchor ("/" on POSIX, "C:\\" on Windows) so the
            # staged path is relative to the destdir root and symlink checks
            # walk the components actually created inside it.
            rel_path = Path(*file.relative_to(file.anchor).parts)
            write_path = Path(self.destdir) / rel_path
        else:
            write_path = file

        install_root = self._install_root(scheme)
        # Relative to the lexical root when it differs from the canonical one
        # (e.g. the trusted scheme directory is itself reached via a symlink);
        # symlinks *below* the root are still lexical and get checked.
        lexical_root = (
            Path(os.path.abspath(self.destdir))  # noqa: PTH100
            if self.destdir is not None
            else lexical_scheme_root
        )
        relative_path = write_path.relative_to(lexical_root)

        return ResolvedTarget(
            scheme=scheme,
            path=path,
            write_path=write_path,
            install_root=install_root,
            relative_path=relative_path,
            case_sensitive=self.is_case_sensitive(),
        )

    def _path_with_destdir(self, scheme: Scheme, path: str) -> Path:
        return self.resolve_target(scheme, path).write_path

    def write_to_fs(
        self,
        scheme: Scheme,
        path: str,
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write contents of ``stream`` to the correct location on the filesystem.

        :param scheme: scheme to write the file in (like "purelib", "platlib" etc).
        :param path: path within that scheme
        :param stream: contents of the file
        :param is_executable: whether the file should be made executable

        - Ensures that an existing file is not being overwritten.
        - Hashes the written content, to determine the entry in the ``RECORD`` file.
        """
        target_path = self._path_with_destdir(scheme, path)
        if not self.overwrite_existing and target_path.exists():
            message = f"File already exists: {target_path!s}"
            raise FileExistsError(message)

        parent_folder = target_path.parent
        if not parent_folder.exists():
            parent_folder.mkdir(parents=True)

        with target_path.open("wb") as f:
            hash_, size = copyfileobj_with_hashing(stream, f, self.hash_algorithm)

        if is_executable:
            make_file_executable(target_path)

        return RecordEntry(path, Hash(self.hash_algorithm, hash_), size)

    def write_file(
        self,
        scheme: Scheme,
        path: Union[str, "os.PathLike[str]"],
        stream: BinaryIO,
        is_executable: bool,
    ) -> RecordEntry:
        """Write a file to correct ``path`` within the ``scheme``.

        :param scheme: scheme to write the file in (like "purelib", "platlib" etc).
        :param path: path within that scheme
        :param stream: contents of the file
        :param is_executable: whether the file should be made executable

        - Changes the shebang for files in the "scripts" scheme.
        - Uses :py:meth:`SchemeDictionaryDestination.write_to_fs` for the
          filesystem interaction.
        """
        path_ = os.fspath(path)

        if scheme == "scripts":
            with fix_shebang(stream, self.interpreter) as stream_with_different_shebang:
                return self.write_to_fs(
                    scheme, path_, stream_with_different_shebang, is_executable
                )

        return self.write_to_fs(scheme, path_, stream, is_executable)

    def write_script(
        self, name: str, module: str, attr: str, section: "ScriptSection"
    ) -> RecordEntry:
        """Write a script to invoke an entrypoint.

        :param name: name of the script
        :param module: module path, to load the entry point from
        :param attr: final attribute access, for the entry point
        :param section: Denotes the "entry point section" where this was specified.
            Valid values are ``"gui"`` and ``"console"``.
        :type section: str

        - Generates a launcher using :any:`Script.generate`.
        - Writes to the "scripts" scheme.
        - Uses :py:meth:`SchemeDictionaryDestination.write_to_fs` for the
          filesystem interaction.
        """
        script = Script(name, module, attr, section)
        script_name, data = script.generate(self.interpreter, self.script_kind)

        with io.BytesIO(data) as stream:
            entry = self.write_to_fs(
                Scheme("scripts"), script_name, stream, is_executable=True
            )

            path = self._path_with_destdir(Scheme("scripts"), script_name)
            mode = path.stat().st_mode
            mode |= (mode & 0o444) >> 2
            path.chmod(mode)

            return entry

    def _compile_bytecode(self, scheme: Scheme, record: RecordEntry) -> None:
        """Compile bytecode for a single .py file."""
        if not self.bytecode_optimization_levels or scheme not in (
            "purelib",
            "platlib",
        ):
            return

        import compileall

        target_path = self._path_with_destdir(scheme, record.path)
        dir_path_to_embed = (Path(self.scheme_dict[scheme]) / record.path).parent

        for level in self.bytecode_optimization_levels:
            compileall.compile_file(
                target_path, optimize=level, quiet=1, ddir=dir_path_to_embed
            )

    def finalize_installation(
        self,
        scheme: Scheme,
        record_file_path: str,
        records: Iterable[tuple[Scheme, RecordEntry]],
    ) -> None:
        """Finalize installation, by writing the ``RECORD`` file & compiling bytecode.

        :param scheme: scheme to write the ``RECORD`` file in
        :param record_file_path: path of the ``RECORD`` file with that scheme
        :param records: entries to write to the ``RECORD`` file
        """

        def prefix_for_scheme(file_scheme: str) -> str | None:
            if file_scheme == scheme:
                return None
            if _WINDOWS:  # pragma: no cover
                path = os.path.abspath(self.scheme_dict[file_scheme])  # noqa: PTH100
            else:  # pragma: no cover
                path = os.path.relpath(
                    self.scheme_dict[file_scheme],
                    start=self.scheme_dict[scheme],
                )
            return path + "/"

        record_list = list(records)
        with construct_record_file(record_list, prefix_for_scheme) as record_stream:
            self.write_to_fs(
                scheme, record_file_path, record_stream, is_executable=False
            )

        for scheme_, record in record_list:
            self._compile_bytecode(scheme_, record)
