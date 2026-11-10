"""A wheel source that only exposes contents which have been verified.

This module provides :class:`VerifiedWheelSource`, a wrapper around any
:class:`~installer.sources.WheelSource` that performs a strict validation of
the wheel's ``RECORD`` against the actual archive contents, and then binds the
installation streams to those validated bytes.

The validation performed here covers:

- the one-to-one relationship between ``RECORD`` entries and archive members
  (rejecting duplicate members, duplicate ``RECORD`` paths and missing
  members),
- the declared size and digest of every regular member,
- the prohibition on empty hashes for regular members.

The wheel specification's exceptions for the ``RECORD`` file itself and for
the ``RECORD.jws`` / ``RECORD.p7s`` signature files are preserved, and are not
extended to regular modules.

Every stream handed out by :meth:`VerifiedWheelSource.get_contents` re-checks
the bytes as they are read. A member that is changed between validation and
installation -- or a member whose consumer stops reading before the verified
end of the stream -- can therefore never be treated as trusted.
"""

import base64
import hashlib
import io
import posixpath
from collections.abc import Iterator
from typing import TYPE_CHECKING, BinaryIO, NamedTuple

from installer.records import InvalidRecordEntry, RecordEntry, parse_record_file
from installer.sources import WheelSource
from installer.utils import _COPY_BUFSIZE

if TYPE_CHECKING:
    from installer.sources import WheelContentElement

__all__ = ["VerifiedWheelSource", "VerifiedWheelSourceError"]

RecordRow = tuple[str, str, str]


class VerifiedWheelSourceError(ValueError):
    """Raised when a wheel cannot be bound to its verified contents.

    This covers both failures of the initial :class:`VerifiedWheelSource`
    validation (the issues are collected in :attr:`issues`) and failures
    detected while a verified stream is being consumed.
    """

    def __init__(self, issues: list[str] | str) -> None:
        if isinstance(issues, str):
            self.issues = [issues]
            super().__init__(issues)
        else:
            self.issues = issues
            super().__init__(repr(issues))

    def __repr__(self) -> str:
        return f"VerifiedWheelSourceError(issues={self.issues!r})"


class _Member(NamedTuple):
    path: str
    record_row: RecordRow | None
    is_executable: bool
    verified: bool


class _PassthroughStream(io.RawIOBase):
    """A thin wrapper that owns closing of the stream it wraps."""

    def __init__(
        self,
        underlying: BinaryIO,
        owner: Iterator["WheelContentElement"] | None = None,
    ) -> None:
        super().__init__()
        self._underlying = underlying
        # Keep the iterator that produced ``underlying`` alive until this
        # stream is closed; otherwise its cleanup would close the stream
        # underneath us.
        self._owner = owner

    def readable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:
        chunk = self._underlying.read(len(b))
        if not chunk:
            return 0
        b[: len(chunk)] = chunk
        return len(chunk)

    def close(self) -> None:
        super().close()
        if not self._underlying.closed:
            self._underlying.close()
        if self._owner is not None:
            self._owner.close()
            self._owner = None


class _VerifyingStream(io.RawIOBase):
    """A readable stream that verifies its bytes against a ``RECORD`` entry.

    The bytes are read from the wrapped stream in bounded chunks and the
    running digest and size are compared to the record entry once the end of
    the member is reached. Nothing is buffered beyond a single chunk.

    A stream closed before its verified end has been reached raises
    :class:`VerifiedWheelSourceError`, so that partially-read (and thus
    unverified) contents can never be treated as trusted. A stream that was
    never read may be closed without error, which allows consumers to skip a
    member without reading it.
    """

    def __init__(
        self,
        underlying: BinaryIO,
        record: RecordEntry,
        member_path: str,
        owner: Iterator["WheelContentElement"] | None = None,
    ) -> None:
        super().__init__()
        self._underlying = underlying
        self._record = record
        self._member_path = member_path
        # Keep the iterator that produced ``underlying`` alive until this
        # stream is closed; otherwise its cleanup would close the stream
        # underneath us.
        self._owner = owner
        assert record.hash_ is not None
        self._algorithm = record.hash_.name
        self._hasher = hashlib.new(self._algorithm)
        self._size = 0
        self._verified = False
        self._ever_read = False

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def readinto(self, b: bytearray) -> int:
        # Bound each read so that a large member is never copied into memory
        # in one go, regardless of how much the caller asks for.
        chunk = self._underlying.read(min(len(b), _COPY_BUFSIZE))
        if not chunk:
            self._check_at_end()
            return 0
        self._ever_read = True
        b[: len(chunk)] = chunk
        self._hasher.update(chunk)
        self._size += len(chunk)
        return len(chunk)

    def readall(self) -> bytes:
        # Provided explicitly so that the default RawIOBase implementation
        # (which allocates growing buffers) is not used; reads stay bounded.
        chunks: list[bytes] = []
        while True:
            chunk = self.read(_COPY_BUFSIZE)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        # Only rewinding to the start is needed (e.g. for shebang rewriting)
        # and can be verified again from the beginning.
        if whence != io.SEEK_SET or offset != 0:
            raise io.UnsupportedOperation("only seek(0) is supported")
        self._underlying.seek(0)
        self._hasher = hashlib.new(self._algorithm)
        self._size = 0
        self._verified = False
        return 0

    def _check_at_end(self) -> None:
        if self._verified:
            return
        issues: list[str] = []
        if self._record.size is not None and self._size != self._record.size:
            issues.append(
                f"Size of {self._member_path} changed: expected "
                f"{self._record.size}, got {self._size}."
            )
        raw_digest = base64.urlsafe_b64encode(self._hasher.digest()).decode("ascii")
        digest = raw_digest.rstrip("=")
        if digest != self._record.hash_.value:
            issues.append(
                f"Hash of {self._member_path} does not match RECORD "
                f"(expected {self._record.hash_.value}, got {digest}); the "
                "contents changed after the wheel was verified."
            )
        if issues:
            raise VerifiedWheelSourceError(issues)
        self._verified = True

    def close(self) -> None:
        if not self.closed and self._ever_read and not self._verified:
            self._check_at_end()
        super().close()
        if not self._underlying.closed:
            self._underlying.close()
        if self._owner is not None:
            self._owner.close()
            self._owner = None


class VerifiedWheelSource(WheelSource):
    """A :class:`~installer.sources.WheelSource` bound to verified contents.

    Wrapping a source validates every archive member against its ``RECORD``
    entry immediately. The resulting object exposes the same interface as the
    wrapped source, but the streams from :meth:`get_contents` are tied to the
    bytes that were actually validated: each stream re-verifies the digest and
    size of its member while it is read, so replacing the underlying data
    after validation cannot change what gets installed.

    Example usage::

        >>> with WheelFile.open("sampleproject-2.0.0-py3-none-any.whl") as source:
        ...     verified = VerifiedWheelSource(source)
        ...     installer.install(verified, destination)
    """

    validation_error = VerifiedWheelSourceError

    def __init__(self, source: WheelSource) -> None:
        super().__init__(
            distribution=source.distribution,
            version=source.version,
        )
        self._source = source
        self._members = self._validate()

    @property
    def dist_info_filenames(self) -> list[str]:
        """Get names of all files in the dist-info directory."""
        return self._source.dist_info_filenames

    def read_dist_info(self, filename: str) -> str:
        """Get contents, from ``filename`` in the dist-info directory."""
        return self._source.read_dist_info(filename)

    def _is_signature_file(self, path: str) -> bool:
        in_dist_info = self.dist_info_dir == posixpath.commonpath(
            [self.dist_info_dir, path]
        )
        return in_dist_info and path.split("/")[-1] in ("RECORD.p7s", "RECORD.jws")

    def _validate(self) -> list[_Member]:
        try:
            record_lines = self._source.read_dist_info("RECORD").splitlines()
            record_rows = list(parse_record_file(record_lines))
        except Exception as exc:
            raise VerifiedWheelSourceError(
                f"Unable to retrieve `RECORD` from the wheel source: {exc!r}"
            ) from exc

        issues: list[str] = []
        record_mapping: dict[str, RecordRow] = {}
        for row in record_rows:
            path = row[0]
            if path in record_mapping:
                issues.append(f"{path} is listed more than once in RECORD.")
                continue
            record_mapping[path] = row

        members: list[_Member] = []
        seen_paths: set[str] = set()
        for record_elements, stream, is_executable in self._source.get_contents():
            path = record_elements[0]
            if path in seen_paths:
                issues.append(f"{path} appears more than once in the wheel.")
                stream.close()
                continue
            seen_paths.add(path)

            record_row = record_mapping.pop(path, None)

            if self._is_signature_file(path):
                # Signature files are not mentioned in RECORD, per the wheel
                # specification; this exception applies only to them.
                if record_row is not None:
                    issues.append(
                        f"Digital signature file {path} is incorrectly "
                        "contained in RECORD."
                    )
                stream.close()
                members.append(_Member(path, record_row, is_executable, False))
                continue

            if record_row is None:
                issues.append(f"{path} is not mentioned in RECORD.")
                stream.close()
                continue

            try:
                record = RecordEntry.from_elements(*record_row)
            except InvalidRecordEntry as exc:
                for issue in exc.issues:
                    issues.append(
                        f"Entry in RECORD file for {path} is invalid: {issue}"
                    )
                stream.close()
                continue

            if path == f"{self.dist_info_dir}/RECORD":
                # RECORD describes every other file but never itself; a hash
                # or size for RECORD is incorrect.
                if record.hash_ is not None or record.size is not None:
                    issues.append("RECORD file incorrectly contains hash / size.")
                stream.close()
                members.append(_Member(path, record_row, is_executable, False))
                continue

            if record.hash_ is None or record.size is None:
                # Regular modules must always carry a hash and a size.
                issues.append(f"Hash / size of {path} is not included in RECORD.")
                stream.close()
                continue

            if not record.validate_stream(stream):
                issues.append(f"Hash / size of {path} didn't match RECORD.")
            stream.close()
            members.append(_Member(path, record_row, is_executable, True))

        # Anything left in the mapping is a RECORD entry with no member.
        for path in record_mapping:
            issues.append(
                f"{path} is mentioned in RECORD but missing from the wheel."
            )

        if issues:
            raise VerifiedWheelSourceError(issues)

        return members

    def validate_record(self) -> None:
        """Re-validate the wrapped source against its ``RECORD``.

        Construction already performs this validation; calling this method
        repeats it against the source's current contents.
        """
        self._members = self._validate()

    def get_contents(self) -> Iterator["WheelContentElement"]:
        """Sequential access to the verified contents of the wheel.

        Regular members are wrapped in a stream that re-verifies their digest
        and size while reading; the ``RECORD`` file and signature files are
        passed through unchanged, matching the wheel specification's special
        handling of them.
        """
        for member in self._members:
            underlying, owner = self._open_member(member.path)
            if not member.verified:
                # RECORD itself and the signature files have no hash/size to
                # verify against; pass their stream straight through. The
                # wrapper still owns closing the underlying stream. Signature
                # files are absent from RECORD, so they yield an empty row.
                row = member.record_row or (member.path, "", "")
                stream: BinaryIO = _PassthroughStream(underlying, owner)
            else:
                assert member.record_row is not None
                record = RecordEntry.from_elements(*member.record_row)
                row = member.record_row
                stream = _VerifyingStream(underlying, record, member.path, owner)
            yield row, stream, member.is_executable

    def _open_member(
        self, path: str
    ) -> tuple[BinaryIO, Iterator["WheelContentElement"]]:
        iterator = iter(self._source.get_contents())
        for record_elements, stream, _is_executable in iterator:
            if record_elements[0] == path:
                return stream, iterator
        iterator.close()
        raise VerifiedWheelSourceError(
            f"{path} was verified but can no longer be read from the wheel source."
        )
