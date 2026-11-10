"""Tests for the verified wheel source.

The security boundary is exercised two ways:

- a fake source whose bytes can be switched between two reads, proving that
  validation and installation consume the same (verified) bytes; and
- a real, on-disk zip file whose contents are rewritten after validation.
"""

import base64
import hashlib
import io
import os
import zipfile
from collections.abc import Iterator

import pytest

from installer import install
from installer.destinations import SchemeDictionaryDestination
from installer.records import RecordEntry, parse_record_file
from installer.sources import WheelContentElement, WheelFile, WheelSource
from installer.utils import _COPY_BUFSIZE, get_launcher_kind
from installer.verified import (
    VerifiedWheelSource,
    VerifiedWheelSourceError,
    _VerifyingStream,
)


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def _record_hash(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _record_row(path: str, data: bytes) -> tuple[str, str, str]:
    return path, _record_hash(data), str(len(data))


class SwitchingWheelSource(WheelSource):
    """A source that can present different bytes on each ``get_contents`` walk.

    ``files`` holds the "verified" contents and is what RECORD describes.
    Flipping :attr:`switched` makes subsequent walks serve ``tampered_files``,
    modelling a file replaced between the validation read and the install read.
    """

    def __init__(
        self,
        files: dict[str, bytes],
        *,
        tampered_files: dict[str, bytes] | None = None,
        duplicate_member: str | None = None,
        drop_member_on_reread: str | None = None,
    ) -> None:
        super().__init__(distribution="fancy", version="1.0.0")
        self._files = files
        self._tampered_files = tampered_files or {}
        self.switched = False
        self._duplicate_member = duplicate_member
        self._drop_member_on_reread = drop_member_on_reread

    @property
    def dist_info_filenames(self) -> list[str]:
        base = self.dist_info_dir + "/"
        return [name[len(base):] for name in self._files if name.startswith(base)]

    def read_dist_info(self, filename: str) -> str:
        return self._files[f"{self.dist_info_dir}/{filename}"].decode("utf-8")

    def _current_files(self) -> dict[str, bytes]:
        if not self.switched:
            return self._files
        current = dict(self._files)
        current.update(self._tampered_files)
        if self._drop_member_on_reread is not None:
            current.pop(self._drop_member_on_reread, None)
        return current

    def get_contents(self) -> Iterator[WheelContentElement]:
        files = self._current_files()
        record_data = self._files[f"{self.dist_info_dir}/RECORD"]
        record_rows = {
            row[0]: row for row in self._parse_record_rows(record_data)
        }
        for path in sorted(files):
            if path[-1:] == "/":
                continue
            # Fall back to an empty row, like WheelFile.get_contents, so the
            # verifier itself detects members missing from RECORD.
            row = record_rows.get(path, (path, "", ""))
            yield row, io.BytesIO(files[path]), False
            if self._duplicate_member == path:
                yield row, io.BytesIO(files[path]), False

    @staticmethod
    def _parse_record_rows(data: bytes) -> list[tuple[str, str, str]]:
        return list(parse_record_file(data.decode().splitlines()))


def _record_text(files: dict[str, bytes], dist_info: str) -> bytes:
    record_path = f"{dist_info}/RECORD"
    lines = []
    for path in sorted(files):
        if path[-1:] == "/" or path == record_path:
            continue
        path_, hash_, size = _record_row(path, files[path])
        lines.append(f"{path_},{hash_},{size}")
    lines.append(f"{record_path},,")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _make_files(*, include_signature: bool = False) -> dict[str, bytes]:
    dist_info = "fancy-1.0.0.dist-info"
    files: dict[str, bytes] = {
        "fancy/": b"",
        "fancy/__init__.py": b"def main():\n    return 'verified'\n",
        "fancy/__main__.py": b"from . import main\nmain()\n",
        f"{dist_info}/": b"",
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{dist_info}/METADATA": b"Metadata-Version: 2.1\nName: fancy\nVersion: 1.0.0\n",
        f"{dist_info}/top_level.txt": b"fancy\n",
    }
    # RECORD only describes the regular members; it is added before the
    # signature file so that the signature stays absent from RECORD.
    files[f"{dist_info}/RECORD"] = _record_text(files, dist_info)
    if include_signature:
        files[f"{dist_info}/RECORD.jws"] = b'{"hash": "sha256=deadbeef"}'
    return files


# --------------------------------------------------------------------------------------
# Construction / validation
# --------------------------------------------------------------------------------------
class TestVerifiedWheelSourceValidation:
    def test_accepts_consistent_source(self):
        source = SwitchingWheelSource(_make_files())
        verified = VerifiedWheelSource(source)

        rows = [row for row, _stream, _exe in verified.get_contents()]
        assert rows  # something was exposed
        paths = {row[0] for row in rows}
        assert "fancy/__init__.py" in paths
        assert f"{verified.dist_info_dir}/RECORD" in paths

    def test_rejects_hash_mismatch_at_construction(self):
        files = _make_files()
        tampered = {"fancy/__init__.py": b"def main():\n    return 'tampered'\n"}
        # Build RECORD describing the good files, but serve bad bytes already.
        source = SwitchingWheelSource(files, tampered_files=tampered)
        source.switched = True

        with pytest.raises(VerifiedWheelSourceError) as ctx:
            VerifiedWheelSource(source)
        assert any("didn't match RECORD" in issue for issue in ctx.value.issues)

    def test_rejects_member_missing_from_archive(self):
        files = _make_files()
        # RECORD still lists the module, but the archive no longer contains it.
        source = SwitchingWheelSource(
            files, drop_member_on_reread="fancy/__main__.py"
        )
        source.switched = True

        with pytest.raises(VerifiedWheelSourceError) as ctx:
            VerifiedWheelSource(source)
        assert any(
            "missing from the wheel" in issue and "__main__.py" in issue
            for issue in ctx.value.issues
        )

    def test_rejects_member_not_mentioned_in_record(self):
        files = _make_files()
        # Remove a module's row from RECORD while keeping the member.
        record_path = f"{source_dist_info()}/RECORD"
        lines = files[record_path].decode().splitlines()
        files[record_path] = (
            "\n".join(line for line in lines if "__main__.py" not in line) + "\n"
        ).encode()
        source = SwitchingWheelSource(files)

        with pytest.raises(VerifiedWheelSourceError) as ctx:
            VerifiedWheelSource(source)
        assert any("not mentioned in RECORD" in issue for issue in ctx.value.issues)

    def test_rejects_duplicate_archive_members(self):
        files = _make_files()
        source = SwitchingWheelSource(
            files, duplicate_member="fancy/__init__.py"
        )
        with pytest.raises(VerifiedWheelSourceError) as ctx:
            VerifiedWheelSource(source)
        assert any("appears more than once" in issue for issue in ctx.value.issues)

    def test_rejects_duplicate_record_paths(self):
        files = _make_files()
        record_path = f"{source_dist_info()}/RECORD"
        row = next(
            line for line in files[record_path].decode().splitlines()
            if "__init__.py" in line
        )
        files[record_path] = (
            files[record_path].decode().rstrip("\n") + "\n" + row + "\n"
        ).encode()
        source = SwitchingWheelSource(files)

        with pytest.raises(VerifiedWheelSourceError) as ctx:
            VerifiedWheelSource(source)
        assert any(
            "listed more than once in RECORD" in issue
            for issue in ctx.value.issues
        )

    def test_rejects_empty_hash_for_regular_module(self):
        files = _make_files()
        record_path = f"{source_dist_info()}/RECORD"
        lines = []
        for line in files[record_path].decode().splitlines():
            if "__init__.py" in line:
                line = line.split(",")[0] + ",,"
            lines.append(line)
        files[record_path] = ("\n".join(lines) + "\n").encode()
        source = SwitchingWheelSource(files)

        with pytest.raises(VerifiedWheelSourceError) as ctx:
            VerifiedWheelSource(source)
        assert any("not included in RECORD" in issue for issue in ctx.value.issues)

    def test_rejects_record_with_self_hash(self):
        files = _make_files()
        record_path = f"{source_dist_info()}/RECORD"
        lines = []
        for line in files[record_path].decode().splitlines():
            if line.endswith("RECORD,,"):
                line = f"{source_dist_info()}/RECORD,sha256=abc,10"
            lines.append(line)
        files[record_path] = ("\n".join(lines) + "\n").encode()
        source = SwitchingWheelSource(files)

        with pytest.raises(VerifiedWheelSourceError) as ctx:
            VerifiedWheelSource(source)
        assert any("RECORD file incorrectly" in issue for issue in ctx.value.issues)

    def test_accepts_signature_file_and_rejects_listing_it(self):
        good_files = _make_files(include_signature=True)
        verified = VerifiedWheelSource(SwitchingWheelSource(dict(good_files)))
        paths = {row[0] for row, _s, _e in verified.get_contents()}
        assert f"{verified.dist_info_dir}/RECORD.jws" in paths

        # The signature exception must not generalise: listing it in RECORD is
        # an error.
        files = dict(good_files)
        record_path = f"{source_dist_info()}/RECORD"
        sig_path = f"{source_dist_info()}/RECORD.jws"
        sig_row = ",".join(_record_row(sig_path, files[sig_path]))
        existing = files[record_path].decode().rstrip("\n")
        assert sig_path not in existing
        files[record_path] = (existing + "\n" + sig_row + "\n").encode()
        with pytest.raises(VerifiedWheelSourceError) as ctx:
            VerifiedWheelSource(SwitchingWheelSource(files))
        assert any("signature file" in issue for issue in ctx.value.issues)

    def test_missing_record_is_an_error(self):
        files = _make_files()
        del files[f"{source_dist_info()}/RECORD"]
        source = SwitchingWheelSource(files)
        with pytest.raises(VerifiedWheelSourceError, match="Unable to retrieve"):
            VerifiedWheelSource(source)

    def test_rejects_invalid_record_entry(self):
        files = _make_files()
        record_path = f"{source_dist_info()}/RECORD"
        lines = []
        for line in files[record_path].decode().splitlines():
            if "__init__.py" in line:
                line = line.split(",")[0] + ",sha=bogus,10"
            lines.append(line)
        files[record_path] = ("\n".join(lines) + "\n").encode()
        source = SwitchingWheelSource(files)

        with pytest.raises(VerifiedWheelSourceError) as ctx:
            VerifiedWheelSource(source)
        assert any("is invalid" in issue for issue in ctx.value.issues)

    def test_error_repr_lists_issues(self):
        error = VerifiedWheelSourceError(["first issue", "second issue"])
        assert "first issue" in repr(error)
        assert error.issues == ["first issue", "second issue"]
        single = VerifiedWheelSourceError("one issue")
        assert single.issues == ["one issue"]


def source_dist_info() -> str:
    return "fancy-1.0.0.dist-info"


# --------------------------------------------------------------------------------------
# TOCTOU boundary with the switching fake source
# --------------------------------------------------------------------------------------
class TestSwitchingBoundary:
    def test_switching_contents_between_reads_is_detected(self):
        files = _make_files()
        tampered = {"fancy/__init__.py": b"def main():\n    return 'tampered'\n"}
        source = SwitchingWheelSource(files, tampered_files=tampered)
        verified = VerifiedWheelSource(source)

        # The underlying bytes change after validation succeeded.
        source.switched = True

        for row, stream, _exe in verified.get_contents():
            if row[0] == "fancy/__init__.py":
                with pytest.raises(
                    VerifiedWheelSourceError, match="does not match RECORD"
                ):
                    stream.read()
                return
        pytest.fail("tampered member was not presented")

    def test_member_removed_after_validation_is_detected(self):
        files = _make_files()
        source = SwitchingWheelSource(
            files, drop_member_on_reread="fancy/__main__.py"
        )
        verified = VerifiedWheelSource(source)
        source.switched = True

        with pytest.raises(VerifiedWheelSourceError, match="can no longer be read"):
            for _row, _stream, _exe in verified.get_contents():
                pass

    def test_install_refuses_contents_switched_after_verification(self, tmp_path):
        files = _make_files()
        tampered = {"fancy/__init__.py": b"def main():\n    return 'tampered'\n"}
        source = SwitchingWheelSource(files, tampered_files=tampered)
        verified = VerifiedWheelSource(source)

        destination = _destination(tmp_path)
        # The bytes change after verification; installation must fail rather
        # than treat the tampered contents as trusted, because every stream
        # re-checks the digest and size at end of reading.
        source.switched = True
        with pytest.raises(VerifiedWheelSourceError, match="does not match RECORD"):
            install(verified, destination, {})

    def test_successful_install_writes_verified_digests(self, tmp_path):
        files = _make_files()
        source = SwitchingWheelSource(files)
        verified = VerifiedWheelSource(source)

        install(verified, _destination(tmp_path), {})

        installed = tmp_path / "purelib" / "fancy" / "__init__.py"
        expected = hashlib.sha256(files["fancy/__init__.py"]).hexdigest()
        assert hashlib.sha256(installed.read_bytes()).hexdigest() == expected


# --------------------------------------------------------------------------------------
# Real on-disk zip boundary
# --------------------------------------------------------------------------------------
def _write_wheel(path, files):
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)


class TestRealZipBoundary:
    def test_real_wheel_installs_verified_digests(self, tmp_path):
        wheel_path = tmp_path / "fancy-1.0.0-py3-none-any.whl"
        files = _make_files()
        _write_wheel(wheel_path, files)

        with WheelFile.open(wheel_path) as source:
            verified = VerifiedWheelSource(source)
            destination = _destination(tmp_path)
            install(verified, destination, {})

        installed = tmp_path / "purelib" / "fancy" / "__init__.py"
        expected = hashlib.sha256(files["fancy/__init__.py"]).hexdigest()
        assert hashlib.sha256(installed.read_bytes()).hexdigest() == expected

    def test_real_wheel_hash_mismatch_rejected(self, tmp_path):
        wheel_path = tmp_path / "fancy-1.0.0-py3-none-any.whl"
        files = _make_files()
        # Serve tampered module bytes while keeping the original RECORD.
        tampered = dict(files)
        tampered["fancy/__init__.py"] = b"def main():\n    return 'tampered'\n"
        _write_wheel(wheel_path, tampered)

        with WheelFile.open(wheel_path) as source, pytest.raises(
            VerifiedWheelSourceError, match="didn't match RECORD"
        ):
            VerifiedWheelSource(source)

    def test_real_wheel_installed_record_matches_written_digests(self, tmp_path):
        wheel_path = tmp_path / "fancy-1.0.0-py3-none-any.whl"
        files = _make_files()
        _write_wheel(wheel_path, files)

        destination = _destination(tmp_path)
        with WheelFile.open(wheel_path) as source:
            install(VerifiedWheelSource(source), destination, {})

        # The generated installation RECORD carries the digest of the bytes
        # actually written, which must match the source member's digest.
        installed_record = (
            tmp_path / "purelib" / "fancy-1.0.0.dist-info" / "RECORD"
        )
        record_rows = {
            row[0]: row
            for row in parse_record_file(installed_record.read_text().splitlines())
        }
        expected = _record_row("fancy/__init__.py", files["fancy/__init__.py"])
        assert record_rows["fancy/__init__.py"] == expected

    def test_real_wheel_missing_member_rejected(self, tmp_path):
        wheel_path = tmp_path / "fancy-1.0.0-py3-none-any.whl"
        files = _make_files()
        _write_wheel(wheel_path, files)

        # Drop a module but leave its RECORD row intact.
        reduced = {
            name: data
            for name, data in files.items()
            if name != "fancy/__main__.py"
        }
        _write_wheel(wheel_path, reduced)

        with WheelFile.open(wheel_path) as source, pytest.raises(
            VerifiedWheelSourceError, match="missing from the wheel"
        ):
            VerifiedWheelSource(source)

    def test_fancy_wheel_fixture_roundtrips(self, fancy_wheel, tmp_path):
        with WheelFile.open(fancy_wheel) as source:
            verified = VerifiedWheelSource(source)
            destination = _destination(tmp_path)
            install(verified, destination, {})

        installed = tmp_path / "purelib" / "fancy" / "__init__.py"
        with zipfile.ZipFile(fancy_wheel) as archive:
            expected = hashlib.sha256(
                archive.read("fancy/__init__.py")
            ).hexdigest()
        assert hashlib.sha256(installed.read_bytes()).hexdigest() == expected


# --------------------------------------------------------------------------------------
# Stream-level guarantees
# --------------------------------------------------------------------------------------
class TestVerifyingStream:
    def _stream(self, data: bytes) -> _VerifyingStream:
        record_path = "fancy/module.py"
        row = _record_row(record_path, data)
        record = RecordEntry.from_elements(*row)
        return _VerifyingStream(io.BytesIO(data), record, record_path)

    def test_full_read_passes(self):
        data = b"x" * 100_000
        stream = self._stream(data)
        assert stream.read() == data
        # Further reads at EOF must stay idempotent rather than re-verifying.
        assert stream.read() == b""
        stream.close()

    def test_early_close_after_partial_read_fails(self):
        stream = self._stream(b"y" * 1000)
        stream.read(10)
        with pytest.raises(VerifiedWheelSourceError):
            stream.close()

    def test_close_without_reading_is_allowed(self):
        stream = self._stream(b"y" * 1000)
        stream.close()
        assert stream.closed

    def test_tampered_tail_is_rejected_at_end(self):
        data = b"z" * 5000
        bad = io.BytesIO(data + b"extra")
        record = RecordEntry.from_elements(*_record_row("fancy/module.py", data))
        verifying = _VerifyingStream(bad, record, "fancy/module.py")
        with pytest.raises(VerifiedWheelSourceError):
            verifying.read()

    def test_reads_are_bounded(self):
        data = b"q" * (_COPY_BUFSIZE * 3)
        requested: list[int] = []

        class Spy(io.BytesIO):
            def read(self, n: int = -1) -> bytes:
                requested.append(n)
                return super().read(n)

        record = RecordEntry.from_elements(*_record_row("fancy/module.py", data))
        stream = _VerifyingStream(Spy(data), record, "fancy/module.py")
        while stream.read(10**9):
            pass
        assert requested
        assert max(requested) <= _COPY_BUFSIZE

    def test_seek_zero_rewinds_and_reverifies(self):
        data = b"#!python\nbody\n" * 100
        stream = self._stream(data)
        stream.readline()
        stream.seek(0)
        assert stream.read() == data
        stream.close()

    def test_non_zero_seek_rejected(self):
        stream = self._stream(b"abc")
        with pytest.raises(io.UnsupportedOperation):
            stream.seek(1)
        stream.close()


# --------------------------------------------------------------------------------------
# Interface compatibility
# --------------------------------------------------------------------------------------
class TestWheelSourceInterface:
    def test_old_interface_remains_abstract(self):
        source = WheelSource("distribution", "version")
        assert source.dist_info_dir == "distribution-version.dist-info"
        for action in (
            lambda: source.dist_info_filenames,
            lambda: source.read_dist_info("METADATA"),
            lambda: source.validate_record(),
            lambda: source.get_contents(),
        ):
            with pytest.raises(NotImplementedError):
                action()

    def test_verified_delegates_metadata_and_properties(self):
        files = _make_files()
        inner = SwitchingWheelSource(files)
        verified = VerifiedWheelSource(inner)

        assert verified.distribution == "fancy"
        assert verified.version == "1.0.0"
        assert verified.dist_info_dir == "fancy-1.0.0.dist-info"
        assert "WHEEL" in verified.dist_info_filenames
        assert "Wheel-Version" in verified.read_dist_info("WHEEL")

    def test_validate_record_can_re_run(self):
        files = _make_files()
        source = SwitchingWheelSource(files)
        verified = VerifiedWheelSource(source)
        verified.validate_record()  # no error: contents still match


def _destination(tmp_path) -> SchemeDictionaryDestination:
    base = str(tmp_path)
    scheme_dict = {
        scheme: os.path.join(base, scheme)
        for scheme in ("purelib", "platlib", "headers", "scripts", "data")
    }
    return SchemeDictionaryDestination(
        scheme_dict=scheme_dict,
        interpreter="/usr/bin/python",
        script_kind=get_launcher_kind(),
    )
