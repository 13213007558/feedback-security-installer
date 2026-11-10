"""Tests for PEP 552 hash-based bytecode generation during installation."""

import marshal
import os
import stat
import subprocess
import sys
import time
import zipfile
from pathlib import Path
from py_compile import PycInvalidationMode, PyCompileError

import installer
import pytest
from installer.destinations import SchemeDictionaryDestination
from installer.records import RecordEntry
from installer.sources import WheelFile

CACHE_TAG = sys.implementation.cache_tag


def build_wheel(
    directory: Path,
    package: str,
    sources: dict[str, bytes],
) -> Path:
    """Build a minimal, installable wheel containing ``sources``."""
    wheel_path = directory / f"{package}-1.0.0-py3-none-any.whl"
    entries = {
        f"{package}-1.0.0.dist-info/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: test\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{package}-1.0.0.dist-info/METADATA": (
            f"Metadata-Version: 2.1\nName: {package}\nVersion: 1.0.0\n".encode()
        ),
        f"{package}-1.0.0.dist-info/top_level.txt": f"{package}\n".encode(),
        f"{package}-1.0.0.dist-info/RECORD": (
            f"{package}-1.0.0.dist-info/RECORD,,\n".encode()
        ),
    }
    entries.update(sources)
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for name, contents in entries.items():
            archive.writestr(name, contents)
    return wheel_path


def make_destination(
    root: Path,
    mode: PycInvalidationMode,
    levels: tuple[int, ...] = (0, 1),
    destdir: str | None = None,
    final_purelib: str | None = None,
) -> SchemeDictionaryDestination:
    purelib = final_purelib or str(root / "purelib")
    scheme_dict = {
        "purelib": purelib,
        "platlib": purelib,
        "headers": str(root / "headers"),
        "scripts": str(root / "scripts"),
        "data": str(root / "data"),
    }
    for key in ("headers", "scripts", "data"):
        Path(scheme_dict[key]).mkdir(parents=True, exist_ok=True)
    if final_purelib is None:
        Path(purelib).mkdir(parents=True, exist_ok=True)
    return SchemeDictionaryDestination(
        scheme_dict,
        sys.executable,
        "posix",
        bytecode_optimization_levels=list(levels),
        bytecode_invalidation_mode=mode,
        destdir=destdir,
    )


def install_wheel(
    wheel_path: Path,
    destination: SchemeDictionaryDestination,
) -> None:
    with WheelFile.open(wheel_path) as source:
        installer.install(source, destination, {})


def read_pyc_header_flags(pyc_path: Path) -> int:
    return int.from_bytes(pyc_path.read_bytes()[4:8], "little")


def load_code_object(pyc_path: Path):
    return marshal.loads(pyc_path.read_bytes()[16:])


def expected_pyc_name(source_name: str, level: int) -> str:
    stem = Path(source_name).stem
    suffix = "" if level == 0 else f".opt-{level}"
    return f"{stem}.{CACHE_TAG}{suffix}.pyc"


class TestBytecodeGeneration:
    @pytest.mark.parametrize(
        "mode",
        [PycInvalidationMode.TIMESTAMP, PycInvalidationMode.CHECKED_HASH],
    )
    def test_naming_and_flags_for_optimization_levels(self, tmp_path, mode):
        package = "levelmod"
        source = b'"""Module docstring."""\nassert True\nx = 1\n'
        wheel = build_wheel(
            tmp_path,
            package,
            # assert + docstring make optimized variants differ in content.
            {f"{package}/__init__.py": source},
        )
        destination = make_destination(tmp_path, mode, levels=(0, 1, 2))
        install_wheel(wheel, destination)

        cache_dir = tmp_path / "purelib" / package / "__pycache__"
        pyc_files = list(cache_dir.glob("*.pyc"))
        expected_names = [
            expected_pyc_name("__init__.py", level) for level in (0, 1, 2)
        ]
        assert {p.name for p in pyc_files} == set(expected_names)

        expected_flag = 0 if mode == PycInvalidationMode.TIMESTAMP else 3
        assert {read_pyc_header_flags(p) for p in pyc_files} == {expected_flag}

        # Different optimization levels must produce distinct bytecode.
        contents = {p.name: p.read_bytes() for p in pyc_files}
        assert len({contents[p.name] for p in pyc_files}) == 3

    def test_co_filename_uses_final_install_path(self, tmp_path):
        package = "pathmod"
        final_purelib = "/stable/install/prefix/site-packages"
        destination = make_destination(
            tmp_path,
            PycInvalidationMode.CHECKED_HASH,
            levels=(0,),
            destdir=str(tmp_path / "stage"),
            final_purelib=final_purelib,
        )
        wheel = build_wheel(tmp_path, package, {f"{package}/__init__.py": b"x = 1\n"})
        install_wheel(wheel, destination)

        pyc = next((tmp_path / "stage").rglob("*.pyc"))
        code = load_code_object(pyc)
        assert code.co_filename == f"{final_purelib}/{package}/__init__.py"
        # The machine-specific staging root must never leak into the bytecode.
        assert str(tmp_path).encode() not in pyc.read_bytes()

    def test_reproducible_across_staging_roots(self, tmp_path):
        package = "repromod"
        source = b"VALUE = 42\n"
        final_purelib = "/stable/install/prefix/site-packages"
        builds = {}
        staging_roots = []
        for index in range(2):
            root = tmp_path / f"staging-root-{index}"
            root.mkdir()
            staging_roots.append(root)
            destination = make_destination(
                root,
                PycInvalidationMode.CHECKED_HASH,
                levels=(0, 1),
                destdir=str(root / "dest"),
                final_purelib=final_purelib,
            )
            wheel = build_wheel(root, package, {f"{package}/__init__.py": source})
            install_wheel(wheel, destination)
            for pyc in (root / "dest").rglob("*.pyc"):
                builds.setdefault(pyc.name, []).append(pyc.read_bytes())

        assert len(builds) == 2
        for name, blobs in builds.items():
            assert len(blobs) == 2
            assert blobs[0] == blobs[1], f"{name} differs between staging roots"

        # A different source modification time must not change hash-based pyc.
        source_file = next((staging_roots[0] / "dest").rglob("*.py"))
        before = {p: p.read_bytes() for p in (staging_roots[0] / "dest").rglob("*.pyc")}
        stamp = source_file.stat().st_mtime
        os.utime(source_file, (stamp + 1000, stamp + 1000))
        rebuild_root = tmp_path / "staging-root-rebuild"
        rebuild_root.mkdir()
        destination = make_destination(
            rebuild_root,
            PycInvalidationMode.CHECKED_HASH,
            levels=(0, 1),
            destdir=str(rebuild_root / "dest"),
            final_purelib=final_purelib,
        )
        wheel = build_wheel(rebuild_root, package, {f"{package}/__init__.py": source})
        install_wheel(wheel, destination)
        after = {p.name: p.read_bytes() for p in (rebuild_root / "dest").rglob("*.pyc")}
        for pyc_path, blob in before.items():
            assert after[pyc_path.name] == blob

    def test_runtime_checked_hash_detects_content_change(self, tmp_path):
        package = "hashmod"
        wheel = build_wheel(
            tmp_path, package, {f"{package}/__init__.py": b"VALUE = 'AAAA'\n"}
        )
        purelib = tmp_path / "purelib"
        destination = make_destination(
            tmp_path, PycInvalidationMode.CHECKED_HASH, levels=(0,)
        )
        install_wheel(wheel, destination)
        source = purelib / package / "__init__.py"

        assert self._import_value(purelib, package) == "AAAA"

        # Equal-length rewrite keeps the source size constant; freezing the
        # mtime isolates source-hash invalidation from timestamp invalidation.
        stamp = source.stat().st_mtime
        time.sleep(0.05)
        source.write_text("VALUE = 'BBBB'\n")
        os.utime(source, (stamp, stamp))

        assert self._import_value(purelib, package) == "BBBB"

    def test_runtime_timestamp_keeps_stale_bytecode(self, tmp_path):
        package = "stampmod"
        wheel = build_wheel(
            tmp_path, package, {f"{package}/__init__.py": b"VALUE = 'AAAA'\n"}
        )
        purelib = tmp_path / "purelib"
        destination = make_destination(
            tmp_path, PycInvalidationMode.TIMESTAMP, levels=(0,)
        )
        install_wheel(wheel, destination)
        source = purelib / package / "__init__.py"

        assert self._import_value(purelib, package) == "AAAA"

        stamp = source.stat().st_mtime
        time.sleep(0.05)
        source.write_text("VALUE = 'BBBB'\n")
        os.utime(source, (stamp, stamp))

        # Timestamp-based pyc cannot detect the content-only change.
        assert self._import_value(purelib, package) == "AAAA"

    @staticmethod
    def _import_value(purelib: Path, package: str) -> str:
        completed = subprocess.run(
            [sys.executable, "-c", f"import {package}; print({package}.VALUE)"],
            cwd=purelib,
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        return completed.stdout.strip()

    def test_compilation_does_not_execute_module(self, tmp_path):
        package = "sidefxmod"
        sentinel = tmp_path / "executed.txt"
        source = f"open(r'{sentinel}', 'w').write('ran')\nVALUE = 1\n".encode()
        wheel = build_wheel(tmp_path, package, {f"{package}/__init__.py": source})
        destination = make_destination(
            tmp_path, PycInvalidationMode.CHECKED_HASH, levels=(0,)
        )
        install_wheel(wheel, destination)

        # Merely compiling must not run module-level code.
        assert not sentinel.exists()

        purelib = tmp_path / "purelib"
        subprocess.run(
            [sys.executable, "-c", f"import {package}"],
            cwd=purelib,
            check=True,
        )
        assert sentinel.read_text() == "ran"


class TestBytecodeRecord:
    def _record_rows(self, tmp_path: Path, package: str) -> dict[str, tuple[str, str]]:
        record_path = tmp_path / "purelib" / f"{package}-1.0.0.dist-info" / "RECORD"
        rows = {}
        for line in record_path.read_text().splitlines():
            path, hash_value, size = line.split(",")
            rows[path] = (hash_value, size)
        return rows

    def test_checked_hash_pyc_recorded_with_own_hash_and_size(self, tmp_path):
        package = "recordmod"
        wheel = build_wheel(tmp_path, package, {f"{package}/__init__.py": b"x = 1\n"})
        destination = make_destination(
            tmp_path, PycInvalidationMode.CHECKED_HASH, levels=(0, 1)
        )
        install_wheel(wheel, destination)

        rows = self._record_rows(tmp_path, package)
        source_entry = rows[f"{package}/__init__.py"]
        pyc_paths = [
            f"{package}/__pycache__/{expected_pyc_name('__init__.py', level)}"
            for level in (0, 1)
        ]

        for pyc_relpath in pyc_paths:
            assert pyc_relpath in rows
            hash_value, size_text = rows[pyc_relpath]
            pyc_path = tmp_path / "purelib" / pyc_relpath
            assert hash_value.startswith("sha256=")
            # Hash and size describe the pyc itself, not the source file.
            assert (hash_value, size_text) != source_entry
            assert int(size_text) == pyc_path.stat().st_size
            record = RecordEntry.from_elements(pyc_relpath, hash_value, size_text)
            assert record.hash_ is not None
            assert record.hash_.name == hash_value.split("=", 1)[0]
            assert record.hash_.validate(pyc_path.read_bytes())

    def test_timestamp_pyc_not_recorded(self, tmp_path):
        package = "unrecordedmod"
        wheel = build_wheel(tmp_path, package, {f"{package}/__init__.py": b"x = 1\n"})
        destination = make_destination(
            tmp_path, PycInvalidationMode.TIMESTAMP, levels=(0, 1)
        )
        install_wheel(wheel, destination)

        rows = self._record_rows(tmp_path, package)
        assert not any(path.endswith(".pyc") for path in rows)
        assert (tmp_path / "purelib" / package / "__pycache__").is_dir()


class TestBytecodeFailures:
    def test_syntax_error_raises_and_removes_pyc(self, tmp_path):
        package = "brokenmod"
        wheel = build_wheel(
            tmp_path, package, {f"{package}/__init__.py": b"def broken(:\n"}
        )
        destination = make_destination(
            tmp_path, PycInvalidationMode.CHECKED_HASH, levels=(0, 1)
        )

        with pytest.raises(PyCompileError) as exc_info:
            install_wheel(wheel, destination)

        # The error references the stable purported file name.
        assert f"{package}/__init__.py" in str(exc_info.value)
        assert list(tmp_path.rglob("*.pyc")) == []
        assert not (tmp_path / "purelib" / package / "__pycache__").exists()

    def test_failed_compile_discards_preexisting_pyc(self, tmp_path):
        package = "stalemod"
        destination = make_destination(
            tmp_path, PycInvalidationMode.CHECKED_HASH, levels=(0,)
        )
        good_wheel = build_wheel(
            tmp_path, package, {f"{package}/__init__.py": b"x = 1\n"}
        )
        install_wheel(good_wheel, destination)
        existing_pyc = next((tmp_path / "purelib").rglob("*.pyc"))
        assert existing_pyc.exists()

        package_dir = tmp_path / "purelib" / package
        (package_dir / "__init__.py").write_text("def broken(:\n")
        record = RecordEntry(f"{package}/__init__.py", None, None)
        with pytest.raises(PyCompileError):
            destination.finalize_installation(
                "purelib",
                f"{package}-1.0.0.dist-info/RECORD",
                [("purelib", record)],
            )

        # The old bytecode must not survive a failed compilation.
        assert not existing_pyc.exists()
        assert list(tmp_path.rglob("*.pyc")) == []

    @pytest.mark.skipif(
        not hasattr(os, "geteuid") or os.geteuid() == 0,
        reason="read-only permissions are not enforced for the root user",
    )
    def test_read_only_directory_reports_and_cleans_up(self, tmp_path):
        package = "readonlymod"
        purelib = tmp_path / "purelib"
        package_dir = purelib / package
        package_dir.mkdir(parents=True)
        (package_dir / "__init__.py").write_text("x = 1\n")

        destination = make_destination(
            tmp_path, PycInvalidationMode.CHECKED_HASH, levels=(0, 1)
        )
        package_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)
        try:
            with pytest.raises(PermissionError):
                destination.finalize_installation(
                    "purelib",
                    f"{package}-1.0.0.dist-info/RECORD",
                    [
                        (
                            "purelib",
                            RecordEntry(f"{package}/__init__.py", None, None),
                        )
                    ],
                )
        finally:
            package_dir.chmod(0o755)

        assert list(tmp_path.rglob("*.pyc")) == []

    def test_interrupted_compilation_rolls_back(self, tmp_path, monkeypatch):
        import py_compile

        package = "interruptmod"
        wheel = build_wheel(
            tmp_path,
            package,
            {
                f"{package}/__init__.py": b"x = 1\n",
                f"{package}/second.py": b"y = 2\n",
            },
        )
        destination = make_destination(
            tmp_path, PycInvalidationMode.CHECKED_HASH, levels=(0,)
        )

        real_compile = py_compile.compile
        calls = {"count": 0}

        def flaky_compile(*args, **kwargs):
            result = real_compile(*args, **kwargs)
            calls["count"] += 1
            if calls["count"] == 1:
                raise KeyboardInterrupt()
            return result

        monkeypatch.setattr(py_compile, "compile", flaky_compile)
        with pytest.raises(KeyboardInterrupt):
            install_wheel(wheel, destination)

        assert list(tmp_path.rglob("*.pyc")) == []

    def test_non_python_records_are_not_compiled(self, tmp_path):
        package = "mixedmod"
        wheel = build_wheel(
            tmp_path,
            package,
            {
                f"{package}/__init__.py": b"x = 1\n",
                f"{package}/data.txt": b"not python\n",
            },
        )
        destination = make_destination(
            tmp_path, PycInvalidationMode.CHECKED_HASH, levels=(0,)
        )
        install_wheel(wheel, destination)

        pyc_names = {p.name for p in tmp_path.rglob("*.pyc")}
        assert pyc_names == {expected_pyc_name("__init__.py", 0)}
