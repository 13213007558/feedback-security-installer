import os

import pytest

from installer.__main__ import _get_scheme_dict as get_scheme_dict
from installer.__main__ import _main as main


def test_get_scheme_dict():
    d = get_scheme_dict(distribution_name="foo")
    assert set(d.keys()) >= {"purelib", "platlib", "headers", "scripts", "data"}


def test_get_scheme_dict_prefix():
    d = get_scheme_dict(distribution_name="foo", prefix="/foo")
    for key in ("purelib", "platlib", "headers", "scripts", "data"):
        assert d[key].startswith(f"{os.sep}foo"), (
            f"{key} does not start with /foo: {d[key]}"
        )


def test_main(fancy_wheel, tmp_path):
    destdir = tmp_path / "dest"

    main([str(fancy_wheel), "-d", str(destdir)], "python -m installer")

    installed_py_files = destdir.rglob("*.py")

    assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

    installed_pyc_files = destdir.rglob("*.pyc")
    assert {f.name.split(".")[0] for f in installed_pyc_files} == {
        "__init__",
        "__main__",
    }


def test_main_multiple_wheels(fancy_wheel, another_fancy_wheel, tmp_path):
    destdir = tmp_path / "dest"

    main(
        [str(fancy_wheel), str(another_fancy_wheel), "-d", str(destdir)],
        "python -m installer",
    )

    for wheel_name in ("fancy", "another_fancy"):
        installed_py_files = destdir.rglob(f"**/{wheel_name}/**/*.py")
        assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

        installed_pyc_files = destdir.rglob(f"**/{wheel_name}/**/*.pyc")
        assert {f.name.split(".")[0] for f in installed_pyc_files} == {
            "__init__",
            "__main__",
        }


def test_main_prefix(fancy_wheel, tmp_path):
    destdir = tmp_path / "dest"

    main([str(fancy_wheel), "-d", str(destdir), "-p", "/foo"], "python -m installer")

    installed_py_files = list(destdir.rglob("*.py"))

    for f in installed_py_files:
        assert str(f.parent).startswith(str(destdir / "foo")), (
            f"path does not respect destdir+prefix: {f}"
        )
    assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

    installed_pyc_files = destdir.rglob("*.pyc")
    assert {f.name.split(".")[0] for f in installed_pyc_files} == {
        "__init__",
        "__main__",
    }


def test_main_no_pyc(fancy_wheel, tmp_path):
    destdir = tmp_path / "dest"

    main(
        [str(fancy_wheel), "-d", str(destdir), "--no-compile-bytecode"],
        "python -m installer",
    )

    installed_py_files = destdir.rglob("*.py")

    assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

    installed_pyc_files = destdir.rglob("*.pyc")
    assert set(installed_pyc_files) == set()


@pytest.mark.parametrize(
    "validation_part",
    ["all", "entries", "none"],
)
def test_main_validate_record_all_pass(fancy_wheel, tmp_path, validation_part):
    destdir = tmp_path / "dest"

    main(
        [str(fancy_wheel), "-d", str(destdir), "--validate-record", validation_part],
        "python -m installer",
    )

    installed_py_files = destdir.rglob("*.py")

    assert {f.stem for f in installed_py_files} == {"__init__", "__main__", "data"}

    installed_pyc_files = destdir.rglob("*.pyc")
    assert {f.name.split(".")[0] for f in installed_pyc_files} == {
        "__init__",
        "__main__",
    }


def test_main_checked_hash_bytecode(fancy_wheel, tmp_path):
    import marshal

    destdir = tmp_path / "dest"

    main(
        [
            str(fancy_wheel),
            "-d",
            str(destdir),
            "--pyc-invalidation-mode",
            "checked-hash",
        ],
        "python -m installer",
    )

    installed_pyc_files = list(destdir.rglob("*.pyc"))
    assert installed_pyc_files

    # PEP 552 checked-hash files carry flag value 3 and are loadable.
    for pyc_file in installed_pyc_files:
        data = pyc_file.read_bytes()
        assert int.from_bytes(data[4:8], "little") == 3
        marshal.loads(data[16:])

    record_text = next(destdir.rglob("RECORD")).read_text()
    # RECORD paths are relative to the install scheme, so they only contain
    # the package-relative portion of the on-disk location.
    record_pyc_paths = {
        line.split(",", 1)[0] for line in record_text.splitlines() if ".pyc," in line
    }
    expected_pyc_paths = {
        f"fancy/__pycache__/{pyc_file.name}" for pyc_file in installed_pyc_files
    }
    assert record_pyc_paths == expected_pyc_paths


def test_main_rejects_unknown_invalidation_mode(fancy_wheel, tmp_path):
    with pytest.raises(SystemExit):
        main(
            [
                str(fancy_wheel),
                "-d",
                str(tmp_path / "dest"),
                "--pyc-invalidation-mode",
                "bogus",
            ],
            "python -m installer",
        )
