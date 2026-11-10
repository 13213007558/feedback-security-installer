import base64
import hashlib
import json
import os
import zipfile

import pytest
from installer.__main__ import _get_scheme_dict as get_scheme_dict
from installer.__main__ import _main as main
from installer.policies import PolicyViolation


def _build_wheel(tmp_path, name, files):
    dist_info = f"{name}-1.0.0.dist-info"
    contents = {
        f"{name}/__init__.py": b"# package\n",
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0.0\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
        ),
        **files,
    }
    rows = []
    for filename, data in sorted(contents.items()):
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .decode()
            .rstrip("=")
        )
        rows.append(f"{filename},sha256={digest},{len(data)}")
    rows.append(f"{dist_info}/RECORD,,")
    contents[f"{dist_info}/RECORD"] = ("\n".join(rows) + "\n").encode()

    wheel_path = tmp_path / f"{name}-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for filename, data in sorted(contents.items()):
            archive.writestr(filename, data)
    return wheel_path


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


def test_main_launch_entry_policy_allows_known_commands(tmp_path):
    wheel_path = _build_wheel(
        tmp_path,
        "fancy",
        {
            "fancy-1.0.0.dist-info/entry_points.txt": (
                b"[console_scripts]\nfancy = fancy:main\n"
                b"[gui_scripts]\nfancy-gui = fancy:main\n"
            ),
        },
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps(
            {
                "default_action": "deny",
                "rules": [
                    {
                        "action": "allow",
                        "categories": ["entry_point"],
                        "names": ["fancy", "fancy-gui"],
                        "modules": ["fancy:main"],
                    }
                ],
            }
        )
    )
    destdir = tmp_path / "dest"

    main(
        [
            str(wheel_path),
            "-d",
            str(destdir),
            "--no-compile-bytecode",
            "--launch-entry-policy",
            str(policy_path),
        ],
        "python -m installer",
    )

    assert destdir.rglob("fancy")
    assert destdir.rglob("fancy-gui")


def test_main_launch_entry_policy_denies_and_writes_nothing(tmp_path):
    wheel_path = _build_wheel(
        tmp_path,
        "evil",
        {"evil.pth": b"import evil.bootstrap\n"},
    )
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(
        json.dumps({"default_action": "deny", "rules": []})
    )
    destdir = tmp_path / "dest"

    with pytest.raises(PolicyViolation):
        main(
            [
                str(wheel_path),
                "-d",
                str(destdir),
                "--no-compile-bytecode",
                "--launch-entry-policy",
                str(policy_path),
            ],
            "python -m installer",
        )

    assert not destdir.exists() or not any(destdir.rglob("*"))


def test_main_invalid_launch_entry_policy_raises(tmp_path):
    wheel_path = _build_wheel(tmp_path, "plain", {})
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps({"default_action": "maybe"}))

    with pytest.raises(ValueError, match="default_action"):
        main(
            [
                str(wheel_path),
                "-d",
                str(tmp_path / "dest"),
                "--no-compile-bytecode",
                "--launch-entry-policy",
                str(policy_path),
            ],
            "python -m installer",
        )
