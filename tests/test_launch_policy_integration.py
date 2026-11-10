"""End-to-end launch entry policy checks using small locally built wheels."""

import base64
import hashlib
import json
import textwrap
import zipfile
from io import BytesIO
from pathlib import Path
from unittest import mock

import pytest
from installer import install
from installer.destinations import SchemeDictionaryDestination
from installer.policies import (
    EntryCategory,
    LaunchEntryPolicy,
    PolicyAction,
    PolicyRule,
    PolicyViolation,
    load_launch_entry_policy,
    policy_from_dict,
)
from installer.sources import WheelFile

WHEEL_FILE = textwrap.dedent(
    """\
    Wheel-Version: 1.0
    Generator: policy-tests
    Root-Is-Purelib: true
    Tag: py3-none-any
    """
)


def build_wheel(path: Path, name: str, files: dict[str, bytes]) -> Path:
    """Build a valid wheel with a correct RECORD for the given files."""
    dist_info = f"{name}-1.0.0.dist-info"
    metadata = textwrap.dedent(
        f"""\
        Metadata-Version: 2.1
        Name: {name}
        Version: 1.0.0
        """
    ).encode()
    wheel = {
        f"{name}/__init__.py": b"# package\n",
        f"{dist_info}/METADATA": metadata,
        f"{dist_info}/WHEEL": WHEEL_FILE.encode(),
        **files,
    }

    record_rows = []
    for filename, content in sorted(wheel.items()):
        digest = hashlib.sha256(content).digest()
        hash_value = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        record_rows.append(f"{filename},sha256={hash_value},{len(content)}")
    record_rows.append(f"{dist_info}/RECORD,,")
    wheel[f"{dist_info}/RECORD"] = ("\n".join(record_rows) + "\n").encode()

    wheel_path = path / f"{name}-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        for filename, content in sorted(wheel.items()):
            archive.writestr(filename, content)
    return wheel_path


def write_policy(path: Path, data: dict) -> Path:
    policy_path = path / "policy.json"
    policy_path.write_text(json.dumps(data), encoding="utf-8")
    return policy_path


def destination_for(tmp_path: Path) -> SchemeDictionaryDestination:
    target = tmp_path / "prefix"
    return SchemeDictionaryDestination(
        scheme_dict={
            "purelib": str(target / "lib"),
            "platlib": str(target / "lib"),
            "scripts": str(target / "bin"),
            "headers": str(target / "include"),
            "data": str(target / "share"),
        },
        interpreter="/usr/bin/python3",
        script_kind="posix",
        bytecode_optimization_levels=(),
    )


# A policy that only allows two known commands and nothing else.
TWO_COMMAND_POLICY = {
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

ENTRY_POINTS = (
    "[console_scripts]\n"
    "fancy = fancy:main\n"
    "\n"
    "[gui_scripts]\n"
    "fancy-gui = fancy:main\n"
)


def test_comment_only_pth_has_no_launch_entries(tmp_path):
    wheel_path = build_wheel(
        tmp_path,
        "commentpkg",
        {
            "commentpkg-1.0.0.dist-info/entry_points.txt": ENTRY_POINTS.encode(),
            "comments.pth": b"# just a comment\n# another comment\n",
        },
    )
    policy = policy_from_dict(TWO_COMMAND_POLICY)
    destination = destination_for(tmp_path)

    with WheelFile.open(wheel_path) as source:
        install(source, destination, {}, launch_entry_policy=policy)

    installed = destination_for(tmp_path)
    assert (Path(installed.scheme_dict["purelib"]) / "comments.pth").exists()
    assert (Path(installed.scheme_dict["scripts"]) / "fancy").exists()
    assert (Path(installed.scheme_dict["scripts"]) / "fancy-gui").exists()


def test_plain_path_pth_is_classified_and_denied(tmp_path):
    wheel_path = build_wheel(
        tmp_path,
        "pathpkg",
        {"paths.pth": b"# header\n/opt/vendor/lib\n\n"},
    )
    policy = policy_from_dict(TWO_COMMAND_POLICY)
    destination = mock.Mock()

    with WheelFile.open(wheel_path) as source, pytest.raises(PolicyViolation) as ctx:
        install(source, destination, {}, launch_entry_policy=policy)

    message = str(ctx.value)
    assert "pth_path" in message
    assert wheel_path.name in message
    assert "purelib:paths.pth" in message
    destination.write_file.assert_not_called()
    destination.write_script.assert_not_called()
    destination.finalize_installation.assert_not_called()


def test_executable_pth_is_classified_as_import(tmp_path):
    secret = "token=AKIA-SECRET-VALUE-MUST-NOT-LEAK"
    wheel_path = build_wheel(
        tmp_path,
        "evilpkg",
        {
            "evil.pth": (
                f"# benign comment\nimport evilpkg.runner  # {secret}\n".encode()
            ),
        },
    )
    policy = LaunchEntryPolicy(
        default_action=PolicyAction.DENY,
        rules=(PolicyRule(PolicyAction.ALLOW, categories=(EntryCategory.PTH_PATH,)),),
    )
    destination = mock.Mock()

    with WheelFile.open(wheel_path) as source, pytest.raises(PolicyViolation) as ctx:
        install(source, destination, {}, launch_entry_policy=policy)

    entry = ctx.value.violations[0][0]
    assert entry.category is EntryCategory.PTH_IMPORT
    assert entry.line_numbers == (2,)
    message = str(ctx.value)
    assert "pth_import" in message
    assert secret not in message
    destination.write_file.assert_not_called()


def test_known_entry_points_are_allowed_and_others_denied(tmp_path):
    good_wheel = build_wheel(
        tmp_path,
        "fancy",
        {
            "fancy-1.0.0.dist-info/entry_points.txt": ENTRY_POINTS.encode(),
        },
    )
    repo_root = Path(__file__).resolve().parent.parent
    policy_path = write_policy(tmp_path, TWO_COMMAND_POLICY)
    assert load_launch_entry_policy(
        repo_root / "examples" / "launch-entry-policy.json"
    ) == load_launch_entry_policy(policy_path)
    policy = load_launch_entry_policy(policy_path)
    destination = destination_for(tmp_path)

    with WheelFile.open(good_wheel) as source:
        install(source, destination, {}, launch_entry_policy=policy)

    assert (Path(destination.scheme_dict["scripts"]) / "fancy").exists()
    assert (Path(destination.scheme_dict["scripts"]) / "fancy-gui").exists()

    bad_wheel = build_wheel(
        tmp_path,
        "sneaky",
        {
            "sneaky-1.0.0.dist-info/entry_points.txt": (
                b"[console_scripts]\nsneaky = sneaky:main\n"
            ),
        },
    )
    with WheelFile.open(bad_wheel) as source, pytest.raises(PolicyViolation) as ctx:
        install(source, mock.Mock(), {}, launch_entry_policy=policy)
    assert "entry_point" in str(ctx.value)
    assert "sneaky" in str(ctx.value)


def test_script_hidden_in_data_relocation_is_reviewed(tmp_path):
    wheel_path = build_wheel(
        tmp_path,
        "relocpkg",
        {
            "relocpkg-1.0.0.data/scripts/relocated-tool": b"#!/bin/sh\necho hi\n",
        },
    )
    policy = policy_from_dict(TWO_COMMAND_POLICY)
    destination = mock.Mock()

    with WheelFile.open(wheel_path) as source, pytest.raises(PolicyViolation) as ctx:
        install(source, destination, {}, launch_entry_policy=policy)

    entry = ctx.value.violations[0][0]
    assert entry.category is EntryCategory.SCRIPT
    assert entry.source_path == "relocpkg-1.0.0.data/scripts/relocated-tool"
    assert entry.destination_path == "relocated-tool"
    assert entry.scheme == "scripts"
    destination.write_file.assert_not_called()


def test_pth_hidden_in_data_relocation_is_reviewed(tmp_path):
    wheel_path = build_wheel(
        tmp_path,
        "relocpth",
        {
            "relocpth-1.0.0.data/purelib/relocated.pth": b"/opt/extra\n",
        },
    )
    policy = LaunchEntryPolicy(
        default_action=PolicyAction.DENY,
        rules=(PolicyRule(PolicyAction.ALLOW, categories=(EntryCategory.PTH_IMPORT,)),),
    )

    with WheelFile.open(wheel_path) as source, pytest.raises(PolicyViolation) as ctx:
        install(source, mock.Mock(), {}, launch_entry_policy=policy)

    entry = ctx.value.violations[0][0]
    assert entry.category is EntryCategory.PTH_PATH
    assert entry.destination_path == "relocated.pth"
    assert entry.scheme == "purelib"


def test_case_variant_pth_cannot_duplicate_another_entry(tmp_path):
    wheel_path = build_wheel(
        tmp_path,
        "casepkg",
        {
            "casepkg-1.0.0.dist-info/entry_points.txt": (
                b"[console_scripts]\nfancy = casepkg:main\n"
            ),
            "casepkg-1.0.0.data/scripts/FANCY": b"#!/bin/sh\necho hi\n",
        },
    )
    permissive = LaunchEntryPolicy(default_action=PolicyAction.ALLOW)

    with WheelFile.open(wheel_path) as source, pytest.raises(PolicyViolation) as ctx:
        install(source, mock.Mock(), {}, launch_entry_policy=permissive)

    assert "duplicate final destination" in str(ctx.value)


def test_nested_pth_is_not_a_site_launch_entry(tmp_path):
    wheel_path = build_wheel(
        tmp_path,
        "nestedpkg",
        {
            "nestedpkg/config.pth": b"import nestedpkg  # site ignores this\n",
        },
    )
    policy = LaunchEntryPolicy(default_action=PolicyAction.DENY)
    destination = destination_for(tmp_path)

    with WheelFile.open(wheel_path) as source:
        install(source, destination, {}, launch_entry_policy=policy)

    assert (
        Path(destination.scheme_dict["purelib"]) / "nestedpkg" / "config.pth"
    ).exists()


def test_additional_metadata_pth_is_also_reviewed(tmp_path):
    wheel_path = build_wheel(tmp_path, "extrapkg", {})
    policy = LaunchEntryPolicy(default_action=PolicyAction.DENY)
    destination = mock.Mock()

    with WheelFile.open(wheel_path) as source, pytest.raises(PolicyViolation) as ctx:
        install(
            source,
            destination,
            {"extra.pth": b"import extrapkg.bootstrap\n"},
            launch_entry_policy=policy,
        )

    entry = ctx.value.violations[0][0]
    assert entry.category is EntryCategory.PTH_IMPORT
    assert entry.source_path == "extrapkg-1.0.0.dist-info/extra.pth"
    destination.write_file.assert_not_called()


def test_install_without_policy_keeps_historical_behaviour(tmp_path):
    wheel_path = build_wheel(
        tmp_path,
        "oldschool",
        {
            "oldschool-1.0.0.data/scripts/tool": b"#!/bin/sh\necho hi\n",
            "boot.pth": b"import oldschool\n",
        },
    )
    destination = destination_for(tmp_path)

    with WheelFile.open(wheel_path) as source:
        install(source, destination, {})

    assert (Path(destination.scheme_dict["scripts"]) / "tool").exists()
    assert (Path(destination.scheme_dict["purelib"]) / "boot.pth").exists()


def test_path_tricks_cannot_hide_pth_suffix(tmp_path):
    # Zip paths are built explicitly here because RECORD/zip do not rewrite
    # ".." segments; this mirrors a wheel trying to disguise its layout.
    wheel_path = tmp_path / "trickypkg-1.0.0-py3-none-any.whl"
    dist_info = "trickypkg-1.0.0.dist-info"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr("trickypkg/__init__.py", b"# package\n")
        archive.writestr(
            f"{dist_info}/METADATA",
            b"Metadata-Version: 2.1\nName: trickypkg\nVersion: 1.0.0\n",
        )
        archive.writestr(f"{dist_info}/WHEEL", WHEEL_FILE.encode())
        archive.writestr(
            "trickypkg-1.0.0.data/purelib/foo/../tricky.pth",
            b"import trickypkg\n",
        )
        archive.writestr(
            f"{dist_info}/RECORD",
            f"{dist_info}/RECORD,,\n",
        )

    policy = LaunchEntryPolicy(default_action=PolicyAction.DENY)
    with WheelFile.open(wheel_path) as source, pytest.raises(PolicyViolation) as ctx:
        install(source, mock.Mock(), {}, launch_entry_policy=policy)

    entry = ctx.value.violations[0][0]
    assert entry.destination_path == "tricky.pth"
    assert entry.category is EntryCategory.PTH_IMPORT


def test_fake_source_uses_distribution_label_in_report(tmp_path):
    from installer.sources import WheelSource

    class FakeSource(WheelSource):
        def __init__(self):
            super().__init__("fake", "2.0.0")
            self._files = {
                "boot.pth": b"import fake\n",
                f"{self.dist_info_dir}/WHEEL": WHEEL_FILE.encode(),
                f"{self.dist_info_dir}/METADATA": (
                    b"Metadata-Version: 2.1\nName: fake\nVersion: 2.0.0\n"
                ),
            }

        @property
        def dist_info_filenames(self):
            prefix = f"{self.dist_info_dir}/"
            return [
                path[len(prefix) :]
                for path in self._files
                if path.startswith(prefix)
            ]

        def read_dist_info(self, filename):
            return self._files[f"{self.dist_info_dir}/{filename}"].decode()

        def validate_record(self):
            return None

        def get_contents(self):
            for path, content in sorted(self._files.items()):
                yield (path, "", ""), BytesIO(content), False

    source = FakeSource()
    policy = LaunchEntryPolicy(default_action=PolicyAction.DENY)
    with pytest.raises(PolicyViolation) as ctx:
        install(source, mock.Mock(), {}, launch_entry_policy=policy)

    assert "fake-2.0.0" in str(ctx.value)


def test_pycache_entries_are_skipped_during_policy_review(tmp_path):
    wheel_path = tmp_path / "cachepkg-1.0.0-py3-none-any.whl"
    dist_info = "cachepkg-1.0.0.dist-info"
    with zipfile.ZipFile(wheel_path, "w") as archive:
        archive.writestr("cachepkg/__init__.py", b"# package\n")
        archive.writestr(
            "cachepkg/__pycache__/evil.cpython-312.pyc",
            b"# compiled bytecode that must never be installed\n",
        )
        archive.writestr(
            f"{dist_info}/METADATA",
            b"Metadata-Version: 2.1\nName: cachepkg\nVersion: 1.0.0\n",
        )
        archive.writestr(f"{dist_info}/WHEEL", WHEEL_FILE.encode())
        archive.writestr(f"{dist_info}/RECORD", f"{dist_info}/RECORD,,\n")

    policy = LaunchEntryPolicy(default_action=PolicyAction.DENY)
    destination = destination_for(tmp_path)

    with pytest.warns(RuntimeWarning), WheelFile.open(wheel_path) as source:
        install(source, destination, {}, launch_entry_policy=policy)

    assert not list(Path(destination.scheme_dict["purelib"]).rglob("*.pyc"))
