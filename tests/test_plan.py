import zipfile
from pathlib import Path

import pytest
from installer import InstallationPlan, build_installation_plan, install
from installer.destinations import SchemeDictionaryDestination
from installer.exceptions import (
    CaseAliasCollisionError,
    DestinationCollisionError,
    ExistingFileError,
    ExistingLinkError,
    FileDirectoryConflictError,
    InstallationPlanError,
    PathTraversalError,
    StalePlanError,
)
from installer.sources import WheelFile

SCHEMES = ("purelib", "platlib", "headers", "scripts", "data")


def make_wheel(
    tmp_path: Path,
    name: str,
    files: dict[str, bytes],
    *,
    version: str = "1.0.0",
    root_is_purelib: str = "true",
    entry_points: str | None = None,
) -> Path:
    """Build a minimal but valid wheel from explicit file contents.

    The generated RECORD lists every member without hashes, which is enough for
    installation planning and execution tests.
    """
    dist_info = f"{name}-{version}.dist-info"
    path = tmp_path / f"{name}-{version}-py3-none-any.whl"

    members = dict(files)
    members.setdefault(
        f"{dist_info}/WHEEL",
        (
            "Wheel-Version: 1.0\n"
            "Generator: test (1.0.0)\n"
            f"Root-Is-Purelib: {root_is_purelib}\n"
            "Tag: py3-none-any\n"
        ).encode(),
    )
    members.setdefault(
        f"{dist_info}/METADATA",
        (f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n").encode(),
    )
    if entry_points is not None:
        members[f"{dist_info}/entry_points.txt"] = entry_points.encode()

    record_lines = [
        f"{member},," for member in members if not member.endswith("/RECORD")
    ]
    record_lines.append(f"{dist_info}/RECORD,,")
    members[f"{dist_info}/RECORD"] = ("\n".join(record_lines) + "\n").encode()

    with zipfile.ZipFile(path, "w") as archive:
        for member, content in members.items():
            archive.writestr(member, content)
    return path


@pytest.fixture()
def scheme_dict(tmp_path: Path) -> dict[str, str]:
    root = tmp_path / "root"
    root.mkdir()
    return {scheme: str(root / scheme) for scheme in SCHEMES}


@pytest.fixture()
def destination(scheme_dict: dict[str, str]) -> SchemeDictionaryDestination:
    return SchemeDictionaryDestination(scheme_dict, "/my/python", "posix")


def _plan(tmp_path, destination, files, **wheel_kwargs):
    wheel = make_wheel(tmp_path, "pkg", files, **wheel_kwargs)
    with WheelFile.open(wheel) as source:
        return build_installation_plan(source, destination, {})


class TestBuildPlan:
    def test_lists_exact_final_targets(self, tmp_path, destination, scheme_dict):
        files = {
            "pkg/__init__.py": b"# root -> purelib\n",
            "pkg-1.0.0.data/purelib/pkg/relocated.py": b"# .data -> purelib\n",
            "pkg-1.0.0.data/data/pkg/shared-data.txt": b"# .data -> data\n",
        }
        wheel = make_wheel(
            tmp_path,
            "pkg",
            files,
            entry_points="[console_scripts]\npkg-tool = pkg:main\n",
        )
        with WheelFile.open(wheel) as source:
            plan = build_installation_plan(source, destination, {"INSTALLER": b"test"})

        assert isinstance(plan, InstallationPlan)

        purelib = Path(scheme_dict["purelib"])
        scripts = Path(scheme_dict["scripts"])
        expected = {
            scripts / "pkg-tool",
            purelib / "pkg" / "__init__.py",
            purelib / "pkg" / "relocated.py",
            Path(scheme_dict["data"]) / "pkg" / "shared-data.txt",
            purelib / "pkg-1.0.0.dist-info" / "WHEEL",
            purelib / "pkg-1.0.0.dist-info" / "METADATA",
            purelib / "pkg-1.0.0.dist-info" / "entry_points.txt",
            purelib / "pkg-1.0.0.dist-info" / "RECORD",
            purelib / "pkg-1.0.0.dist-info" / "INSTALLER",
        }
        assert set(plan.targets) == expected
        # RECORD is always planned last, since it is written during finalize.
        assert plan.files[-1].kind == "record"
        assert plan.files[-1].path == "pkg-1.0.0.dist-info/RECORD"

    def test_purelib_data_collision(self, tmp_path, destination):
        files = {
            "pkg/module.py": b"# archive root member\n",
            "pkg-1.0.0.data/purelib/pkg/module.py": b"# relocated .data member\n",
        }
        with pytest.raises(DestinationCollisionError, match="pkg/module.py"):
            _plan(tmp_path, destination, files)

    def test_cross_scheme_collision_when_roots_alias(self, tmp_path):
        shared = tmp_path / "shared"
        shared.mkdir()
        scheme_dict = {scheme: str(shared) for scheme in SCHEMES}
        destination = SchemeDictionaryDestination(scheme_dict, "/my/python", "posix")
        files = {
            "pkg/__init__.py": b"# purelib\n",
            "pkg-1.0.0.data/platlib/pkg/__init__.py": b"# platlib, same file\n",
        }
        with pytest.raises(DestinationCollisionError, match="pkg/__init__.py"):
            _plan(tmp_path, destination, files)

    def test_entry_point_script_collision(self, tmp_path, destination):
        files = {
            "pkg/__init__.py": b"def main():\n    pass\n",
            # An archive member lands in scripts/ under the very name the
            # generated console-script launcher will use.
            "pkg-1.0.0.data/scripts/pkg-tool": b"#!python\nprint('archive')\n",
        }
        wheel = make_wheel(
            tmp_path,
            "pkg",
            files,
            entry_points="[console_scripts]\npkg-tool = pkg:main\n",
        )
        with (
            WheelFile.open(wheel) as source,
            pytest.raises(DestinationCollisionError, match="pkg-tool"),
        ):
            build_installation_plan(source, destination, {})

    def test_entry_points_collide_with_each_other(self, tmp_path, destination):
        files = {"pkg/__init__.py": b"def main():\n    pass\n"}
        wheel = make_wheel(
            tmp_path,
            "pkg",
            files,
            entry_points=(
                "[console_scripts]\n"
                "tool = pkg:main\n"
                "[gui_scripts]\n"
                "tool = pkg:main\n"
            ),
        )
        with (
            WheelFile.open(wheel) as source,
            pytest.raises(DestinationCollisionError),
        ):
            build_installation_plan(source, destination, {})

    def test_case_alias_collision_within_plan(self, tmp_path):
        # A Windows-style target makes the destination case-insensitive even
        # though the tests run on a case-sensitive development machine.
        scheme_dict = {scheme: str(tmp_path / "root" / scheme) for scheme in SCHEMES}
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        destination = SchemeDictionaryDestination(
            scheme_dict, "C:/python/python.exe", "win-amd64"
        )
        files = {
            "pkg/Module.py": b"# upper\n",
            "pkg-1.0.0.data/purelib/pkg/module.py": b"# lower\n",
        }
        with pytest.raises(CaseAliasCollisionError, match="module.py"):
            _plan(tmp_path, destination, files)

    def test_case_alias_against_existing_file(self, tmp_path, scheme_dict):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        destination = SchemeDictionaryDestination(
            scheme_dict, "C:/python/python.exe", "win-amd64"
        )
        existing = Path(scheme_dict["purelib"]) / "pkg"
        existing.mkdir(parents=True)
        (existing / "Module.py").write_bytes(b"# pre-existing\n")

        files = {"pkg/module.py": b"# new, differs only in case\n"}
        with pytest.raises(CaseAliasCollisionError):
            _plan(tmp_path, destination, files)

    def test_case_sensitive_target_allows_case_variants(self, tmp_path, destination):
        files = {
            "pkg/Module.py": b"# upper\n",
            "pkg/module.py": b"# lower\n",
        }
        plan = _plan(tmp_path, destination, files)
        names = {
            planned.target.write_path.name
            for planned in plan.files
            if planned.scheme == "purelib" and planned.path.startswith("pkg/")
        }
        assert names == {"Module.py", "module.py"}

    def test_file_directory_conflict_within_plan(self, tmp_path, destination):
        # One member needs pkg/sub as a directory, another writes a file there.
        files = {
            "pkg/sub/__init__.py": b"# makes pkg/sub a directory\n",
            "pkg-1.0.0.data/purelib/pkg/sub": b"# wants pkg/sub as a file\n",
        }
        with pytest.raises(FileDirectoryConflictError, match="pkg/sub"):
            _plan(tmp_path, destination, files)

    def test_existing_directory_blocks_file(self, tmp_path, scheme_dict, destination):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        (Path(scheme_dict["purelib"]) / "pkg").mkdir(parents=True)
        files = {"pkg": b"# wants pkg as a file\n"}
        with pytest.raises(FileDirectoryConflictError):
            _plan(tmp_path, destination, files)

    def test_path_traversal_is_rejected(self, tmp_path, destination):
        files = {"pkg-1.0.0.data/purelib/../../escape.py": b"# evil\n"}
        with pytest.raises(PathTraversalError):
            _plan(tmp_path, destination, files)

    def test_traversal_in_additional_metadata(self, tmp_path, destination):
        wheel = make_wheel(tmp_path, "pkg", {"pkg/__init__.py": b""})
        with (
            WheelFile.open(wheel) as source,
            pytest.raises(PathTraversalError),
        ):
            build_installation_plan(
                source,
                destination,
                {"subdir/../../../escape.txt": b"# evil metadata name\n"},
            )

    def test_symbolic_link_target_is_refused(self, tmp_path, scheme_dict, destination):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"# outside the root\n")
        link = Path(scheme_dict["purelib"]) / "link.py"
        link.symlink_to(outside)

        files = {"link.py": b"# would follow the link\n"}
        with pytest.raises(ExistingLinkError, match="symbolic link"):
            _plan(tmp_path, destination, files)
        # The link target must be untouched, since planning never writes.
        assert outside.read_bytes() == b"# outside the root\n"

    def test_symbolic_link_ancestor_is_refused(
        self, tmp_path, scheme_dict, destination
    ):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        outside_dir = tmp_path / "outside-dir"
        outside_dir.mkdir()
        link_dir = Path(scheme_dict["purelib"]) / "linked"
        link_dir.symlink_to(outside_dir)

        files = {"linked/module.py": b"# escapes via link directory\n"}
        with pytest.raises(ExistingLinkError):
            _plan(tmp_path, destination, files)
        assert not (outside_dir / "module.py").exists()

    def test_trusted_root_link_is_accepted(self, tmp_path):
        # A symbolic link *at or above* the configured root is part of the
        # trusted environment; only links below the root are refused.
        real_root = tmp_path / "real-root"
        real_root.mkdir()
        link_root = tmp_path / "link-root"
        link_root.symlink_to(real_root)
        scheme_dict = {scheme: str(link_root / scheme) for scheme in SCHEMES}
        destination = SchemeDictionaryDestination(scheme_dict, "/my/python", "posix")

        plan = _plan(tmp_path, destination, {"pkg/__init__.py": b"# ok\n"})
        written_root = Path(plan.files[0].target.install_root)
        # The symlinked scheme root resolves into the trusted real root.
        assert written_root == real_root / "purelib"
        # The planned write path keeps the configured (symlinked) root while
        # the canonical trusted root is recorded alongside it.
        assert plan.files[0].target.write_path == (
            link_root / "purelib" / "pkg" / "__init__.py"
        )

    def test_existing_regular_file_is_blocked_then_overwritable(
        self, tmp_path, scheme_dict
    ):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        wheel = make_wheel(tmp_path, "pkg", {"pkg/__init__.py": b"# new\n"})
        existing = Path(scheme_dict["purelib"]) / "pkg"
        existing.mkdir(parents=True)
        marker = existing / "__init__.py"
        marker.write_bytes(b"# old\n")

        with WheelFile.open(wheel) as source:
            strict = SchemeDictionaryDestination(scheme_dict, "/my/python", "posix")
            with pytest.raises(ExistingFileError):
                build_installation_plan(source, strict, {})
            # Nothing was written while planning.
            assert marker.read_bytes() == b"# old\n"

            permissive = SchemeDictionaryDestination(
                scheme_dict, "/my/python", "posix", overwrite_existing=True
            )
            plan = build_installation_plan(source, permissive, {})
            assert marker in plan.targets

    def test_overwrite_does_not_follow_links(self, tmp_path, scheme_dict):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        wheel = make_wheel(tmp_path, "pkg", {"pkg/__init__.py": b"# new\n"})
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"# must stay untouched\n")
        marker = Path(scheme_dict["purelib"]) / "pkg"
        marker.mkdir(parents=True)
        link = marker / "__init__.py"
        link.symlink_to(outside)

        permissive = SchemeDictionaryDestination(
            scheme_dict, "/my/python", "posix", overwrite_existing=True
        )
        with (
            WheelFile.open(wheel) as source,
            pytest.raises(ExistingLinkError),
        ):
            build_installation_plan(source, permissive, {})
        assert outside.read_bytes() == b"# must stay untouched\n"
        assert link.is_symlink()

    def test_additional_metadata_collision(self, tmp_path, destination):
        wheel = make_wheel(
            tmp_path,
            "pkg",
            {"pkg-1.0.0.dist-info/INSTALLER": b"# from archive\n"},
        )
        with (
            WheelFile.open(wheel) as source,
            pytest.raises(DestinationCollisionError, match="INSTALLER"),
        ):
            build_installation_plan(source, destination, {"INSTALLER": b"test"})

    def test_record_collision(self, tmp_path, destination):
        files = {
            "pkg-1.0.0.dist-info/RECORD.p7s": b"# signature, fine\n",
            "pkg-1.0.0.data/purelib/pkg-1.0.0.dist-info/RECORD": b"# hijack\n",
        }
        with pytest.raises(DestinationCollisionError, match="RECORD"):
            _plan(tmp_path, destination, files)

    def test_destdir_is_part_of_targets_and_fingerprint(self, tmp_path, scheme_dict):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        destdir = tmp_path / "stage"
        destination = SchemeDictionaryDestination(
            scheme_dict, "/my/python", "posix", destdir=str(destdir)
        )
        plan = _plan(tmp_path, destination, {"pkg/__init__.py": b"# staged\n"})
        assert all(target.is_relative_to(destdir.resolve()) for target in plan.targets)
        assert str(destdir) in str(plan.destination_fingerprint)

    def test_destdir_symbolic_link_is_refused(self, tmp_path, scheme_dict):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        stage = tmp_path / "stage"
        stage.mkdir()
        outside = tmp_path / "outside-dir"
        outside.mkdir()
        # destdir staging recreates the absolute purelib path below stage, so
        # the symlink has to sit at that lexical location to be reachable.
        staged_purelib = stage / Path(scheme_dict["purelib"]).relative_to(
            Path(scheme_dict["purelib"]).anchor
        )
        staged_purelib.mkdir(parents=True)
        (staged_purelib / "evil").symlink_to(outside)
        destination = SchemeDictionaryDestination(
            scheme_dict, "/my/python", "posix", destdir=str(stage)
        )

        files = {"evil/module.py": b"# escapes through a staged symlink\n"}
        with pytest.raises(ExistingLinkError):
            _plan(tmp_path, destination, files)
        assert not (outside / "module.py").exists()


class TestPlanBinding:
    def test_rejects_different_source(self, tmp_path, destination):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()
        wheel_a = make_wheel(dir_a, "pkg_a", {"pkg_a/__init__.py": b""})
        wheel_b = make_wheel(dir_b, "pkg_b", {"pkg_b/__init__.py": b""})
        with WheelFile.open(wheel_a) as source_a:
            plan = build_installation_plan(source_a, destination, {})
        with (
            WheelFile.open(wheel_b) as source_b,
            pytest.raises(StalePlanError, match="different wheel source"),
        ):
            install(source_b, destination, {}, plan=plan)

    def test_rejects_changed_destination(self, tmp_path, scheme_dict, destination):
        wheel = make_wheel(tmp_path, "pkg", {"pkg/__init__.py": b""})
        with WheelFile.open(wheel) as source:
            plan = build_installation_plan(source, destination, {})

        other_dict = dict(scheme_dict)
        other_dict["purelib"] = scheme_dict["purelib"] + "-moved"
        moved = SchemeDictionaryDestination(other_dict, "/my/python", "posix")
        with (
            WheelFile.open(wheel) as source,
            pytest.raises(StalePlanError),
        ):
            install(source, moved, {}, plan=plan)

    def test_rejects_plan_for_unsupported_destination(self, tmp_path, destination):
        from unittest import mock

        wheel = make_wheel(tmp_path, "pkg", {"pkg/__init__.py": b""})
        with WheelFile.open(wheel) as source:
            plan = build_installation_plan(source, destination, {})
        with (
            WheelFile.open(wheel) as source,
            pytest.raises(TypeError),
        ):
            install(source, mock.Mock(), {}, plan=plan)


class TestPlanExecution:
    def test_failed_plan_writes_nothing(self, tmp_path, scheme_dict, destination):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        files = {
            "pkg/module.py": b"# root\n",
            "pkg-1.0.0.data/purelib/pkg/module.py": b"# collision\n",
        }
        wheel = make_wheel(tmp_path, "pkg", files)
        with (
            WheelFile.open(wheel) as source,
            pytest.raises(InstallationPlanError),
        ):
            install(source, destination, {})

        # The temporary install root must not contain a single planned file.
        all_entries = [
            entry
            for scheme_path in scheme_dict.values()
            for entry in Path(scheme_path).rglob("*")
        ]
        assert all_entries == []

    def test_successful_install_matches_preview(self, tmp_path, scheme_dict):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        destination = SchemeDictionaryDestination(scheme_dict, "/my/python", "posix")
        files = {
            "pkg/__init__.py": b"INIT = 1\n",
            "pkg-1.0.0.data/purelib/pkg/extra.py": b"EXTRA = 2\n",
            "pkg-1.0.0.data/data/pkg/data-file.txt": b"# data scheme\n",
        }
        wheel = make_wheel(
            tmp_path,
            "pkg",
            files,
            entry_points="[console_scripts]\npkg-cli = pkg:main\n",
        )
        with WheelFile.open(wheel) as source:
            plan = build_installation_plan(
                source, destination, {"INSTALLER": b"plan-tests"}
            )
            returned_plan = install(
                source, destination, {"INSTALLER": b"plan-tests"}, plan=plan
            )

        assert returned_plan is plan
        for target in plan.targets:
            assert target.exists(), f"missing planned file: {target}"
        record = Path(scheme_dict["purelib"]) / "pkg-1.0.0.dist-info" / "RECORD"
        record_lines = record.read_text().splitlines()
        record_paths = {line.split(",", 1)[0] for line in record_lines}
        assert "pkg/__init__.py" in record_paths
        assert "pkg/extra.py" in record_paths
        assert "pkg-1.0.0.dist-info/INSTALLER" in record_paths

    def test_install_builds_plan_implicitly(self, tmp_path, scheme_dict):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        destination = SchemeDictionaryDestination(scheme_dict, "/my/python", "posix")
        wheel = make_wheel(tmp_path, "pkg", {"pkg/__init__.py": b"INIT = 1\n"})
        with WheelFile.open(wheel) as source:
            plan = install(source, destination, {})
        assert isinstance(plan, InstallationPlan)
        assert (Path(scheme_dict["purelib"]) / "pkg" / "__init__.py").exists()

    def test_destdir_install(self, tmp_path, scheme_dict):
        for path in scheme_dict.values():
            Path(path).mkdir(parents=True)
        stage = tmp_path / "stage"
        destination = SchemeDictionaryDestination(
            scheme_dict, "/my/python", "posix", destdir=str(stage)
        )
        wheel = make_wheel(tmp_path, "pkg", {"pkg/__init__.py": b"INIT = 1\n"})
        with WheelFile.open(wheel) as source:
            plan = install(source, destination, {})
        for target in plan.targets:
            assert target.exists()
            assert target.is_relative_to(stage.resolve())
