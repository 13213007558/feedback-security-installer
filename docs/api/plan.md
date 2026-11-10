```{caution}
This API is not finalised, and may change in a patch version.
```

# `installer.plan`

`installer.plan` computes every filesystem target of an installation *before*
any file is written. The resulting
{class}`~installer.plan.InstallationPlan` can be previewed by publishing tools
and later handed to {func}`installer.install` for execution.

The plan covers four kinds of outputs:

- archive members, including files relocated through the
  `{distribution}-{version}.data` directory into `purelib`, `platlib`,
  `scripts`, `headers` or `data`;
- launcher scripts generated from `entry_points.txt`;
- additional dist-info metadata supplied by the caller;
- the final `RECORD` file.

Targets are computed from the actual `scheme_dict` and `destdir`
configuration. Before returning, the plan verifies that:

- no two outputs land on the same file, including across different schemes
  whose configured directories point at the same place;
- no output needs a path that another output uses as a file (or vice versa);
- no two outputs are case-only aliases on a case-insensitive target (Windows
  launcher kinds are treated as case-insensitive, POSIX as case-sensitive);
- no output escapes its scheme directory after `..` normalisation;
- no output writes through a symbolic link inside the trusted installation
  root. Links at or above the configured root are treated as part of the
  trusted environment; links below it are always refused, even when
  overwriting is enabled.

A pre-existing regular file blocks the plan unless `overwrite_existing` is
set; a pre-existing symbolic link is never overwritten.

```{note}
The checks assume the installation roots are trusted and not writable by
unrelated processes. They do not defend against entries that appear between
planning and execution.
```

A plan is bound to the wheel identity
(`distribution`, `version` and the concrete source object) and to a
fingerprint of the destination configuration (`scheme_dict`, `destdir` and
the platform case rules). Executing a plan against a different source or
destination raises {class}`~installer.exceptions.StalePlanError`.

## Example

```python
from installer import build_installation_plan, install
from installer.destinations import SchemeDictionaryDestination
from installer.sources import WheelFile

destination = SchemeDictionaryDestination(
    sysconfig.get_paths(),
    interpreter=sys.executable,
    script_kind="posix",
)

with WheelFile.open("package-1.0.0-py3-none-any.whl") as source:
    # Preview every file that would be written.
    plan = build_installation_plan(source, destination, {"INSTALLER": b"my-tool"})
    for target in plan.targets:
        print(target)
    # Execute the exact plan; raises if source or destination changed.
    install(source, destination, {"INSTALLER": b"my-tool"}, plan=plan)
```

```{eval-rst}
.. automodule:: installer.plan
    :members:
```
