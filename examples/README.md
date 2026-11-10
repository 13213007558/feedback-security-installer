# Example launch entry policy

`launch-entry-policy.json` only allows the two known commands `fancy` and
`fancy-gui` (both resolving to `fancy:main`, generated from
`entry_points.txt`). Everything else is denied by default:

- executable (`import ...`) and path lines in any `.pth` file,
- executable scripts shipped in a wheel's `.data/scripts` directory,
- any other `console_scripts` / `gui_scripts` entry point.

Use it with:

```sh
python -m installer --launch-entry-policy examples/launch-entry-policy.json wheel.whl
```

or from Python:

```python
from installer.policies import load_launch_entry_policy

policy = load_launch_entry_policy("examples/launch-entry-policy.json")
install(source, destination, additional_metadata, launch_entry_policy=policy)
```

## Scope

This policy only reviews **launch entries** — the mechanisms that run code or
modify `sys.path` when the interpreter starts or when an installed command is
invoked. Passing the check does **not** prove that the package's ordinary
imported code, build hooks or data files are safe; review those separately.
