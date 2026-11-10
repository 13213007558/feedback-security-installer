```{caution}
This API is not finalised, and may change in a patch version.
```

# `installer.policies`

Optional review of wheel **launch entries** before anything is written to the
destination. A launch entry is anything that can run code or modify
`sys.path` outside of an explicit `import` of the package:

- `pth_path` -- a path line in a `.pth` file that the target interpreter's
  {mod}`site` machinery adds to `sys.path`.
- `pth_import` -- an `import ...` line in a `.pth` file that
  {func}`site.addpackage` executes at interpreter start-up.
- `script` -- an executable shipped in the wheel's `scripts` scheme,
  including files relocated from `.data/scripts`.
- `entry_point` -- a launcher generated from `entry_points.txt`.

`.pth` lines are classified using the same rules as the running
interpreter's {mod}`site` module (comments and blank lines are ignored), and
only `.pth` files at the root of a site directory are considered. The policy
never executes the wheel's code; it only reads file contents and metadata to
classify entries.

All decisions are made before the first file is written, so a denial never
leaves a partially installed wheel. The final, post-`.data`-relocation
destination is used for every decision, and destinations are compared
case-insensitively to catch collisions on case-insensitive file systems.

```{eval-rst}
.. automodule:: installer.policies
    :members:
```

## Scope

Passing this policy only means the wheel's **launch entries** match the
configured rules. It does not prove that the package's ordinary imported
code, build hooks or data files are safe -- review those separately.
