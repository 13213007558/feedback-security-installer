```{caution}
This API is not finalised, and may change in a patch version.
```

# `installer.verified`

`VerifiedWheelSource` wraps any {any}`installer.sources.WheelSource`,
validates its `RECORD` against the actual archive contents, and then only
exposes streams that re-verify the bytes while they are read. This binds the
installation to exactly the bytes that passed the integrity check, so data
changed between validation and installation cannot be installed.

Validation enforces a one-to-one relationship between `RECORD` entries and
archive members (rejecting duplicate members, duplicate `RECORD` paths and
missing members), the declared size and digest of every regular member, and
the prohibition on empty hashes for regular modules. The wheel
specification's exceptions for the `RECORD` file itself and for the
`RECORD.jws` / `RECORD.p7s` signature files are retained and are not applied
to ordinary modules.

Streams are verified in bounded chunks, and a stream closed before its
verified end is reached raises an error instead of presenting partially-read
bytes as trusted.

```python
from installer.sources import WheelFile
from installer.verified import VerifiedWheelSource
from installer import install

with WheelFile.open("sampleproject-2.0.0-py3-none-any.whl") as source:
    verified = VerifiedWheelSource(source)
    install(verified, destination, additional_metadata={})
```

```{eval-rst}
.. automodule:: installer.verified
    :members:
```
