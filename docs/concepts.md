# Concepts

This library has two main abstractions:

- {any}`WheelSource`: Serves as source of information about a wheel file.
- {any}`WheelDestination`: Handles all file writing and post-installation
  processing.

## WheelSource

These objects represent a wheel file, abstracting away how the actual file is
stored or accessed.

This allows the core install logic to be used with in-memory wheel files, or
unzipped-on-disk wheel, or with {any}`zipfile.ZipFile` objects from an on-disk
wheel, or something else entirely.

This protocol/abstraction is designed to be implementable without a direct
dependency on this library. This allows for other libraries in the Python
packaging ecosystem to provide implementations of the protocol, allowing for
more code reuse opportunities.

One of the benefits of this fully described interface is the possibility to
decouple the implementation of additional validation on wheels (such as
validating the RECORD entries in a wheel match the actual contents of the wheel,
or enforcing signing requirements) based on what the specific use case demands.

## WheelDestination

These objects are responsible for handling the writing-to-filesystem
interactions, determining RECORD file entries and post-install actions (like
generating .pyc files). While this is a lot of responsibility, this was
explicitly provided to make it possible for custom `WheelDestination`
implementations to be more powerful and flexible.

Most of these tasks can either be delegated to utilities provided in this
library (eg: script generation), or to the Python standard library (eg:
generating `.pyc` files).

## Installation planning

Before writing anything, {class}`~installer.destinations.SchemeDictionaryDestination`
computes an {class}`~installer.plan.InstallationPlan` describing the final
filesystem location of every output: archive members (including
`.data` relocations), generated entry-point launchers, additional dist-info
metadata and the regenerated `RECORD`.

Comparing archive member names is not enough, because two different members can
land on the same file after scheme relocation, and a generated launcher can
share a name with an archived script. Planning therefore resolves every output
against the actual `scheme_dict` and `destdir`, then checks for:

- two outputs writing the same file, including across schemes that share a
  directory;
- a file path that another output needs as a directory (or vice versa);
- case-only aliases on case-insensitive targets;
- paths escaping a scheme root through `..`;
- symbolic links inside the trusted installation root, which are never
  followed or overwritten.

A failed plan raises before the first file is written. The plan is bound to
the wheel identity and a destination fingerprint, so it cannot be replayed
against a different source or another scheme configuration. See
{mod}`installer.plan` for the API and {mod}`installer.exceptions` for the
specific errors.
