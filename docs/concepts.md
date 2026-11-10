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

## Launch entry policies

Some wheels install mechanisms that run code or change `sys.path` without an
explicit `import` of the package: executable or path lines in `.pth` files,
executables in the `scripts` scheme and launchers generated from
`entry_points.txt`. {mod}`installer.policies` provides an optional policy that
classifies these launch entries using the target interpreter's actual
{mod}`site` semantics and allows or denies them before the installation
writes anything.

This review is deliberately narrow: it covers launch entries only. Allowing a
wheel through the policy is not a statement that the package's ordinary code
is safe.
