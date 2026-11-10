"""A library for installing Python wheels."""

__version__ = "1.1.0"
__all__ = ["InstallationPlan", "build_installation_plan", "install"]

from installer._core import build_installation_plan, install
from installer.plan import InstallationPlan
