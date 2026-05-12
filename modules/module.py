# recon_wp/modules/module.py
"""
Module container - groups steps for organized execution.

A module is a named collection of related steps that run together.
Modules provide organization and validation for groups of reconnaissance steps.
"""

# WHAT: Groups related steps together for organized execution
# HOW: Add steps via add_step(), validate via validate()
# WHY: Provides structure - modules group checks by category (discovery, fingerprint, etc.)

from typing import Type


class Module:
    """A named collection of steps that run together.

    Single Responsibility: only groups steps, doesn't execute them directly.
    """

    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self._steps: list[Type] = []

    def add_step(self, step_class: Type) -> None:
        """Add a step class to this module."""
        self._steps.append(step_class)

    @property
    def steps(self) -> list[Type]:
        """Return all step classes in this module."""
        return self._steps

    def validate(self) -> list[str]:
        """Validate module configuration.

        Returns:
            List of warning/error messages. Empty if valid.
        """
        issues = []

        if not self._steps:
            issues.append(
                f"Module '{self.name}' has no steps registered - module is empty"
            )

        return issues

    def __len__(self) -> int:
        return len(self._steps)

    def __repr__(self) -> str:
        return f"Module(name={self.name}, steps={len(self._steps)})"
