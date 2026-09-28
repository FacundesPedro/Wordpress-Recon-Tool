# recon_wp/base/scheduler.py
"""Dependency-aware step scheduler.

WHAT: Builds a small DAG from step relations declared on step classes
      (``requires`` / ``provides`` / ``depends_on``) and runs the ready nodes
      concurrently.
HOW:  ``build_graph`` resolves producers for each ``requires`` key and wires
      edges, reporting unknown producers and cycles. ``run_graph`` launches
      nodes whose dependencies have completed, bounded by whatever concurrency
      the caller enforces inside ``run_node``.
WHY:  Steps within a risk tier can run in parallel, and a consumer can wait for
      a producer to publish a shared artifact instead of repeating an HTTP
      request (see core/scan_context.py).

Artifacts listed in ``LAZY_ARTIFACTS`` are resolved by ``WebArtifacts`` on
demand, so a step may ``requires`` them without a dedicated producer step.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Any

from core.scan_context import LAZY_ARTIFACTS

# Backwards-compatible alias (older name for the lazy artifact set).
LAZY_ARTIFACTS_SET = LAZY_ARTIFACTS


@dataclass
class StepNode:
    """One step in the execution graph."""

    step_class: type
    module_name: str
    provides: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()

    # Runtime graph state
    deps: list[StepNode] = field(default_factory=list)
    dependents: list[StepNode] = field(default_factory=list)
    indegree: int = 0

    @property
    def name(self) -> str:
        return self.step_class.__name__


@dataclass
class StepGraph:
    """Result of ``build_graph``."""

    nodes: list[StepNode]
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _dedupe(items: list[StepNode]) -> list[StepNode]:
    seen: set[int] = set()
    result: list[StepNode] = []
    for item in items:
        if id(item) not in seen:
            seen.add(id(item))
            result.append(item)
    return result


def build_graph(
    entries: list[tuple[type, str]],
) -> StepGraph:
    """Build a step DAG.

    Args:
        entries: ``(step_class, module_name)`` pairs. Module names are used for
            logging and per-module concurrency; steps keep their own module
            label for findings.

    Returns:
        A :class:`StepGraph` with wired nodes plus any warnings/errors.
    """
    warnings: list[str] = []
    errors: list[str] = []

    nodes: list[StepNode] = []
    for step_class, module_name in entries:
        nodes.append(
            StepNode(
                step_class=step_class,
                module_name=module_name,
                provides=tuple(getattr(step_class, "provides", ()) or ()),
                requires=tuple(getattr(step_class, "requires", ()) or ()),
                depends_on=tuple(getattr(step_class, "depends_on", ()) or ()),
            )
        )

    by_name: dict[str, StepNode] = {}
    for node in nodes:
        if node.name in by_name:
            warnings.append(f"duplicate step class '{node.name}' in graph")
        by_name.setdefault(node.name, node)

    providers: dict[str, StepNode] = {}
    for node in nodes:
        for key in node.provides:
            if key in providers:
                warnings.append(
                    f"artifact '{key}' provided by multiple steps "
                    f"({providers[key].name}, {node.name}); using the latter"
                )
            providers[key] = node

    for node in nodes:
        deps: list[StepNode] = []
        for dep_name in node.depends_on:
            target = by_name.get(dep_name)
            if target is None:
                warnings.append(
                    f"{node.name} depends on unknown step '{dep_name}'"
                )
            elif target is node:
                warnings.append(f"{node.name} depends on itself")
            else:
                deps.append(target)

        for key in node.requires:
            provider = providers.get(key)
            if provider is None:
                if key not in LAZY_ARTIFACTS:
                    warnings.append(
                        f"{node.name} requires '{key}' but no step provides it"
                    )
            elif provider is node:
                warnings.append(f"{node.name} both provides and requires '{key}'")
            else:
                deps.append(provider)

        node.deps = _dedupe(deps)

    _wire(nodes)
    _resolve_cycles(nodes, warnings)

    return StepGraph(nodes=nodes, warnings=warnings, errors=errors)


def _wire(nodes: list[StepNode]) -> None:
    """Recompute indegree/dependents from ``deps``."""
    for node in nodes:
        node.indegree = len(node.deps)
        node.dependents = []
    for node in nodes:
        for dep in node.deps:
            dep.dependents.append(node)


def _resolve_cycles(nodes: list[StepNode], warnings: list[str]) -> None:
    """Detect cycles (Kahn). Cyclic nodes run anyway, in arbitrary order."""
    indegree = {id(n): n.indegree for n in nodes}
    ready = [n for n in nodes if indegree[id(n)] == 0]
    processed = 0
    while ready:
        node = ready.pop()
        processed += 1
        for dep in node.dependents:
            indegree[id(dep)] -= 1
            if indegree[id(dep)] == 0:
                ready.append(dep)

    if processed < len(nodes):
        cyclic = [n for n in nodes if indegree[id(n)] > 0]
        warnings.append(
            "dependency cycle detected among: "
            + ", ".join(n.name for n in cyclic)
            + "; running in arbitrary order"
        )
        for node in cyclic:
            node.deps = []
        _wire(nodes)


async def run_graph(
    nodes: list[StepNode],
    run_node: Callable[[StepNode], Any],
    should_skip: Callable[[StepNode], bool] | None = None,
    on_skip: Callable[[StepNode], None] | None = None,
) -> None:
    """Execute nodes as their dependencies complete.

    Args:
        nodes: Wired nodes from :func:`build_graph`.
        run_node: Async callable that runs one node. It must not raise; the
            runner records its own errors and marks missing artifacts.
        should_skip: Optional predicate; when true the node is not run.
        on_skip: Optional callback invoked for skipped nodes (e.g. to mark
            their artifacts missing).
    """
    remaining = len(nodes)
    ready = [n for n in nodes if n.indegree == 0]
    pending: dict[asyncio.Task, StepNode] = {}

    def complete(node: StepNode) -> None:
        nonlocal remaining
        remaining -= 1
        for dependent in node.dependents:
            dependent.indegree -= 1
            if dependent.indegree == 0:
                ready.append(dependent)

    while remaining > 0:
        while ready:
            node = ready.pop(0)
            if should_skip is not None and should_skip(node):
                if on_skip is not None:
                    on_skip(node)
                complete(node)
                continue
            task = asyncio.create_task(run_node(node))
            pending[task] = node

        if not pending:
            # No runnable nodes left (a cycle slipped through) — stop.
            break

        done, _ = await asyncio.wait(
            set(pending), return_when=asyncio.FIRST_COMPLETED
        )
        for task in done:
            node = pending.pop(task)
            # ``run_node`` is expected to swallow errors; guard anyway so one
            # bad node cannot deadlock the graph.
            with suppress(Exception):
                task.result()
            complete(node)
