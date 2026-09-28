# tests/test_scheduler.py
"""Tests for base/scheduler.py — dependency graph and parallel driver."""

import asyncio

import pytest

from base.scheduler import build_graph, run_graph


class Step:
    """Named step helper for graph tests."""


def make_step(name, provides=(), requires=(), depends_on=(), module="test"):
    return type(
        name,
        (Step,),
        {
            "provides": tuple(provides),
            "requires": tuple(requires),
            "depends_on": tuple(depends_on),
        },
    )


class TestBuildGraph:
    def test_wires_requires_to_producer(self):
        producer = make_step("Producer", provides=("token",))
        consumer = make_step("Consumer", requires=("token",))

        graph = build_graph([(producer, "m"), (consumer, "m")])
        nodes = {n.name: n for n in graph.nodes}

        assert nodes["Consumer"].deps == [nodes["Producer"]]
        assert nodes["Producer"].dependents == [nodes["Consumer"]]
        assert nodes["Consumer"].indegree == 1
        assert graph.warnings == []

    def test_wires_explicit_depends_on(self):
        first = make_step("First")
        second = make_step("Second", depends_on=("First",))

        graph = build_graph([(first, "m"), (second, "m")])
        nodes = {n.name: n for n in graph.nodes}
        assert nodes["Second"].deps == [nodes["First"]]

    def test_lazy_artifact_has_no_edge_or_warning(self):
        consumer = make_step("Consumer", requires=("homepage",))

        graph = build_graph([(consumer, "m")])
        assert graph.nodes[0].deps == []
        assert graph.warnings == []

    def test_missing_producer_warns(self):
        consumer = make_step("Consumer", requires=("nobody_makes_this",))

        graph = build_graph([(consumer, "m")])
        assert any("no step provides it" in w for w in graph.warnings)

    def test_unknown_depends_on_warns(self):
        step = make_step("Step", depends_on=("Ghost",))

        graph = build_graph([(step, "m")])
        assert any("unknown step 'Ghost'" in w for w in graph.warnings)

    def test_duplicate_provider_warns(self):
        a = make_step("A", provides=("x",))
        b = make_step("B", provides=("x",))

        graph = build_graph([(a, "m"), (b, "m")])
        assert any("provided by multiple steps" in w for w in graph.warnings)

    def test_cycle_is_broken_and_warned(self):
        a = make_step("A", requires=("b_key",), provides=("a_key",))
        b = make_step("B", requires=("a_key",), provides=("b_key",))

        graph = build_graph([(a, "m"), (b, "m")])
        assert any("cycle detected" in w for w in graph.warnings)
        assert all(n.indegree == 0 for n in graph.nodes)


class TestRunGraph:
    @pytest.mark.asyncio
    async def test_runs_dependencies_in_order(self):
        order = []
        producer = make_step("Producer", provides=("token",))
        consumer = make_step("Consumer", requires=("token",))
        graph = build_graph([(producer, "m"), (consumer, "m")])

        async def run_node(node):
            order.append(node.name)
            if node.name == "Producer":
                await asyncio.sleep(0.01)

        await run_graph(graph.nodes, run_node)
        assert order == ["Producer", "Consumer"]

    @pytest.mark.asyncio
    async def test_runs_independent_nodes_concurrently(self):
        started = []
        gate = asyncio.Event()

        a = make_step("A")
        b = make_step("B")
        graph = build_graph([(a, "m"), (b, "m")])

        async def run_node(node):
            started.append(node.name)
            if len(started) == 2:
                gate.set()
            # Both must be running before either finishes.
            await asyncio.wait_for(gate.wait(), timeout=1)

        await run_graph(graph.nodes, run_node)
        assert sorted(started) == ["A", "B"]

    @pytest.mark.asyncio
    async def test_should_skip_and_on_skip(self):
        skipped = []
        ran = []

        a = make_step("A", provides=("x",))
        graph = build_graph([(a, "m")])

        async def run_node(node):
            ran.append(node.name)

        await run_graph(
            graph.nodes,
            run_node,
            should_skip=lambda node: True,
            on_skip=lambda node: skipped.append(node.name),
        )
        assert ran == []
        assert skipped == ["A"]

    @pytest.mark.asyncio
    async def test_failing_node_does_not_stall_dependents(self):
        order = []
        producer = make_step("Producer", provides=("token",))
        consumer = make_step("Consumer", requires=("token",))
        graph = build_graph([(producer, "m"), (consumer, "m")])

        async def run_node(node):
            order.append(node.name)
            if node.name == "Producer":
                raise RuntimeError("boom")

        # run_graph must swallow the failure and still release dependents.
        await run_graph(graph.nodes, run_node)
        assert order == ["Producer", "Consumer"]
