# -*- encoding: utf-8 -*-
"""Regression tests for unbounded recursion in Reger.sources().

``Reger.sources()`` (src/keri/vdr/eventing.py:2569) recurses on each edge's
target credential. On base there is no cycle guard and no depth cap, so a
crafted credential drives keripy's own recursion driver into a raw
``RecursionError``. A path-scoped ancestor set (the first hardening attempt)
stops the RecursionError but permits *exponential re-expansion*: a source
reachable by many edges is fetched once per path, so a shallow acyclic chain
whose nodes each carry two edges to the next node fans out to 2**depth fetches
and hangs the Doist -- worse than the crash it replaced.

The correct fix is a walk-global visited-set keyed by SAID (modelled on
``IpexHandler._walkGraph``'s ``seen`` at src/keri/acdc/ipexing.py:655): a source
reached by multiple edges is fetched and returned exactly once, so total work
is linear in the number of distinct sources. A depth cap remains as a backstop.

These are stub-level tests: constructing a full habitat + registry + cyclically
issued ACDCs is impractical, so (following probe_part_b_recursion.py) only the
leaf data-fetch (``cloneCred``) and the serializer (``coreMessagize``) are
stubbed. The recursion control flow under test is keripy's own unmodified
``Reger.sources`` code.
"""
import pytest

import keri.vdr.eventing as ve
from keri.kering import ValidationError
from keri.vdr.eventing import Reger


class FakeCreder:
    """Minimal stand-in for a SerderACDC carrying outgoing edges.

    ``targets`` is a list of far-node SAIDs; each becomes one ``e`` entry, so a
    list with a repeated SAID models several edges pointing at the same node.
    """

    def __init__(self, said, targets):
        self.said = said
        # sources() reads creder.edge -> {key: {"n": said}}; key 'd' is skipped.
        self.edge = {"d": "self"}
        for i, target in enumerate(targets):
            self.edge[f"e{i}"] = {"n": target}
        self.size = 0
        self.pvrsn = None
        self.raw = b""


def _stub_serializer(monkeypatch):
    """Isolate the recursion by neutralizing serialization."""
    monkeypatch.setattr(ve, "coreMessagize", lambda *a, **k: b"")


def test_sources_no_exponential_reexpansion(monkeypatch):
    """B-49 red->green (the HANG, not just a cycle): an ACYCLIC chain whose
    every node carries two edges to the next node.

    Unguarded and path-scoped, this fans out to 2**depth fetches (depth 40 ->
    ~1e12) and hangs. With a walk-global visited-set the total fetch count is
    linear in the number of distinct source SAIDs. We bound the run with an
    explicit fetch-count cap so base doesn't actually hang the test: on base the
    cap trips (RuntimeError); after the fix cloneCred is called exactly once per
    distinct source.
    """
    _stub_serializer(monkeypatch)
    reger = Reger(reopen=False)

    depth = 40
    # n0 -> n1 -> ... -> n{depth}; every non-leaf node has TWO edges to next.
    calls = {"n": 0}
    FETCH_CAP = 1000  # far above the linear count (=depth), far below 2**depth

    def clone(said):
        calls["n"] += 1
        if calls["n"] > FETCH_CAP:
            raise RuntimeError("fetch explosion: exponential re-expansion")
        idx = int(said[1:])
        nxt = f"n{idx + 1}"
        targets = [nxt, nxt] if idx + 1 <= depth else []
        return FakeCreder(said, targets), "Epre", "0", "Esaid"

    reger.cloneCred = clone

    root = FakeCreder("n0", ["n1", "n1"])
    result = reger.sources(reger, root)

    # Exactly one fetch per distinct source SAID (n1..n{depth}) -- linear.
    assert calls["n"] == depth
    saids = [screder.said for screder, _atc in result]
    assert saids == [f"n{i}" for i in range(1, depth + 1)]


def test_sources_diamond_returns_shared_node_once(monkeypatch):
    """Valid-input green: a diamond (A->B, A->C, B->D, C->D) returns D exactly
    once under visited-set semantics."""
    _stub_serializer(monkeypatch)
    reger = Reger(reopen=False)

    graph = {
        "B": FakeCreder("B", ["D"]),
        "C": FakeCreder("C", ["D"]),
        "D": FakeCreder("D", []),
    }
    reger.cloneCred = lambda said: (graph[said], "Epre", "0", "Esaid")

    root = FakeCreder("A", ["B", "C"])
    result = reger.sources(reger, root)
    saids = [screder.said for screder, _atc in result]

    assert saids.count("D") == 1
    # BFS/DFS order: B, then D (via B), then C; D not re-fetched via C.
    assert saids == ["B", "D", "C"]


def test_sources_linear_chain_in_order(monkeypatch):
    """Valid-input green: a plain linear chain returns all sources in order."""
    _stub_serializer(monkeypatch)
    reger = Reger(reopen=False)

    graph = {
        "s1": FakeCreder("s1", ["s2"]),
        "s2": FakeCreder("s2", ["s3"]),
        "s3": FakeCreder("s3", []),
    }
    reger.cloneCred = lambda said: (graph[said], "Epre", "0", "Esaid")

    root = FakeCreder("root", ["s1"])
    result = reger.sources(reger, root)
    saids = [screder.said for screder, _atc in result]

    assert saids == ["s1", "s2", "s3"]


def test_sources_deep_chain_backstop_raises(monkeypatch):
    """Backstop: an acyclic chain deeper than the depth cap raises
    ``ValidationError`` rather than exhausting the stack."""
    _stub_serializer(monkeypatch)
    reger = Reger(reopen=False)

    depth = reger.MaxSourceDepth + 50

    def clone(said):
        idx = int(said[1:])
        nxt = f"n{idx + 1}" if idx + 1 <= depth else None
        targets = [nxt] if nxt is not None else []
        return FakeCreder(said, targets), "Epre", "0", "Esaid"

    reger.cloneCred = clone
    root = FakeCreder("n0", ["n1"])
    with pytest.raises(ValidationError):
        reger.sources(reger, root)
