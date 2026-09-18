# -*- encoding: utf-8 -*-
"""Regression tests for IpexHandler._evaluateGroupEdge.

``IpexHandler._evaluateGroupEdge`` (src/keri/acdc/ipexing.py:841) recurses over
nested edge-group JSON. On base there is no depth cap, so a crafted grant
carrying deeply nested edge groups drives keripy's own evaluator into a raw
``RecursionError``.

The whole ``_evaluate*`` family signals a malformed shape by RETURNING
``None``/``False``, and the sole caller (src/keri/acdc/ipexing.py:952) does
``if matched is not True: return False`` -- it does not catch exceptions. So the
depth cap must ALSO fail closed by returning ``None``; raising
``ValidationError`` (the first hardening attempt) propagates an exception past a
caller that expects a value, defeating the fail-closed contract. This test pins
the cap to ``return None`` and asserts no exception escapes.

Pure-group nesting never reaches the leaf path, so no DB is required; the
handler is instantiated with stub collaborators it never touches here.
"""
import pytest

from keri.acdc.ipexing import IpexHandler


def _handler():
    """An IpexHandler whose collaborators are unused by _evaluateGroupEdge."""
    return IpexHandler(resource="/ipex/grant", hby=None, notifier=None)


def _nested_group(depth):
    """Build a pure edge-group nested ``depth`` levels deep.

    Each level is a group with one non-reserved child that is itself a group;
    the innermost is an empty group. ``e0`` is not a reserved edge label.
    """
    group = {}
    for _ in range(depth):
        group = {"e0": group}
    return group


def test_group_edge_too_deep_returns_none_not_raise():
    """S8 red->green: an edge group nested far past the cap must FAIL CLOSED by
    returning None, not raise (ValidationError) and not RecursionError. The
    depth (2000) is past both the cap (24) and Python's recursion limit, so on
    base this raises RecursionError."""
    handler = _handler()

    group = _nested_group(2000)

    # Must not raise -- neither RecursionError (base) nor ValidationError (the
    # prior attempt). It returns None so the caller's `matched is not True`
    # branch fails verification closed.
    matched = handler._evaluateGroupEdge(group,
                                         nodes={},
                                         nserder=None,
                                         nested=False,
                                         inheritedSchema=None)
    assert matched is None
    # Caller contract at ipexing.py:952 -- `if matched is not True: return False`.
    assert (matched is not True)


def test_group_edge_at_boundary_returns_none():
    """The cap fires as soon as depth exceeds MaxEdgeGroupDepth; a group just
    past the boundary still fails closed with None and no exception."""
    handler = _handler()

    group = _nested_group(handler.MaxEdgeGroupDepth + 2)
    matched = handler._evaluateGroupEdge(group,
                                         nodes={},
                                         nserder=None,
                                         nested=False,
                                         inheritedSchema=None)
    assert matched is None


def test_group_edge_shallow_valid_unaffected(monkeypatch):
    """Valid-input green: a legitimately shallow nested group (well within the
    cap) still evaluates to its reduced child result -- the cap does not
    interfere with normal edge sections. Leaf evaluation is stubbed to isolate
    the group recursion."""
    handler = _handler()
    monkeypatch.setattr(handler, "_evaluateLeafEdge",
                        lambda group, **kw: True)

    # A 3-level nested group whose innermost child is a leaf ("n" present).
    leaf = {"n": "Esomefarnode"}
    group = {"e0": {"e0": {"e0": leaf}}}

    matched = handler._evaluateGroupEdge(group,
                                         nodes={},
                                         nserder=None,
                                         nested=False,
                                         inheritedSchema=None)
    assert matched is True
