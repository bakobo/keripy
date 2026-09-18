# -*- encoding: utf-8 -*-
"""
tests.app.test_directing_limits

Regression test for the TCP concurrent-connection cap on Directant: Directant spawned a Reactant per inbound
connection with no upper bound. serviceDo must refuse (close) a new connection once
the number of live Reactants reaches the cap.

The cap must sit BELOW the default per-process fd ceiling (ulimit -n, typically
1024) or EMFILE is hit at the same point and the cap accomplishes little; the
default is a few hundred (256).
"""

from keri.app import Directant
from keri.app import directing


class DummyHab:
    name = "dummy"


class FakeIx:
    def __init__(self):
        self.cutoff = False
        self.tymeout = 0.0
        self.serviced = False

    def serviceSends(self):
        self.serviced = True


class FakeServer:
    def __init__(self, ixes):
        self.ixes = ixes
        self.removed = []

    def wind(self, tymth):
        pass

    def removeIx(self, ca):
        self.removed.append(ca)
        self.ixes.pop(ca, None)


def _cycle(gen):
    next(gen)  # enter context
    next(gen)  # run one service pass over server.ixes


def test_default_cap_below_fd_ceiling():
    """The default cap must be a few hundred -- below the default ulimit -n of
    1024 -- so EMFILE is not reached before the cap engages."""
    assert Directant.MaxTCPConnections == 256
    assert Directant.MaxTCPConnections < 1024


def test_tcp_connection_cap_refuses_over_limit():
    # two existing connections (already have Reactants), plus one new connection
    existing = [("h", 0), ("h", 1)]
    newca = ("h", 2)
    ixes = {ca: FakeIx() for ca in existing + [newca]}
    new_ix = ixes[newca]
    server = FakeServer(ixes)

    d = Directant(hab=DummyHab(), server=server)
    d.MaxTCPConnections = 2
    # pre-seed the two existing connections as live Reactants
    for ca in existing:
        d.rants[ca] = object()

    gen = d.serviceDo()
    _cycle(gen)

    # the new, over-cap connection must be refused: closed, never given a Reactant
    assert newca in server.removed
    assert newca not in d.rants
    assert len(d.rants) == 2
    assert new_ix.serviced is True  # closeConnection flushed then removed it


def test_tcp_connection_cap_accepts_under_limit():
    """A fresh Directant with headroom is not blocked by the cap (pure
    narrowing): the default cap is well above two connections, so the guard
    does not fire below it."""
    d = Directant(hab=DummyHab(), server=FakeServer({}))
    assert d.MaxTCPConnections >= 2
    assert d.atConnectionLimit() is False


if __name__ == "__main__":
    test_default_cap_below_fd_ceiling()
    test_tcp_connection_cap_refuses_over_limit()
    test_tcp_connection_cap_accepts_under_limit()
