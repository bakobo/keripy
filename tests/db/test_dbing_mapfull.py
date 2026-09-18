# -*- encoding: utf-8 -*-
"""
tests.db.test_dbing_mapfull

Regression test for graceful translation of lmdb.MapFullError.

LMDB raises MapFullError when a write cannot fit in the memory map. Critically,
for realistic small values the error surfaces at COMMIT time -- inside the
``with self.env.begin(...) as txn:`` block's ``__exit__`` -- NOT at the inner
``txn.put()`` call. A try/except wrapped only around ``.put()`` therefore never
sees it, and a raw ``lmdb.MapFullError`` escapes the keri.kering exception
hierarchy and kills the Doist.

These tests fill a deliberately tiny map (1 MiB) with many ~200 B values so the
overflow happens at the commit boundary, the path the prior 16 KiB-value test
(which failed early at mdb_put and was a false green) never exercised. After the
fix, the growth-causing write primitives translate MapFullError to
kering.DatabaseError.
"""

import lmdb
import pytest

from keri.db import dbing
from keri import kering


class TinyMapLMDBer(dbing.LMDBer):
    """LMDBer with a 1 MiB map so a modest number of small values overflow it."""
    MapSize = 1024 * 1024  # 1 MiB


SMALL_VAL = b"x" * 200  # realistic ~200 B event-sized value


def fillUntilFull(writer):
    """Call writer(i) for increasing i until the map overflows.

    Returns the exception that was raised (whatever its type), or fails the
    test if 100k writes complete without overflow (map too big / value too
    small).
    """
    for i in range(100000):
        try:
            writer(i)
        except BaseException as ex:  # capture whatever escapes, raw or translated
            return ex
    pytest.fail("map never filled -- test misconfigured")


def test_putVal_mapfull_at_commit_translates():
    """putVal filling a 1 MiB map with ~200 B values raises kering.DatabaseError.

    On base (no commit-boundary catch) this raises raw lmdb.MapFullError from
    the ``with`` line. After the fix it is translated to kering.DatabaseError.
    """
    with dbing.openLMDB(cls=TinyMapLMDBer) as dber:
        assert dber.MapSize == 1024 * 1024
        db = dber.env.open_db(key=b'mapfull.')

        def writer(i):
            dber.putVal(db, key=b'k.%08d' % i, val=SMALL_VAL)

        ex = fillUntilFull(writer)
        # The raw lmdb error must not escape the keri hierarchy.
        assert not isinstance(ex, lmdb.MapFullError), (
            f"raw lmdb.MapFullError escaped (type={type(ex).__name__}): {ex}")
        assert isinstance(ex, kering.DatabaseError), (
            f"expected kering.DatabaseError, got {type(ex).__name__}: {ex}")


def test_putIoDupVals_mapfull_at_commit_translates():
    """Representative IoDup-family primitive: putIoDupVals (backs floodable
    .ooes/.ldes/.kels escrows) must also translate a small-value commit-time
    MapFullError to kering.DatabaseError.
    """
    with dbing.openLMDB(cls=TinyMapLMDBer) as dber:
        db = dber.env.open_db(key=b'mapfulldup.', dupsort=True)

        def writer(i):
            # distinct key per call so each is a fresh growth-causing write
            dber.putIoDupVals(db, key=b'k.%08d' % i, vals=[SMALL_VAL])

        ex = fillUntilFull(writer)
        assert not isinstance(ex, lmdb.MapFullError), (
            f"raw lmdb.MapFullError escaped (type={type(ex).__name__}): {ex}")
        assert isinstance(ex, kering.DatabaseError), (
            f"expected kering.DatabaseError, got {type(ex).__name__}: {ex}")


def test_valid_small_write_roundtrip_unchanged():
    """Valid writes well below the map size are unaffected by the translation."""
    with dbing.openLMDB(cls=TinyMapLMDBer) as dber:
        db = dber.env.open_db(key=b'ok.')
        assert dber.putVal(db, key=b'a.1', val=b'wow') is True
        assert dber.putVal(db, key=b'a.1', val=b'wow') is False  # no overwrite
        assert bytes(dber.getVal(db, key=b'a.1')) == b'wow'

        dupdb = dber.env.open_db(key=b'okdup.', dupsort=True)
        assert dber.putIoDupVals(dupdb, key=b'b.1', vals=[b'v0', b'v1']) is True
        assert dber.getIoDupVals(dupdb, key=b'b.1') == [b'v0', b'v1']


if __name__ == "__main__":
    test_putVal_mapfull_at_commit_translates()
    test_putIoDupVals_mapfull_at_commit_translates()
    test_valid_small_write_roundtrip_unchanged()
