# -*- encoding: utf-8 -*-
"""
tests.acdc.test_registring module

Tests for keri.acdc.registring: the two symbols the bakobo fork carries ahead of
upstream -- vetRegistries (parallel-registry equivocation) and Rever (the
RegBaser ingest shell).

Everything these build on is tested in tests.acdc.test_regeventing, which is the
upstream home of the vet* verification core.  The builders and fixtures are
imported from there rather than duplicated, so a change to the shared material
cannot leave these two rows testing something else.  V17 is a row of the approved
test catalogue (V1..V23); the rever_* rows cover the ingest shell.
"""

import pytest

from keri import kering
from keri import Vrsn_2_0
from keri.acdc import regcept
from keri.acdc.registring import Rever, vetRegistries
from keri.acdc.regbasing import RegBaser
from keri.app import habbing
from keri.db import openLMDB

from .test_regeventing import (STAMP0, STAMP1, STAMP2, STAMP3, anchor,
                               makeAcdc, makeRegistry, makeUpdate, openIssuer,
                               remake)


def test_V17_parallel_registries_conflict_refused():
    """V17: evidence containing two registries by one issuer, both committing
    td = the same ACDC with disagreeing states, is refused as a conflict --
    parallel-registry equivocation is duplicity one level up."""
    with openIssuer("v17") as (hby, hab):
        acdcX = makeAcdc(hab, regid=None)

        ripA = makeRegistry(hab, stamp=STAMP0)
        blindA, bupA = makeUpdate(ripA.said, ripA.said, acdcX.said, 'issued',
                                  sn=1, stamp=STAMP1)
        anchor(hab, bupA)

        ripB = makeRegistry(hab, stamp=STAMP1)
        blindB, bupB = makeUpdate(ripB.said, ripB.said, acdcX.said, 'revoked',
                                  sn=1, stamp=STAMP2)
        anchor(hab, bupB)

        evidences = [(ripA, [bupA], blindA), (ripB, [bupB], blindB)]
        for order in (evidences, list(reversed(evidences))):
            with pytest.raises(kering.ConflictingRegistriesError):
                vetRegistries(acdc=acdcX, evidences=order, db=hby.db)

        # a single registry committing the ACDC passes through vetRegistries
        recs = vetRegistries(acdc=acdcX, evidences=[(ripA, [bupA], blindA)],
                             db=hby.db)
        assert len(recs) == 1
        assert recs[0].state == 'issued'
        assert recs[0].binding == 'oneway'


# ---------------------------------------------------------------------------
# The ingest shell: Rever over RegBaser
# ---------------------------------------------------------------------------

def test_rever_ingest_and_acceptance():
    """The ingest node writes evts/ancs and commits tels/heads acceptance
    markers only after full verification."""
    with openIssuer("shell1") as (hby, hab), \
            openLMDB(cls=RegBaser, name="shell1", temp=True) as reger:
        rever = Rever(reger=reger, db=hby.db)
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, bup1 = makeUpdate(ripper.said, ripper.said, acdc.said, 'issued',
                             sn=1, stamp=STAMP1)
        anchor(hab, bup1)
        regid = ripper.said

        rever.processEvent(ripper)
        assert reger.evts.get(keys=ripper.said).said == ripper.said
        number, diger = reger.ancs.get(keys=ripper.said)
        assert hby.db.kels.getLast(keys=hab.pre, on=number.num) is not None
        assert reger.tels.get(keys=regid, on=0).qb64 == ripper.said
        assert reger.heads.get(keys=regid).qb64 == ripper.said

        rever.processEvent(bup1)
        assert reger.tels.get(keys=regid, on=1).qb64 == bup1.said
        assert reger.heads.get(keys=regid).qb64 == bup1.said
        assert reger.maes.cntAll() == 0
        assert reger.ooes.cntAll() == 0

        # reprocessing accepted events is idempotent
        rever.processEvent(ripper)
        rever.processEvent(bup1)
        assert reger.heads.get(keys=regid).qb64 == bup1.said


def test_rever_missing_anchor_escrow_and_drain():
    """An event whose KEL anchor is missing lands in maes (no acceptance
    marker); the drain accepts it once the anchor appears."""
    with openIssuer("shell2") as (hby, hab), \
            openLMDB(cls=RegBaser, name="shell2", temp=True) as reger:
        rever = Rever(reger=reger, db=hby.db)
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, bup1 = makeUpdate(ripper.said, ripper.said, acdc.said, 'issued',
                             sn=1, stamp=STAMP1)
        regid = ripper.said
        rever.processEvent(ripper)

        with pytest.raises(kering.MissingAnchorError):
            rever.processEvent(bup1)  # not yet anchored
        assert reger.evts.get(keys=bup1.said) is not None  # body retained
        assert reger.tels.get(keys=regid, on=1) is None  # but not accepted
        assert reger.heads.get(keys=regid).qb64 == ripper.said
        assert reger.maes.cnt(keys=regid, on=1) == 1

        rever.processEscrowMissingAnchors()  # nothing new: stays escrowed
        assert reger.maes.cnt(keys=regid, on=1) == 1

        anchor(hab, bup1)  # new KEL material arrives
        rever.processEscrowMissingAnchors()
        assert reger.tels.get(keys=regid, on=1).qb64 == bup1.said
        assert reger.heads.get(keys=regid).qb64 == bup1.said
        assert reger.maes.cntAll() == 0


def test_rever_out_of_order_escrow_and_drain():
    """An event arriving before its prior lands in ooes; the drain accepts it
    once the prior is accepted."""
    with openIssuer("shell3") as (hby, hab), \
            openLMDB(cls=RegBaser, name="shell3", temp=True) as reger:
        rever = Rever(reger=reger, db=hby.db)
        ripper = makeRegistry(hab)
        acdc = makeAcdc(hab, regid=ripper.said)
        _, bup1 = makeUpdate(ripper.said, ripper.said, acdc.said, 'issued',
                             sn=1, stamp=STAMP1)
        anchor(hab, bup1)
        _, bup2 = makeUpdate(ripper.said, bup1.said, acdc.said, 'revoked',
                             sn=2, stamp=STAMP2)
        anchor(hab, bup2)
        regid = ripper.said

        # update before its registry inception
        with pytest.raises(kering.OutOfOrderError):
            rever.processEvent(bup1)
        assert reger.ooes.cnt(keys=regid, on=1) == 1

        rever.processEvent(ripper)

        # update beyond head + 1: out of order on a stream, not a refusal
        # (the party-side core refuses the same shape as a gap, V4)
        with pytest.raises(kering.OutOfOrderError):
            rever.processEvent(bup2)
        assert reger.ooes.cnt(keys=regid, on=2) == 1

        rever.processEscrowOutOfOrders()
        assert reger.tels.get(keys=regid, on=1).qb64 == bup1.said
        assert reger.tels.get(keys=regid, on=2).qb64 == bup2.said
        assert reger.heads.get(keys=regid).qb64 == bup2.said
        assert reger.ooes.cntAll() == 0


def test_rever_refusals():
    """Refusals are named and leave no acceptance markers: stranger-KEL
    anchors, malformed rips, broken prior digests, equal-n duplicity."""
    with habbing.openHby(name="shell4", temp=True, version=Vrsn_2_0) as hby, \
            openLMDB(cls=RegBaser, name="shell4", temp=True) as reger:
        issuer = hby.makeHab(name="issuer", version=Vrsn_2_0)
        stranger = hby.makeHab(name="stranger", version=Vrsn_2_0)
        rever = Rever(reger=reger, db=hby.db)

        # a rip whose n is not "0"
        crooked = remake(regcept(israid=issuer.pre, stamp=STAMP0), n='1')
        anchor(issuer, crooked)
        with pytest.raises(kering.MissequenceError):
            rever.processEvent(crooked)
        assert reger.tels.get(keys=crooked.said, on=1) is None

        # a rip anchored only in a stranger's KEL
        endorsed = regcept(israid=issuer.pre, stamp=STAMP1)
        anchor(stranger, endorsed)
        with pytest.raises(kering.MisanchorError):
            rever.processEvent(endorsed)
        assert reger.tels.get(keys=endorsed.said, on=0) is None
        assert reger.heads.get(keys=endorsed.said) is None

        # a healthy registry to break updates against
        ripper = makeRegistry(issuer)
        acdc = makeAcdc(issuer, regid=ripper.said)
        regid = ripper.said
        rever.processEvent(ripper)
        _, bup1 = makeUpdate(regid, ripper.said, acdc.said, 'issued', sn=1,
                             stamp=STAMP1)
        anchor(issuer, bup1)
        rever.processEvent(bup1)

        # an update at head + 1 whose p does not match the head
        _, crooked = makeUpdate(regid, acdc.said, acdc.said, 'revoked', sn=2,
                                stamp=STAMP2)
        anchor(issuer, crooked)
        with pytest.raises(kering.MisdigestError):
            rever.processEvent(crooked)
        assert reger.tels.get(keys=regid, on=2) is None

        # an anchored second event at an already-accepted n: duplicity
        _, fork = makeUpdate(regid, ripper.said, acdc.said, 'revoked', sn=1,
                             stamp=STAMP3)
        anchor(issuer, fork)
        with pytest.raises(kering.DuplicitousRegistryError):
            rever.processEvent(fork)
        assert reger.tels.get(keys=regid, on=1).qb64 == bup1.said  # unmoved


if __name__ == "__main__":
    test_V17_parallel_registries_conflict_refused()
    test_rever_ingest_and_acceptance()
    test_rever_missing_anchor_escrow_and_drain()
    test_rever_out_of_order_escrow_and_drain()
    test_rever_refusals()
