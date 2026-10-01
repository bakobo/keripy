# -*- encoding: utf-8 -*-
"""
tests.core.test_ld_escrow module

Regression test for the KEL likely-duplicitous escrow.

A duplicitous KEL event (a second, different event at an already-accepted sn
that is not a valid recovery) must route through Kevery.escrowLDEvent, land in
the .ldes escrow, and raise LikelyDuplicitousError. The escrow write and the
escrow reader (Kevery.processEscrowDuplicitous) must agree on the key form, so
the escrowed event round-trips through db.ldes.getAllItemIter.

This exercises the Kevery/KEL path specifically: the pre-existing
LikelyDuplicitousError tests live in tests/vdr/test_eventing.py and drive the
TEL/Tevery path, which raises without ever touching the .ldes escrow — so they
did not cover escrowLDEvent, and a rename of the escrow write API went unnoticed.

The remaining tests cover signature verification before escrow. A Validator
that receives a key event without at least one verifiable Controller signature
MUST drop it rather than escrow it (KERI spec, Indexed signatures). For a
conflicting rotation the signing keys must also be committed to by the prior
next key digests, since anyone can sign a rotation with fresh keys.
"""

from keri.kering import (Vrsn_1_0, Kinds, LikelyDuplicitousError,
                         ValidationError)
from keri.core import (Salter, Diger, Kevery, MtrDex, incept, interact,
                       rotate)
from keri.db import openDB

import pytest


def test_kel_likely_duplicitous_escrow():
    """A duplicitous KEL event is escrowed in .ldes and raises LikelyDuplicitousError."""
    kwa = dict(version=Vrsn_1_0, kind=Kinds.json)
    signers = Salter(raw=b"ABCDEFGH01234567").signers(count=8, path='ld', temp=True)

    with openDB(name="dup") as db:
        kevery = Kevery(db=db, lax=False, local=True)

        # icp@0
        icp = incept(keys=[signers[0].verfer.qb64],
                     ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **kwa)
        kevery.processEvent(serder=icp, sigers=[signers[0].sign(icp.raw, index=0)])
        pre = icp.pre
        assert pre in kevery.kevers  # accepted

        # ixn@1 (in order) — accepted, advances sn to 1
        ixn = interact(pre=pre, dig=icp.said, sn=1, **kwa)
        kevery.processEvent(serder=ixn, sigers=[signers[0].sign(ixn.raw, index=0)])
        assert kevery.kevers[pre].sn == 1

        # ixn@1' — a DIFFERENT event at the already-accepted sn=1, same prior,
        # extra anchor so its SAID differs. Not a recovery (ixn cannot supersede),
        # so it is duplicitous.
        dup = interact(pre=pre, dig=icp.said, sn=1,
                       data=[{"d": "EAduplicitousfork0000000000000000000000000000"}], **kwa)
        assert dup.said != ixn.said

        with pytest.raises(LikelyDuplicitousError):
            kevery.processEvent(serder=dup, sigers=[signers[0].sign(dup.raw, index=0)])

        # The duplicitous event must be captured in the .ldes escrow, readable via
        # the same iterator Kevery.processEscrowDuplicitous walks — same key form
        # (keys=pre, on=sn) the reader and the sibling .ooes escrow use.
        escrowed = [((p.decode() if isinstance(p, (bytes, bytearray)) else p),
                     sn,
                     (edig.decode() if isinstance(edig, (bytes, bytearray)) else edig))
                    for (p,), sn, edig in db.ldes.getAllItemIter(keys=b'')]
        assert (pre, 1, dup.said) in escrowed, \
            f"duplicitous event not round-tripped through .ldes; got {escrowed}"

        # Drive the reader (processEscrowDuplicitous) on the now-live path: it must
        # walk the escrow with the same key form (keys=pre, on=sn) without crashing.
        # The event is still duplicitous, so the reader re-raises LikelyDuplicitousError
        # internally and keeps the entry escrowed rather than removing it.
        kevery.processEscrowDuplicitous()
        still = [((p.decode() if isinstance(p, (bytes, bytearray)) else p),
                  sn,
                  (edig.decode() if isinstance(edig, (bytes, bytearray)) else edig))
                 for (p,), sn, edig in db.ldes.getAllItemIter(keys=b'')]
        assert (pre, 1, dup.said) in still, \
            f"reader did not round-trip the escrow key form; got {still}"


def _escrowed(db):
    """Returns list of (pre, sn, said) triples in the .ldes escrow."""
    return [((p.decode() if isinstance(p, (bytes, bytearray)) else p),
             sn,
             (edig.decode() if isinstance(edig, (bytes, bytearray)) else edig))
            for (p,), sn, edig in db.ldes.getAllItemIter(keys=b'')]


def _assertDropped(kevery, db, serder, sigers):
    """Processing serder with sigers is rejected as invalid, not escrowed as
    likely duplicitous, and leaves nothing stored under its SAID."""
    with pytest.raises(ValidationError) as ex:
        kevery.processEvent(serder=serder, sigers=sigers)
    assert not isinstance(ex.value, LikelyDuplicitousError)

    assert (serder.pre, serder.sn, serder.said) not in _escrowed(db)
    dgkey = (serder.preb, serder.saidb)
    assert db.evts.get(keys=dgkey) is None
    assert not db.sigs.get(keys=dgkey)
    assert db.dtss.get(keys=dgkey) is None
    assert db.esrs.get(keys=dgkey) is None


def _assertEscrowed(kevery, db, serder, sigers):
    """Processing serder with sigers escrows it as likely duplicitous."""
    with pytest.raises(LikelyDuplicitousError):
        kevery.processEvent(serder=serder, sigers=sigers)
    assert (serder.pre, serder.sn, serder.said) in _escrowed(db)


def test_ld_escrow_drops_conflicting_ixn_with_bad_sig():
    """A conflicting ixn without a verifiable controller signature is dropped,
    and one signed by the key in force before its sn is escrowed."""
    kwa = dict(version=Vrsn_1_0, kind=Kinds.json)
    signers = Salter(raw=b"ABCDEFGH01234567").signers(count=8, path='ld', temp=True)

    with openDB(name="ldixn") as db:
        kevery = Kevery(db=db, lax=False, local=True)

        icp = incept(keys=[signers[0].verfer.qb64],
                     ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **kwa)
        kevery.processEvent(serder=icp, sigers=[signers[0].sign(icp.raw, index=0)])
        pre = icp.pre

        # rot@1 accepted, so the key in force at sn=1 is no longer the key
        # that signs a conflicting ixn at sn=1
        rot = rotate(pre=pre, keys=[signers[1].verfer.qb64], dig=icp.said, sn=1,
                     ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64], **kwa)
        kevery.processEvent(serder=rot, sigers=[signers[1].sign(rot.raw, index=0)])
        assert kevery.kevers[pre].sn == 1

        dup = interact(pre=pre, dig=icp.said, sn=1, **kwa)

        # signature from a key that is not the controller's
        _assertDropped(kevery, db, dup, [signers[7].sign(dup.raw, index=0)])
        # signature from the post-rotation key, which did not control sn=1's prior
        _assertDropped(kevery, db, dup, [signers[1].sign(dup.raw, index=0)])

        # signed by the key in force before sn=1, so genuinely duplicitous
        _assertEscrowed(kevery, db, dup, [signers[0].sign(dup.raw, index=0)])


def test_ld_escrow_drops_conflicting_icp_with_bad_sig():
    """A conflicting icp for a basic prefix without a verifiable controller
    signature is dropped; one signed by the prefix's own key is escrowed."""
    kwa = dict(version=Vrsn_1_0, kind=Kinds.json)
    signers = Salter(raw=b"ABCDEFGH01234567").signers(count=8, path='ld', temp=True)

    with openDB(name="ldicp") as db:
        kevery = Kevery(db=db, lax=False, local=True)

        # basic (non self-addressing) transferable prefix, so a different icp
        # with the same prefix can exist
        icp = incept(keys=[signers[0].verfer.qb64], code=MtrDex.Ed25519,
                     ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **kwa)
        kevery.processEvent(serder=icp, sigers=[signers[0].sign(icp.raw, index=0)])
        pre = icp.pre
        assert pre == signers[0].verfer.qb64

        dup = incept(keys=[signers[0].verfer.qb64], code=MtrDex.Ed25519,
                     ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64], **kwa)
        assert dup.pre == pre and dup.said != icp.said

        _assertDropped(kevery, db, dup, [signers[7].sign(dup.raw, index=0)])
        _assertEscrowed(kevery, db, dup, [signers[0].sign(dup.raw, index=0)])


def test_ld_escrow_drops_conflicting_rot_with_uncommitted_keys():
    """A conflicting rot signed validly by keys the prior next digests do not
    commit to is dropped; one signed by the committed next key is escrowed."""
    kwa = dict(version=Vrsn_1_0, kind=Kinds.json)
    signers = Salter(raw=b"ABCDEFGH01234567").signers(count=8, path='ld', temp=True)

    with openDB(name="ldrot") as db:
        kevery = Kevery(db=db, lax=False, local=True)

        icp = incept(keys=[signers[0].verfer.qb64],
                     ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **kwa)
        kevery.processEvent(serder=icp, sigers=[signers[0].sign(icp.raw, index=0)])
        pre = icp.pre

        rot = rotate(pre=pre, keys=[signers[1].verfer.qb64], dig=icp.said, sn=1,
                     ndigs=[Diger(ser=signers[2].verfer.qb64b).qb64], **kwa)
        kevery.processEvent(serder=rot, sigers=[signers[1].sign(rot.raw, index=0)])
        assert kevery.kevers[pre].sn == 1

        # fresh keys the sender controls; the signature verifies against the
        # event's own key but icp's next digest does not commit to that key
        forged = rotate(pre=pre, keys=[signers[6].verfer.qb64], dig=icp.said, sn=1,
                        ndigs=[Diger(ser=signers[7].verfer.qb64b).qb64], **kwa)
        _assertDropped(kevery, db, forged, [signers[6].sign(forged.raw, index=0)])

        # the committed next key signing a different rotation is duplicitous
        dup = rotate(pre=pre, keys=[signers[1].verfer.qb64], dig=icp.said, sn=1,
                     ndigs=[Diger(ser=signers[3].verfer.qb64b).qb64], **kwa)
        _assertEscrowed(kevery, db, dup, [signers[1].sign(dup.raw, index=0)])


def test_ld_escrow_processor_drops_unverifiable_entry():
    """An escrowed entry without a verifiable controller signature, as written
    before signatures were checked, is removed by processEscrowDuplicitous
    rather than resurrected."""
    kwa = dict(version=Vrsn_1_0, kind=Kinds.json)
    signers = Salter(raw=b"ABCDEFGH01234567").signers(count=8, path='ld', temp=True)

    with openDB(name="ldproc") as db:
        kevery = Kevery(db=db, lax=False, local=True)

        icp = incept(keys=[signers[0].verfer.qb64],
                     ndigs=[Diger(ser=signers[1].verfer.qb64b).qb64], **kwa)
        kevery.processEvent(serder=icp, sigers=[signers[0].sign(icp.raw, index=0)])
        pre = icp.pre
        ixn = interact(pre=pre, dig=icp.said, sn=1, **kwa)
        kevery.processEvent(serder=ixn, sigers=[signers[0].sign(ixn.raw, index=0)])

        bad = interact(pre=pre, dig=icp.said, sn=1,
                       data=[{"d": "EAduplicitousfork0000000000000000000000000000"}], **kwa)
        good = interact(pre=pre, dig=icp.said, sn=1,
                        data=[{"d": "EAduplicitousfork1111111111111111111111111111"}], **kwa)

        # write the unverifiable entry straight into the escrow
        kevery.escrowLDEvent(serder=bad, sigers=[signers[7].sign(bad.raw, index=0)])
        _assertEscrowed(kevery, db, good, [signers[0].sign(good.raw, index=0)])
        assert (pre, 1, bad.said) in _escrowed(db)

        kevery.processEscrowDuplicitous()
        escrowed = _escrowed(db)
        assert (pre, 1, bad.said) not in escrowed
        assert (pre, 1, good.said) in escrowed
