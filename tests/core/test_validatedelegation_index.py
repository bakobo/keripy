# -*- encoding: utf-8 -*-
"""Regression tests for the delegation-seal lookup in Kever.validateDelegation().

In the superseding drt-of-drt recovery branch (src/keri/core/eventing.py:3434,
3439) the delegating event's seal list is searched with ``list.index()`` under
a source comment reading ``# assumes index can't be None``. When a crafted
delegating event does not carry the expected delegation seal, ``list.index()``
raises a raw ``ValueError`` that escapes the keri.kering hierarchy.

This is a stub-level test: constructing full superseding drt-of-drt delegation
state (two delegating events at the same SAID with mismatched anchoring seals)
is impractical, so a minimal crafted ``self`` and event serders drive
Kever.validateDelegation's own control flow to the seal lookup. The lookup
logic under test is keripy's own unmodified code.
"""
from types import SimpleNamespace

import pytest

from keri.core.coring import Diger, Number
from keri.core.eventing import Kever
from keri.core.structing import SealEvent
from keri.kering import Ilks, ValidationError


DELPRE = "Edelegator_prefix_00000000000000000000000000"


def _make_state(bossnSeals, bossoSeals):
    """Build the minimal (self, serder) needed to drive validateDelegation into
    the superseding-recovery seal lookup at eventing.py:3434.

    bossnSeals / bossoSeals are the raw seal dict lists carried by the new and
    original delegating events respectively.
    """
    # Received (new) delegated event: a drt at the same sn as the last accepted
    # event, so the non-superseding fast paths are skipped.
    serder = SimpleNamespace(
        pre="Edelegate_prefix_0000000000000000000000000000",
        snh="5",
        sn=5,
        said="Enew_delegate_event_said_000000000000000000",
        ilk=Ilks.drt,
        sner=SimpleNamespace(num=5),
        pretty=lambda: "",
    )

    # A valid Diger qb64 is required because validateDelegation reconstructs a
    # Diger from the delegating event's said.
    delSaid = Diger(ser=b"delegating-event").qb64

    # New delegating event (bossn) returned by the eager seal lookup.
    bossn = SimpleNamespace(
        sn=3,
        snh="3",
        said=delSaid,
        Ilk=Ilks.drt,
        seals=bossnSeals,
    )

    # Original delegating event (bosso) returned by fetchDelegatingEvent; same
    # said as bossn so control reaches the seal-index comparison.
    bosso = SimpleNamespace(
        sn=3,
        said=delSaid,
        Ilk=Ilks.drt,
        seals=bossoSeals,
        pre="Edelegate_prefix_0000000000000000000000000000",
        snh="4",
        pretty=lambda: "",
    )

    fakeSelf = SimpleNamespace(
        locallyOwned=lambda: False,
        locallyMembered=lambda: False,
        locallyWitnessed=lambda wits: False,
        kevers={DELPRE: SimpleNamespace(doNotDelegate=False)},
        db=SimpleNamespace(
            fetchLastSealingEventByEventSeal=lambda pre, seal: bossn,
        ),
        escrowPDEvent=lambda **k: None,
        fetchDelegatingEvent=lambda delpre, serfo, original, eager: bosso,
        # self is the last accepted event: a drt at the same sn as serder.
        serder=SimpleNamespace(
            pre="Edelegate_prefix_0000000000000000000000000000",
            snh="4",
            said="Eoriginal_delegate_event_said_0000000000000",
            pretty=lambda: "",
        ),
        sner=SimpleNamespace(num=5),
        ilk=Ilks.drt,
    )
    return fakeSelf, serder


def _call(fakeSelf, serder):
    return Kever.validateDelegation(
        fakeSelf, serder, [], [], [], DELPRE,
        delsner=None, delsger=None, eager=True, local=True)


def test_validatedelegation_missing_seal_raises_keri_error():
    """Red->green: when the delegating event lacks the expected delegation
    seal, the lookup must raise a keri.kering error, not a raw ValueError."""
    # bossn carries a well-formed seal that is NOT the delegate's seal.
    bogus = {"i": "Esome_other_prefix", "s": "0", "d": "Esome_other_said"}
    fakeSelf, serder = _make_state(bossnSeals=[bogus], bossoSeals=[bogus])
    with pytest.raises(ValidationError):
        _call(fakeSelf, serder)


def test_validatedelegation_present_seal_unchanged():
    """Narrowing proof: when both delegating events carry the expected seals,
    the seal lookup succeeds and the superseding-recovery branch returns the
    delegator source tuple -- valid input behaves exactly as before."""
    # Seals matching the delegate's (new) and delegator's (original) events.
    # bossn carries a dummy then the delegate's own seal, so its index (1) is
    # later than the original's (0) -> a valid superseding delegation.
    nseal = {"i": "Edelegate_prefix_0000000000000000000000000000",
             "s": "5",
             "d": "Enew_delegate_event_said_000000000000000000"}
    dummy = {"i": "Efiller_prefix", "s": "0", "d": "Efiller_said"}
    oseal = {"i": "Edelegate_prefix_0000000000000000000000000000",
             "s": "4",
             "d": "Eoriginal_delegate_event_said_0000000000000"}
    fakeSelf, serder = _make_state(bossnSeals=[dummy, nseal], bossoSeals=[oseal])

    result = _call(fakeSelf, serder)
    assert result is not None
    assert len(result) == 2  # (delsner, delsger) delegator source tuple
