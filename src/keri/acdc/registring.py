# -*- encoding: utf-8 -*-
"""
keri.acdc.registring module

Bakobo fork delta over keri.acdc.regeventing: the two symbols this fork carries
ahead of upstream.

vetRegistries answers a question vet() cannot: given several registries' (TELs')
evidence against one presented ACDC, do two registries by the same issuer commit
that ACDC with disagreeing states?  That is registry duplicity one level up, and
it is refused in any evidence order.

Rever is the ingest shell: it processes registry event streams into a RegBaser
with missing-anchor (.maes) and out-of-order (.ooes) escrows and drain methods.

Everything these two build on -- the vet* verification core, the anchor search,
the TEL chain rules -- now lives in regeventing.py, which absorbed this module's
core upstream (WebOfTrust/keripy, the rename registring -> regeventing).  This
file is therefore the two-symbol delta its predecessor promised to collapse to.
Fold each symbol into regeventing.py as and when it lands upstream.
"""

from ..kering import (Ilks, ValidationError,
                      MissingAnchorError, OutOfOrderError, MisdigestError,
                      MissequenceError, MisregistryError,
                      DuplicitousRegistryError, ConflictingRegistriesError)
from ..core import Diger, Number, Saider
from .. import help
from .regeventing import (RegStateRecord, _coerce, vet, vetAnchor,
                          vetBindings, vetRip)

logger = help.ogler.getLogger()


def vetRegistries(acdc, evidences, *, db, sources=None):
    """Verify several registries' evidence against one presented ACDC and
    refuse parallel-registry equivocation: two registries by one issuer
    whose verified head states both commit to the ACDC but disagree are
    registry duplicity one level up, in any evidence order.

    Returns:
        records (list[RegStateRecord]): the verified, binding-checked
            records of the registries whose head state commits to the
            presented ACDC (empty when none does)

    Parameters:
        acdc (SerderACDC|bytes): the presented ACDC
        evidences (Iterable): registry evidence sets, each a (rip, updates)
            or (rip, updates, blinder) tuple as vet() takes them
        db (Baser): KEL database the caller has already populated
        sources (Mapping|None): optional anchor-location claims (see vet)

    Raises:
        ConflictingRegistriesError: two registries commit the ACDC with
            disagreeing states (permanent refusal), plus everything vet()
            raises for each evidence set
    """
    serder = _coerce(acdc)
    records = []
    for evidence in evidences:
        if len(evidence) == 3:
            ripe, upds, blinder = evidence
        else:
            ripe, upds = evidence
            blinder = None
        records.append(vet(ripe, upds, db=db, blinder=blinder,
                           sources=sources))

    committed = [record for record in records if record.acdc == serder.said]
    states = {record.state for record in committed}
    if len(committed) > 1 and len(states) > 1:
        raise ConflictingRegistriesError(
            f"Parallel registries "
            f"{[record.regid for record in committed]} of issuer(s) "
            f"{sorted(set(record.issuer for record in committed))} commit "
            f"ACDC {serder.said} with disagreeing states "
            f"{sorted(state or '' for state in states)}: equivocation.")

    out = []
    for record in committed:
        binding = vetBindings(acdc=serder, regid=record.regid,
                              issuer=record.issuer, td=record.acdc)
        out.append(record._replace(binding=binding))
    return out


class Rever:
    """Rever is a registry (TEL) event verifier and ingest node for ACDC v2
    state registries.  It processes a stream of rip/bup events into a
    RegBaser: event bodies into .evts, verified KEL anchor couples into
    .ancs, and the acceptance commit markers .tels/.heads only after full
    verification -- chain rules and KEL anchor both.  Events whose KEL
    anchor is missing escrow to .maes; events arriving before their prior
    escrow to .ooes; the drain methods re-attempt acceptance when new KEL or
    TEL material arrives.  Analogous to the v1 Tever/Tevery pair, but for
    the v2 registry event grammar and its unsigned, anchor-authenticated
    events.

    Attributes:
        reger (RegBaser): registry event database
        db (Baser): KEL database, the source of anchor truth.  KEL
            verification is not Rever's job; the caller populates db through
            its own KEL processing.
    """

    def __init__(self, reger, db):
        """Initialize instance

        Parameters:
            reger (RegBaser): registry event database
            db (Baser): KEL database the caller populates and verifies
        """
        self.reger = reger
        self.db = db

    def processEvent(self, serder):
        """Process one registry event: verify and accept, escrow, or refuse.

        Parameters:
            serder (SerderACDC|bytes): registry event (rip or bup)

        Raises:
            OutOfOrderError: event escrowed to .ooes awaiting its prior
            MissingAnchorError: event escrowed to .maes awaiting its anchor
            MissequenceError, MisdigestError, MisanchorError,
            DuplicitousRegistryError, ValidationError: named refusals; the
            event is not stored
        """
        serder = _coerce(serder)
        if serder.ilk == Ilks.rip:
            self.processRip(serder)
        elif serder.ilk == Ilks.bup:
            self.processUpdate(serder)
        else:
            raise ValidationError(f"Unexpected ilk={serder.ilk} for registry "
                                  f"event {serder.said}.")

    def processRip(self, serder):
        """Process a registry inception (rip) event."""
        vetRip(serder)
        regid = serder.said
        if self.reger.tels.get(keys=regid, on=0) is not None:
            return  # the key is the said, so this is the same event: idempotent
        issuer = serder.sad['i']
        try:
            couple = vetAnchor(serder, db=self.db, issuer=issuer,
                               told=(regid,))
        except MissingAnchorError:
            self.escrowMissingAnchor(serder, regid=regid, sn=0)
            raise
        self.accept(serder, regid=regid, sn=0, couple=couple)

    def processUpdate(self, serder):
        """Process a blindable registry update (bup) event."""
        n = Number(numh=serder.sad['n']).num
        if n < 1:
            raise MissequenceError(f"Registry update {serder.said} has "
                                   f"n={serder.sad['n']} but updates must "
                                   f"be at n >= 1.")
        regid = serder.sad['rd']
        if self.reger.tels.get(keys=regid, on=0) is None:
            # registry inception not yet accepted: out of order
            self.escrowOutOfOrder(serder, regid=regid, sn=n)
            raise OutOfOrderError(f"Registry {regid} not yet accepted for "
                                  f"update {serder.said} at n={n}.")
        ripper = self.reger.evts.get(keys=regid)
        issuer = ripper.sad['i']
        headsaider = self.reger.heads.get(keys=regid)
        head = self.reger.evts.get(keys=headsaider.qb64)
        hn = Number(numh=head.sad['n']).num

        if n <= hn:  # level already accepted
            existing = self.reger.tels.get(keys=regid, on=n)
            if existing is not None and existing.qb64 == serder.said:
                return  # idempotent
            priorsaider = self.reger.tels.get(keys=regid, on=n - 1)
            if priorsaider is None or serder.sad['p'] != priorsaider.qb64:
                raise MisdigestError(f"Registry event {serder.said} at "
                                     f"n={n} has p={serder.sad['p']} which "
                                     f"is not the accepted prior's said.")
            try:
                vetAnchor(serder, db=self.db, issuer=issuer, told=(regid,))
            except MissingAnchorError:
                # unanchored, so unattributable: park until its anchor
                # appears, at which point the duplicity surfaces
                self.escrowMissingAnchor(serder, regid=regid, sn=n)
                raise
            raise DuplicitousRegistryError(f"Registry duplicity for "
                                           f"{regid}: anchored event "
                                           f"{serder.said} at already "
                                           f"accepted n={n} conflicts with "
                                           f"{existing.qb64}.")

        if n > hn + 1:  # beyond the head: intermediate may be in flight
            self.escrowOutOfOrder(serder, regid=regid, sn=n)
            raise OutOfOrderError(f"Registry update {serder.said} at n={n} "
                                  f"arrived with registry {regid} head at "
                                  f"n={hn}.")

        # n == hn + 1: the only acceptable next level
        if serder.sad['p'] != headsaider.qb64:
            raise MisdigestError(f"Registry event {serder.said} at n={n} "
                                 f"has p={serder.sad['p']} which is not the "
                                 f"head's said {headsaider.qb64}.")
        if serder.sad['rd'] != ripper.said:  # rd is the lookup key, but vet anyway
            raise MisregistryError(f"Registry update {serder.said} rd "
                                   f"mismatch for registry {regid}.")
        try:
            couple = vetAnchor(serder, db=self.db, issuer=issuer,
                               told=(regid,))
        except MissingAnchorError:
            self.escrowMissingAnchor(serder, regid=regid, sn=n)
            raise
        self.accept(serder, regid=regid, sn=n, couple=couple)

    def accept(self, serder, *, regid, sn, couple):
        """Commit a fully verified registry event: body, anchor couple, and
        the acceptance markers.  Acceptance is idempotent."""
        kelsn, kelsaid = couple
        self.reger.evts.pin(keys=serder.said, val=serder)
        self.reger.ancs.pin(keys=serder.said,
                            val=(Number(num=kelsn), Diger(qb64=kelsaid)))
        self.reger.tels.put(keys=regid, on=sn, val=Saider(qb64=serder.said))
        self.reger.heads.pin(keys=regid, val=Saider(qb64=serder.said))
        logger.info("Rever: accepted %s event said=%s reg=%.8s at n=%s",
                    serder.ilk, serder.said, regid, sn)

    def escrowMissingAnchor(self, serder, *, regid, sn):
        """Escrow an event whose KEL anchor is missing: body retained in
        .evts, membership in .maes.  Membership in .evts does not indicate
        acceptance."""
        self.reger.evts.pin(keys=serder.said, val=serder)
        self.reger.maes.add(keys=regid, on=sn, val=serder.said)
        logger.debug("Rever: escrowed missing-anchor %s event said=%s "
                     "reg=%.8s at n=%s", serder.ilk, serder.said, regid, sn)

    def escrowOutOfOrder(self, serder, *, regid, sn):
        """Escrow an event that arrived before its prior: body retained in
        .evts, membership in .ooes."""
        self.reger.evts.pin(keys=serder.said, val=serder)
        self.reger.ooes.add(keys=regid, on=sn, val=serder.said)
        logger.debug("Rever: escrowed out-of-order %s event said=%s "
                     "reg=%.8s at n=%s", serder.ilk, serder.said, regid, sn)

    def processEscrowMissingAnchors(self):
        """Drain the missing-anchor escrow: re-attempt acceptance of each
        escrowed event, typically after new KEL material arrives.  Events
        still missing their anchor stay; events that now refuse are purged;
        events that accept (or migrate to the out-of-order escrow) leave."""
        for keys, on, val in list(self.reger.maes.getTopItemIter()):
            said = val[0] if isinstance(val, tuple) else val
            serder = self.reger.evts.get(keys=said)
            if serder is None:  # orphaned marker
                self.reger.maes.rem(keys=keys, on=on, val=val)
                continue
            try:
                self.processEvent(serder)
            except MissingAnchorError:
                continue  # still waiting on KEL material
            except OutOfOrderError:
                self.reger.maes.rem(keys=keys, on=on, val=val)
            except ValidationError as ex:
                logger.info("Rever: purged missing-anchor escrow event "
                            "said=%s: %s", said, ex)
                self.reger.maes.rem(keys=keys, on=on, val=val)
            else:
                self.reger.maes.rem(keys=keys, on=on, val=val)

    def processEscrowOutOfOrders(self):
        """Drain the out-of-order escrow: re-attempt acceptance of each
        escrowed event, typically after new TEL material arrives.  Events
        still out of order stay; events that now refuse are purged; events
        that accept (or migrate to the missing-anchor escrow) leave."""
        for keys, on, val in list(self.reger.ooes.getTopItemIter()):
            said = val[0] if isinstance(val, tuple) else val
            serder = self.reger.evts.get(keys=said)
            if serder is None:  # orphaned marker
                self.reger.ooes.rem(keys=keys, on=on, val=val)
                continue
            try:
                self.processEvent(serder)
            except OutOfOrderError:
                continue  # still waiting on TEL material
            except MissingAnchorError:
                self.reger.ooes.rem(keys=keys, on=on, val=val)
            except ValidationError as ex:
                logger.info("Rever: purged out-of-order escrow event "
                            "said=%s: %s", said, ex)
                self.reger.ooes.rem(keys=keys, on=on, val=val)
            else:
                self.reger.ooes.rem(keys=keys, on=on, val=val)
