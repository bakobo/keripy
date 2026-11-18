# -*- encoding: utf-8 -*-
"""
keri.acdc.merkling module

Batch Merkle trees for anchoring many registry (TEL) transaction events under
ONE root seal in an issuer's KEL (ACDC spec, "Independent Registry Transaction
Event Seals Using Merkle Tree Roots").

An issuer of independent-registry bulk-issued ACDCs SHOULD NOT anchor a set's
registry events as a list of individual seals in one key event: any reader of
that KEL would see them co-anchored and reassemble the set.  It anchors a
single seal whose digest is the root of a tree over the transaction-event SAIDs
of a whole batch, across registries and issuees.  A verifier given one event
and its inclusion proof learns that the issuer committed to that event and
nothing about any other leaf.

Construction.  The spec as published pins neither leaf definition nor hashing,
and two implementations that chose differently would compute different roots.
This module implements the construction proposed in
trustoverip/kswg-acdc-specification#204 and first worked in keripy's
independent-registry bulk-issuance examples:

- a leaf is the transaction event's SAID (qb64), and a tree commits each leaf
  once;
- leaf hash H(0x00 + said), interior hash H(0x01 + left + right), RFC 6962
  domain separation over qb64 TEXT concatenation, so an interior node's
  preimage cannot be replayed as a leaf;
- H is Blake3-256 (Diger's default), and every hash is a qb64 Diger;
- an odd node at any level is promoted unchanged, never duplicated, which
  avoids the duplicate-last-leaf ambiguity (CVE-2012-2459).

This is a plain (dense) Merkle tree.  The spec also describes a sparse Merkle
tree; the two are different structures and a bare root digest cannot say
which one it is.  An issuer can declare the type with a typed seal {t, d}
whose t is BATCH_TREE_TYPE.  Be exact about what that declares: a Verser's
value space is (proto, pvrsn, gvrsn), so t says "ACDC protocol v2.0", and the
dense construction is pinned only as the one ACDC v2.0 defines.

An inclusion proof is an ordered sequence of (sibling, side) pairs, leaf level
first, where sibling is a qb64 digest and side is 'L' or 'R', the side on
which the sibling sits.  A level at which the path's node was promoted
contributes no pair.  No CESR wire encoding of a proof is defined here.
"""

from collections.abc import Mapping, Sequence

from ..kering import MerkleProofError, Protocols, Vrsn_2_0
from ..core import Diger
from ..core.coring import DigDex, Verser


LeafPrefix = b'\x00'  # RFC 6962 leaf domain prefix
NodePrefix = b'\x01'  # RFC 6962 interior-node domain prefix

BATCH_TREE_TYPE = Verser(proto=Protocols.acdc, pvrsn=Vrsn_2_0,
                         gvrsn=Vrsn_2_0).qb64
"""Type value t of a typed seal {t, d} whose d is a batch tree root."""

Sides = ('L', 'R')


def _leaf(said, code=DigDex.Blake3_256):
    return Diger(ser=LeafPrefix + said.encode(), code=code).qb64


def _node(left, right, code=DigDex.Blake3_256):
    return Diger(ser=NodePrefix + (left + right).encode(), code=code).qb64


def _isDigest(qb64):
    if not isinstance(qb64, str):
        return False
    try:
        Diger(qb64=qb64)
    except Exception:
        return False
    return True


class BatchTree:
    """Dense Merkle tree over TEL transaction-event SAIDs whose root an issuer
    seals in its KEL.  See the module docstring for the construction.

    Leaf order is the caller's: it is the issuer's choice and is what the
    proofs' paths disclose.  A proof's side bits give its leaf's exact index,
    and its length bounds the batch size.  An issuer should shuffle (or sort
    by SAID) so one holder's events do not sit in a contiguous run.

    Privacy depends on what the issuer puts in one batch, not on the tree.
    The root, and the key event sealing it, are shared by every leaf, so two
    verifiers comparing anchor couples learn that their events share a
    batch.  A batch holding one bulk-issued set's events (its issuance, or a
    set-wide revocation) therefore links the set's copies exactly as a list
    of seals in one key event would.  A batch decorrelates only when it mixes
    events across bulk sets, issuees and registries.

    Attributes:
        leaves (list[str]): the qb64 leaf SAIDs, in tree order
        levels (list[list[str]]): hashes per level, leaf hashes first
    """

    def __init__(self, leaves, code=DigDex.Blake3_256):
        """
        Parameters:
            leaves (Iterable[str]): qb64 SAIDs of the transaction events to
                commit, in tree order; at least one, each a qb64 digest,
                none repeated
            code (str): DigDex code of the tree's hash.  The root carries
                it, so a verifier reads the algorithm off the sealed root.

        Raises:
            ValueError: empty, non-digest or repeated leaves
        """
        self.leaves = list(leaves)
        if not self.leaves:
            raise ValueError("A batch tree must commit at least one leaf.")
        for leaf in self.leaves:
            if not _isDigest(leaf):
                raise ValueError(f"Batch tree leaf {leaf!r} is not a qb64 "
                                 f"digest.")
        if len(set(self.leaves)) != len(self.leaves):
            raise ValueError("A batch tree commits each leaf once; repeated "
                             "leaves are refused.")
        self.code = code
        self._index = {leaf: i for i, leaf in enumerate(self.leaves)}
        self.levels = [[_leaf(leaf, code) for leaf in self.leaves]]
        while len(self.levels[-1]) > 1:
            cur = self.levels[-1]
            nxt = [_node(cur[i], cur[i + 1], code)
                   for i in range(0, len(cur) - 1, 2)]
            if len(cur) % 2:  # promote the odd node, never duplicate it
                nxt.append(cur[-1])
            self.levels.append(nxt)

    @staticmethod
    def leaf(said, code=DigDex.Blake3_256):
        """Leaf hash H(0x00 + said) as qb64."""
        return _leaf(said, code)

    @staticmethod
    def node(left, right, code=DigDex.Blake3_256):
        """Interior hash H(0x01 + left + right) as qb64."""
        return _node(left, right, code)

    @property
    def root(self):
        """qb64 root digest: the value the issuer seals in its KEL."""
        return self.levels[-1][0]

    def prove(self, said):
        """Return the inclusion proof of leaf said as a list of
        (sibling, side) pairs, leaf level first.

        Raises:
            ValueError: said is not a leaf of this tree
        """
        try:
            index = self._index[said]
        except (KeyError, TypeError):
            raise ValueError(f"{said!r} is not a leaf of this batch tree.")
        proof = []
        for level in self.levels[:-1]:
            if index % 2:
                proof.append((level[index - 1], 'L'))
            elif index + 1 < len(level):
                proof.append((level[index + 1], 'R'))
            index //= 2
        return proof

    @staticmethod
    def verify(said, proof, root):
        """True iff proof reconstructs root from leaf said, hashing with the
        digest algorithm root's derivation code names.  A root that is not a
        qb64 digest verifies nothing.

        Raises:
            MerkleProofError: proof is malformed
        """
        try:
            code = Diger(qb64=root).code
        except Exception:
            rootOf(said, proof)  # still refuse a malformed proof by name
            return False
        return rootOf(said, proof, code=code) == root


def rootOf(said, proof, code=DigDex.Blake3_256):
    """Reconstruct the root a proof claims for leaf said, hashing with the
    digest algorithm code names.

    Returns:
        root (str): qb64 root digest

    Raises:
        MerkleProofError: said is not a qb64 digest, or proof is not a
            sequence of (qb64 digest, 'L'|'R') pairs.  Malformation is
            permanent: no later evidence can make the proof well formed.
    """
    if not _isDigest(said):
        raise MerkleProofError(f"Inclusion proof leaf {said!r} is not a qb64 "
                               f"digest.")
    if isinstance(proof, (str, bytes)) or not isinstance(proof, Sequence):
        raise MerkleProofError(f"Inclusion proof for {said} is not a "
                               f"sequence of (sibling, side) pairs.")
    digest = _leaf(said, code)
    for step in proof:
        if (isinstance(step, (str, bytes)) or not isinstance(step, Sequence)
                or len(step) != 2):
            raise MerkleProofError(f"Inclusion proof step {step!r} for "
                                   f"{said} is not a (sibling, side) pair.")
        sibling, side = step
        if side not in Sides or not _isDigest(sibling):
            raise MerkleProofError(f"Inclusion proof step {step!r} for "
                                   f"{said} needs a qb64 digest and a side "
                                   f"in {Sides}.")
        digest = (_node(sibling, digest, code) if side == 'L'
                  else _node(digest, sibling, code))
    return digest


def rootSeals(seals):
    """Extract the batch tree roots a key event's seal list commits to.

    A root is named by the KERI Merkle tree root digest seal {rd}, or by a
    typed seal {t, d} whose t is BATCH_TREE_TYPE.  A bare digest seal {d},
    a seal couple {s, d}, a source seal {i, s, d} and a bare string are not
    roots: each commits to one datum, and reading one as a root would let a
    digest the issuer sealed for another purpose stand in for a tree it never
    built.  (With RFC 6962 domain separation no TEL event SAID can equal a
    tree root, but the issuer's declaration is still what makes a root.)

    Returns:
        roots (list[str]): qb64 root digests, in seal order
    """
    roots = []
    if not isinstance(seals, (list, tuple)):
        return roots
    for seal in seals:
        if not isinstance(seal, Mapping):
            continue
        if set(seal) == {'rd'}:
            roots.append(seal['rd'])
        elif set(seal) == {'t', 'd'} and seal['t'] == BATCH_TREE_TYPE:
            roots.append(seal['d'])
    return roots
