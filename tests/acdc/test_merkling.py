# -*- encoding: utf-8 -*-
"""
tests.acdc.test_merkling module

The batch Merkle tree that commits many registry (TEL) transaction events under
ONE root seal in an issuer's KEL (ACDC spec 15.4, "Independent Registry
Transaction Event Seals Using Merkle Tree Roots"; construction as proposed in
trustoverip/kswg-acdc-specification#204).

These tests pin the construction byte for byte, because two implementations
that build the tree differently compute different roots and cannot
cross-verify: RFC 6962 domain separation (leaf H(0x00 + said), interior
H(0x01 + left + right)) over qb64 text, Blake3-256, and an odd node promoted
unchanged rather than duplicated.
"""

import pytest

from keri import kering
from keri.core import Diger
from keri.acdc import merkling
from keri.acdc.merkling import BatchTree, BATCH_TREE_TYPE, rootOf, rootSeals


def saids(n, tag=b'ev'):
    return [Diger(ser=tag + bytes([i])).qb64 for i in range(n)]


def test_leaf_and_node_domain_separation_pinned():
    """A leaf is H(0x00 + said) and a node H(0x01 + left + right), over qb64
    text with Blake3-256: a one-leaf tree's root is NOT the leaf's own SAID,
    so a bare digest seal of a TEL event can never be read as a tree root."""
    a, b = saids(2)
    leafA = Diger(ser=b'\x00' + a.encode()).qb64
    leafB = Diger(ser=b'\x00' + b.encode()).qb64
    assert BatchTree([a]).root == leafA == BatchTree.leaf(a)
    assert BatchTree([a]).root != a
    assert BatchTree([a, b]).root == Diger(
        ser=b'\x01' + (leafA + leafB).encode()).qb64
    assert Diger(qb64=BatchTree([a]).root).code == Diger(qb64=a).code


def test_odd_node_promoted_not_duplicated():
    """Three leaves: the third leaf's hash is promoted unchanged, so the root
    is H(1 + H(1 + la + lb) + lc), and a duplicated-last-leaf tree [a,b,c,c]
    does NOT share the root (CVE-2012-2459)."""
    a, b, c = saids(3)
    la, lb, lc = (BatchTree([x]).root for x in (a, b, c))
    ab = Diger(ser=b'\x01' + (la + lb).encode()).qb64
    assert BatchTree([a, b, c]).root == Diger(
        ser=b'\x01' + (ab + lc).encode()).qb64
    with pytest.raises(ValueError):
        BatchTree([a, b, c, c])  # a leaf commits once; duplicates are refused
    assert BatchTree([a, b, c]).prove(c) == [(ab, 'L')]


def test_every_leaf_proves_for_sizes_one_through_seventeen():
    for n in range(1, 18):
        leaves = saids(n, tag=b'sz%d' % n)
        tree = BatchTree(leaves)
        for leaf in leaves:
            proof = tree.prove(leaf)
            assert rootOf(leaf, proof) == tree.root
            assert BatchTree.verify(leaf, proof, tree.root)


def test_tampered_proofs_fail():
    leaves = saids(6)
    tree = BatchTree(leaves)
    leaf = leaves[2]
    proof = tree.prove(leaf)
    assert len(proof) == 3

    # a foreign leaf does not prove under this root
    assert not BatchTree.verify(Diger(ser=b'stranger').qb64, proof, tree.root)
    # flip one side
    flipped = [(proof[0][0], 'L' if proof[0][1] == 'R' else 'R')] + proof[1:]
    assert not BatchTree.verify(leaf, flipped, tree.root)
    # drop one step
    assert not BatchTree.verify(leaf, proof[1:], tree.root)
    # substitute one sibling
    swapped = [(Diger(ser=b'x').qb64, proof[0][1])] + proof[1:]
    assert not BatchTree.verify(leaf, swapped, tree.root)
    # an unknown leaf has no proof
    with pytest.raises(ValueError):
        tree.prove(Diger(ser=b'stranger').qb64)


def test_malformed_proof_refused_by_name():
    """A proof that is not a sequence of (qb64 digest, 'L'|'R') pairs is a
    permanent, named refusal rather than a mismatch to retry."""
    leaf = saids(1)[0]
    sib = saids(1, tag=b'sib')[0]
    for bad in ([(sib, 'X')], [(sib,)], [('not qb64', 'L')], "LR",
                [(sib, 'L', 'extra')], None, [None]):
        with pytest.raises(kering.MerkleProofError):
            rootOf(leaf, bad)


def test_leaf_must_be_a_qb64_digest():
    with pytest.raises(ValueError):
        BatchTree(["not a said"])
    with pytest.raises(ValueError):
        BatchTree([])


def test_root_seals_recognized():
    """A KEL event's seal list names a batch root either as the KERI Merkle
    root seal {rd} or as a typed seal {t, d} whose type is the ACDC v2.0
    batch tree.  A bare digest seal {d} or a bare string is NOT a root: it
    commits to one datum, and reading it as a root would let any digest the
    issuer ever sealed stand in for a tree it never built."""
    r1, r2, r3, r4, r5 = saids(5, tag=b'root')
    seals = [dict(rd=r1),
             dict(t=BATCH_TREE_TYPE, d=r2),
             dict(t='other-type', d=r3),
             dict(d=r4),
             r5,
             dict(i='x', s='0', d=r4)]
    assert rootSeals(seals) == [r1, r2]
    assert rootSeals(None) == []


def test_worked_examples_use_the_library_tree():
    """The two independent-registry bulk-issuance examples' batch trees are
    this class, so their pinned roots pin the library construction too."""
    from tests.acdc import (test_bulk_issuance_cocreated_registry as co,
                            test_bulk_issuance_precreated_registry as pre)
    assert co._BatchTree is BatchTree
    assert pre._BatchTree is BatchTree
    assert pre.BATCH_TREE_TYPE == BATCH_TREE_TYPE
    assert merkling.BatchTree is BatchTree


def test_tree_hash_is_the_codes_digest():
    """The tree hashes with the digest algorithm its code names; Blake3-256
    by default.  A proof folds with the code it is asked for, so a proof from
    a SHA3 tree reconstructs that tree's root only under the SHA3 code."""
    from keri.core.coring import DigDex
    leaves = saids(5)
    sha = BatchTree(leaves, code=DigDex.SHA3_256)
    a = leaves[0]
    assert sha.leaf(a, code=DigDex.SHA3_256) == Diger(
        ser=b'\x00' + a.encode(), code=DigDex.SHA3_256).qb64
    assert Diger(qb64=sha.root).code == DigDex.SHA3_256
    proof = sha.prove(leaves[3])
    assert rootOf(leaves[3], proof, code=DigDex.SHA3_256) == sha.root
    assert rootOf(leaves[3], proof) != sha.root
    assert BatchTree.verify(leaves[3], proof, sha.root)  # code read off root
    assert Diger(qb64=BatchTree(leaves).root).code == DigDex.Blake3_256
