# -*- encoding: utf-8 -*-
"""
tests.db.test_temp_root module

A temp database removes the mkdtemp root it was opened under, not only the tail
of its path. hio before ioflo/hio#162 removed only the tail, so every Baser,
Keeper, Configer, Reger and Mailboxer opened with temp=True stranded an empty
keri_*_test skeleton in the temp directory for the life of the box, which a
suite that opens them by the thousand turns into inode exhaustion. PyPI's hio
0.7.20 does not carry that fix, so this pins that the dependency keri installs
does.
"""
import os
import tempfile

from keri.db import Baser


def mkdtempRoot(path):
    """Return the directory directly under the temp directory that holds path."""
    tmp = os.path.realpath(tempfile.gettempdir())
    path = os.path.realpath(path)
    while os.path.dirname(path) != tmp:
        parent = os.path.dirname(path)
        assert parent != path, f"{path} is not under {tmp}"
        path = parent
    return path


def test_temp_baser_removes_its_mkdtemp_root_on_close():
    baser = Baser(name="temproot", temp=True, reopen=True)
    root = mkdtempRoot(baser.path)
    assert os.path.basename(root).startswith(baser.TempPrefix)
    assert os.path.exists(root)

    baser.close(clear=True)

    assert not os.path.exists(root)


def test_mkdtempRoot_refuses_a_path_outside_the_temp_directory():
    try:
        mkdtempRoot("/")
    except AssertionError as ex:
        assert "is not under" in str(ex)
    else:
        raise AssertionError("mkdtempRoot accepted a path outside the temp directory")
