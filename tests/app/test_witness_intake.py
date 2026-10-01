# -*- encoding: utf-8 -*-
"""
tests.app.test_witness_intake

Each request a witness accepts at POST / or PUT / is parsed as its own frame,
so a request whose attachments are short or malformed cannot affect how a
different request is parsed. Uses the HttpEnd and Parser that setupWitness wires.
"""
import contextlib
import io
import socket

from hio.core import http

from keri.app import habbing, indirecting
from keri.app.httping import CESR_CONTENT_TYPE, CESR_ATTACHMENT_HEADER
from keri.core import counting, serdering


class _Req:
    """Minimal stand-in for the falcon Request fields the handlers read."""
    def __init__(self, body: bytes, attachment: str = None, method="POST"):
        self.method = method
        self.content_type = CESR_CONTENT_TYPE
        self.content_length = len(body)
        self.bounded_stream = io.BytesIO(body)
        self.stream = self.bounded_stream
        self.headers = {CESR_ATTACHMENT_HEADER: attachment} if attachment is not None else {}

    def get_header(self, name, default=None):
        return self.headers.get(name, default)


class _Rep:
    def __init__(self):
        self.status = None
        self.stream = None

    def set_header(self, *_a, **_k):
        pass


def _split(hab):
    """(json body bytes, attachment str) for hab's inception, as a CESR POST carries them."""
    full = hab.msgOwnInception() if hasattr(hab, "msgOwnInception") else hab.makeOwnInception()
    sad = serdering.SerderKERI(raw=bytes(full), verify=False)
    return bytes(sad.raw), bytes(bytearray(full)[len(sad.raw):]).decode("utf-8")


def _short_group():
    """An AttachmentGroup counter declaring 50 quadlets, followed by only one."""
    return counting.Counter(counting.CtrDex_1_0.AttachmentGroup, count=50).qb64 + "-AAB"


def _freePort():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@contextlib.contextmanager
def _witness():
    with contextlib.ExitStack() as stack:
        witHby = stack.enter_context(habbing.openHby(name="intake-wit", temp=True))
        witHby.makeHab(name="wit", transferable=False)
        aHby = stack.enter_context(habbing.openHby(name="intake-a", temp=True))
        bHby = stack.enter_context(habbing.openHby(name="intake-b", temp=True))
        clientA = aHby.makeHab(name="a", transferable=False)
        clientB = bHby.makeHab(name="b", transferable=False)

        doers = indirecting.setupWitness(witHby, alias="wit", tcpPort=None,
                                         httpPort=_freePort())
        serverDoer = [d for d in doers if isinstance(d, http.ServerDoer)][0]
        stack.callback(serverDoer.server.close)
        witStart = [d for d in doers if isinstance(d, indirecting.WitnessStart)][0]
        httpEnd = serverDoer.server.app._router.find("/")[0]
        assert isinstance(httpEnd, indirecting.HttpEnd)
        yield witHby, clientA, clientB, witStart.parser, httpEnd


def _drain(parser, steps=400):
    """Run the witness's continuous parser over whatever it has buffered."""
    g = parser.parsator(local=True)
    for _ in range(steps):
        next(g)


def test_two_posts_both_land():
    with _witness() as (witHby, clientA, clientB, parser, httpEnd):
        httpEnd.on_post(_Req(*_split(clientA)), _Rep())
        httpEnd.on_post(_Req(*_split(clientB)), _Rep())
        _drain(parser)
        assert clientA.pre in witHby.kevers
        assert clientB.pre in witHby.kevers


def test_post_after_short_attachment_group_lands():
    with _witness() as (witHby, clientA, clientB, parser, httpEnd):
        body, _ = _split(clientA)
        httpEnd.on_post(_Req(body, _short_group()), _Rep())
        httpEnd.on_post(_Req(*_split(clientB)), _Rep())
        _drain(parser)
        assert clientB.pre in witHby.kevers


def test_put_after_short_attachment_group_lands():
    with _witness() as (witHby, clientA, clientB, parser, httpEnd):
        body, _ = _split(clientA)
        short = body + _short_group().encode("utf-8")
        httpEnd.on_put(_Req(short, method="PUT"), _Rep())
        httpEnd.on_put(_Req(bytes(clientB.msgOwnInception()
                                  if hasattr(clientB, "msgOwnInception")
                                  else clientB.makeOwnInception()), method="PUT"),
                       _Rep())
        _drain(parser)
        assert clientB.pre in witHby.kevers
