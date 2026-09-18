# -*- encoding: utf-8 -*-
"""
tests.app.test_response_cap

The response cap is cosmetic against the
client OOM (hio buffers the whole response first) and the prior implementation
raised ValidationError into the Receiptor.receipt/get generators with no handler,
crashing the Doist. boundedResponseBody now returns None over-cap and NEVER
raises, so an over-cap response drops the body instead of crashing the doer.
A streaming cap in hio bounds the response itself.
"""
from types import SimpleNamespace

from keri.app import httping

CAP = httping.MAX_RESPONSE_SIZE


def test_bounded_response_normal_returns_bytes():
    rep = SimpleNamespace(status=200, body=b"receipt-bytes", headers={})
    assert httping.boundedResponseBody(rep) == b"receipt-bytes"


def test_bounded_response_over_cap_body_returns_none_not_raise():
    rep = SimpleNamespace(status=200, body=b"A" * (CAP + 1), headers={})
    # must NOT raise (that was the doer crash); returns None
    assert httping.boundedResponseBody(rep) is None


def test_bounded_response_over_cap_content_length_returns_none():
    rep = SimpleNamespace(status=200, body=b"small",
                          headers={"Content-Length": str(CAP + 1)})
    assert httping.boundedResponseBody(rep) is None


def test_bounded_response_missing_body():
    rep = SimpleNamespace(status=200, body=None, headers={})
    assert httping.boundedResponseBody(rep) == b""


def test_get_does_not_crash_on_over_cap_response(monkeypatch):
    """Receiptor.get must complete (return False) for an over-cap witness
    response instead of raising into its generator."""
    from keri.app import agenting
    from keri.app.agenting import Receiptor
    from keri import kering

    parsed = []

    class FakeClient:
        def __init__(self):
            self.responses = [object()]

        def respond(self):
            return SimpleNamespace(status=200, body=b"A" * (CAP + 1), headers={})

    class FakeKever:
        sner = SimpleNamespace(num=0)
        wits = ["EWit"]

    class FakeHab:
        kever = FakeKever()

        def fetchUrls(self, eid, scheme=None):
            if scheme == kering.Schemes.https:
                return {kering.Schemes.https: "https://8.8.8.8/"}
            return {}

    class FakeClienter:
        def request(self, method, url):
            return FakeClient()

        def remove(self, client):
            pass

    class FakeHby:
        prefixes = {"EPre"}
        habs = {"EPre": FakeHab()}

    monkeypatch.setattr(agenting, "Clienter", lambda: FakeClienter())
    # avoid parsing being reached at all (body dropped) — spy would flag a bug
    monkeypatch.setattr(FakeHab, "psr", SimpleNamespace(
        parseOne=lambda *a, **k: parsed.append(True)), raising=False)

    rcptr = Receiptor(hby=FakeHby())
    dog = rcptr.get("EPre", sn=0)
    result = None
    try:
        while True:
            next(dog)
    except StopIteration as ex:
        result = ex.value

    assert result is False           # over-cap response -> not ok, no crash
    assert parsed == []              # body was dropped, never parsed
