# -*- encoding: utf-8 -*-
"""
tests.app.test_body_cap

A shared bounded-read helper caps
every body-reading front-door route: POST / (parseCesrHttpRequest), /ext/oobi,
/end/{aid}/{role}, mailbox PUT, and the SignatureValidationComponent middleware.

PARTIAL mitigation: hio buffers the whole request body before falcon dispatches,
so a handler-level check runs after the bytes are resident. These tests prove the
413 rejection and the removal of the parse amplification; full OOM closure needs
an hio server-layer body limit.
"""
import falcon
import pytest
from falcon import testing

from keri.app import httping

CAP = httping.MAX_CESR_BODY_SIZE


def _req(method="POST", path="/", headers=None, body=b"", content_length=None):
    hdrs = {"Content-Type": httping.CESR_CONTENT_TYPE,
            httping.CESR_ATTACHMENT_HEADER: "-AABAA"}
    if headers:
        hdrs.update(headers)
    env = testing.create_environ(method=method, path=path, headers=hdrs, body=body)
    if content_length is not None:
        env["CONTENT_LENGTH"] = str(content_length)
    return falcon.Request(env)


# --- the shared helpers ------------------------------------------------------

def test_enforce_max_body_rejects_over_cap_content_length():
    req = _req(content_length=CAP + 1)
    with pytest.raises(falcon.HTTPError) as ei:
        httping.enforceMaxBody(req)
    assert ei.value.status == falcon.HTTP_413


def test_enforce_max_body_allows_under_cap():
    httping.enforceMaxBody(_req(content_length=100))  # no raise


def test_read_bounded_body_overflow_when_cl_absent():
    """Undeclared / chunked body: the read itself is bounded to limit+1."""
    class FakeStream:
        def __init__(self, data):
            self.data = data

        def read(self, n):
            return self.data[:n]

    class FakeReq:
        content_length = None

        def __init__(self, data):
            self.bounded_stream = FakeStream(data)

    with pytest.raises(falcon.HTTPError) as ei:
        httping.readBoundedBody(FakeReq(b"A" * 20), limit=10)
    assert ei.value.status == falcon.HTTP_413


# --- each body-reading route rejects an over-cap declared Content-Length ------

def test_post_slash_parsecesr_413():
    req = _req(content_length=CAP + 1)
    with pytest.raises(falcon.HTTPError) as ei:
        httping.parseCesrHttpRequest(req)
    assert ei.value.status == falcon.HTTP_413


def test_post_slash_parsecesr_small_ok():
    req = _req(body=b'{"hello":"world"}')
    cr = httping.parseCesrHttpRequest(req)
    assert cr.payload == {"hello": "world"}


def test_signature_middleware_413():
    comp = httping.SignatureValidationComponent(hby=None, pre="EAID")
    req = _req(content_length=CAP + 1)
    with pytest.raises(falcon.HTTPError) as ei:
        comp.process_request(req, resp=None)
    assert ei.value.status == falcon.HTTP_413


def test_ext_oobi_413():
    from keri.app.oobiing import OobiResource
    res = OobiResource(hby=None)
    req = _req(path="/oobi", content_length=CAP + 1)
    rep = falcon.Response()
    with pytest.raises(falcon.HTTPError) as ei:
        res.on_post(req, rep)
    assert ei.value.status == falcon.HTTP_413


def test_end_point_413():
    from keri.end.ending import PointEnd
    pe = PointEnd(hby=None)
    req = _req(path="/end/EAID/witness", content_length=CAP + 1)
    rep = falcon.Response()
    with pytest.raises(falcon.HTTPError) as ei:
        pe.on_post(req, rep, aid="EAID", role="witness")
    assert ei.value.status == falcon.HTTP_413


def test_mailbox_put_413():
    from keri.app.indirecting import HttpEnd
    he = HttpEnd()
    req = _req(method="PUT", content_length=CAP + 1)
    rep = falcon.Response()
    with pytest.raises(falcon.HTTPError) as ei:
        he.on_put(req, rep)
    assert ei.value.status == falcon.HTTP_413


def test_mailbox_put_small_ok():
    from keri.app.indirecting import HttpEnd
    he = HttpEnd()
    req = _req(method="PUT", body=b"hello")
    rep = falcon.Response()
    he.on_put(req, rep)
    assert bytes(he.rxbs) == b"hello"
    assert rep.status == falcon.HTTP_204
