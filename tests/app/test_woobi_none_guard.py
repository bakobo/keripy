# -*- encoding: utf-8 -*-
"""
tests.app.test_woobi_none_guard

Clienter.request returns None for a blocked URL
(address policy). The Oobiery.request sibling checks None; the wOOBI
Authenticator.request did not, so it stored None and processMultiFactorAuth then
raised AttributeError ('NoneType' has no attribute 'responses') into authzDo.
"""


class _FakeSub:
    def __init__(self):
        self.removed = []
        self.pinned = []

    def rem(self, keys):
        self.removed.append(keys)

    def pin(self, keys, val):
        self.pinned.append((keys, val))


class _FakeDB:
    def __init__(self):
        self.woobi = _FakeSub()
        self.mfa = _FakeSub()


class _FakeHby:
    def __init__(self):
        self.db = _FakeDB()


class _BlockingClienter:
    """Mimics Clienter.request refusing a blocked URL by returning None."""
    def request(self, method, url):
        return None


def test_woobi_blocked_url_not_stored_as_none():
    from keri.app.oobiing import Authenticator

    hby = _FakeHby()
    auth = Authenticator(hby=hby, clienter=_BlockingClienter())

    wurl = "http://169.254.169.254/oobi/EAID/witness"
    auth.request(wurl, obr=object())

    # A None client must never be stored (that is what crashed authzDo).
    assert auth.clients == {}
    assert None not in auth.clients.values()
    # The wOOBI record is cleaned up, and no MFA follow-up is pinned for a URL
    # we could not even fetch.
    assert (wurl,) in hby.db.woobi.removed
    assert hby.db.mfa.pinned == []
