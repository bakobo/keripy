# -*- encoding: utf-8 -*-
"""
tests.app.test_address_policy

address policy for keripy's outbound HTTP (checkUrl) and the fetch/send paths that
route through it. Doctrine:

  * link-local / cloud-metadata (169.254.0.0/16, fe80::/10), multicast, reserved
    and unspecified destinations are blocked UNCONDITIONALLY (no opt-out);
  * RFC-1918 / ULA private ranges are ALLOWED by default (private-network
    witnesses are a normal KERI deployment; a KEL is verified regardless of
    fetch origin) and blockable only via the BLOCK_PRIVATE_ADDRESSES opt-in;
  * loopback stays allowed (local dev / tests).
"""
import pytest

from keri.app import httping
from keri.kering import ValidationError


# --- decouple metadata/link-local from RFC-1918 --------------------

METADATA_FORMS = [
    "http://169.254.169.254/latest/meta-data/",   # canonical cloud metadata
    "http://[::ffff:169.254.169.254]/",            # IPv4-mapped IPv6
    "http://2852039166/",                          # decimal encoding
    "http://0xA9FEA9FE/",                          # hex encoding
    "http://0251.0376.0251.0376/",                 # octal encoding
]

PRIVATE_URLS = [
    "http://10.1.2.3/oobi",
    "http://192.168.1.10/oobi",
    "http://172.16.5.5/oobi",
    "http://[fd00::1]/oobi",
]


@pytest.mark.parametrize("url", METADATA_FORMS)
def test_metadata_blocked_regardless_of_private_flag(url):
    # blocked with the default (private allowed)
    assert httping.BLOCK_PRIVATE_ADDRESSES is False
    with pytest.raises(ValidationError):
        httping.checkUrl(url)
    # and still blocked when private is explicitly permitted or blocked
    with pytest.raises(ValidationError):
        httping.checkUrl(url, blockPrivate=False)
    with pytest.raises(ValidationError):
        httping.checkUrl(url, blockPrivate=True)


def test_link_local_ipv6_blocked_unconditionally():
    with pytest.raises(ValidationError):
        httping.checkUrl("http://[fe80::1]/", blockPrivate=False)


@pytest.mark.parametrize("url", PRIVATE_URLS)
def test_private_allowed_by_default(url):
    # default: private ranges are reachable (returns the parsed url, no raise)
    purl = httping.checkUrl(url)
    assert purl.scheme == "http"


@pytest.mark.parametrize("url", PRIVATE_URLS)
def test_private_blocked_when_opt_in(url):
    with pytest.raises(ValidationError):
        httping.checkUrl(url, blockPrivate=True)


def test_module_flag_opt_in_blocks_private(monkeypatch):
    monkeypatch.setattr(httping, "BLOCK_PRIVATE_ADDRESSES", True)
    with pytest.raises(ValidationError):
        httping.checkUrl("http://10.1.2.3/oobi")
    # metadata is still blocked under the opt-in
    with pytest.raises(ValidationError):
        httping.checkUrl("http://169.254.169.254/")


def test_loopback_and_public_allowed():
    assert httping.checkUrl("http://127.0.0.1:5642/oobi").hostname == "127.0.0.1"
    assert httping.checkUrl("http://8.8.8.8/oobi").hostname == "8.8.8.8"


def test_bad_scheme_rejected():
    for url in ("file:///etc/passwd", "gopher://8.8.8.8/", "ftp://8.8.8.8/"):
        with pytest.raises(ValidationError):
            httping.checkUrl(url)


def test_clienter_request_returns_none_for_blocked():
    """Clienter.request must refuse a blocked host by returning None (so callers
    that already handle a None client fail cleanly, not by connecting)."""
    clienter = httping.Clienter()
    assert clienter.request("GET", "http://169.254.169.254/latest/") is None


def test_clienter_request_allows_private_by_default(monkeypatch):
    """A private host is not refused at the guard by default: request proceeds to
    build a client (we stub the hio client/doer so no socket is opened and the
    DoDoer machinery is bypassed)."""
    built = {}

    class FakeClient:
        def __init__(self, **kwa):
            built.update(kwa)

        def request(self, **kwa):
            pass

    monkeypatch.setattr(httping.http.clienting, "Client", FakeClient)
    monkeypatch.setattr(httping.http.clienting, "ClientDoer",
                        lambda client=None: object())

    clienter = httping.Clienter()
    monkeypatch.setattr(clienter, "extend", lambda doers: None)

    client = clienter.request("GET", "http://10.1.2.3/oobi")
    assert client is not None
    assert built["hostname"] == "10.1.2.3"
