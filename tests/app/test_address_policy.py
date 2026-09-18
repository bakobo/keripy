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

    monkeypatch.setattr(httping, "RedirectGuardedClient", FakeClient)
    monkeypatch.setattr(httping.http.clienting, "ClientDoer",
                        lambda client=None: object())

    clienter = httping.Clienter()
    monkeypatch.setattr(clienter, "extend", lambda doers: None)

    client = clienter.request("GET", "http://10.1.2.3/oobi")
    assert client is not None
    assert built["hostname"] == "10.1.2.3"


# --- cover the message-send paths + httpClient ---------------------

def _fakeHioClient(monkeypatch):
    """Replace agenting's client class (RedirectGuardedClient) and ClientDoer with
    capturing fakes so no socket is opened; returns the dict that captures the
    client constructor kwargs."""
    from keri.app import agenting
    built = {}

    class FakeClient:
        def __init__(self, **kwa):
            built.update(kwa)
            self.requests = []
            self.responses = []

        def request(self, **kwa):
            pass

    monkeypatch.setattr(agenting, "RedirectGuardedClient", FakeClient)
    monkeypatch.setattr(agenting.http.clienting, "ClientDoer",
                        lambda client=None: object())
    return built


def test_http_messenger_blocks_metadata(monkeypatch):
    from keri.app.agenting import HTTPMessenger
    _fakeHioClient(monkeypatch)
    with pytest.raises(ValidationError):
        HTTPMessenger(hab=None, wit="EWit", url="http://169.254.169.254/")


def test_http_messenger_uses_guarded_client_for_public(monkeypatch):
    from keri.app.agenting import HTTPMessenger
    built = _fakeHioClient(monkeypatch)
    HTTPMessenger(hab=None, wit="EWit", url="http://8.8.8.8/")
    # constructed via RedirectGuardedClient (the fake), and not forced to a zero
    # redirect budget (redirectable is defaulted True inside the guarded client).
    assert built["hostname"] == "8.8.8.8"
    assert built.get("redirectable", True) is not False


def test_http_stream_messenger_blocks_metadata(monkeypatch):
    from keri.app.agenting import HTTPStreamMessenger
    _fakeHioClient(monkeypatch)
    with pytest.raises(ValidationError):
        HTTPStreamMessenger(hab=None, wit="EWit",
                            url="http://169.254.169.254/", msg=b"x")


def test_http_stream_messenger_uses_guarded_client(monkeypatch):
    from keri.app.agenting import HTTPStreamMessenger
    built = _fakeHioClient(monkeypatch)
    HTTPStreamMessenger(hab=None, wit="EWit", url="http://8.8.8.8/", msg=b"x")
    assert built["hostname"] == "8.8.8.8"
    assert built.get("redirectable", True) is not False


def test_http_client_blocks_metadata(monkeypatch):
    """httpClient builds its URL from hab.fetchUrls; a metadata target is refused
    with a caught MissingEntryError-style refusal (ValidationError)."""
    from keri.app import agenting
    _fakeHioClient(monkeypatch)

    class FakeHab:
        def fetchUrls(self, eid, scheme=None):
            return {scheme: "http://169.254.169.254/"} if scheme == "http" else {}

    with pytest.raises(ValidationError):
        agenting.httpClient(FakeHab(), "EWit")


def test_http_client_uses_guarded_client(monkeypatch):
    from keri.app import agenting
    from keri import kering
    built = _fakeHioClient(monkeypatch)

    class FakeHab:
        def fetchUrls(self, eid, scheme=None):
            if scheme == kering.Schemes.https:
                return {kering.Schemes.https: "https://8.8.8.8/"}
            return {}

    agenting.httpClient(FakeHab(), "EWit")
    assert built["hostname"] == "8.8.8.8"
    assert built.get("redirectable", True) is not False
