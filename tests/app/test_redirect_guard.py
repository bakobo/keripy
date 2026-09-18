# -*- encoding: utf-8 -*-
"""
tests.app.test_redirect_guard

redirectable=False (a zero redirect budget)
breaks endpoints behind an http->https ingress (k8s 301/308). RedirectGuardedClient
allows a small budget but re-runs the address policy on each redirect target, so a
peer cannot redirect keripy into a blocked range.
"""
import pytest

from keri.app import httping


def _client(maxRedirects=httping.MAX_REDIRECTS):
    # Construct without opening a socket (hio connects lazily on reopen/service).
    return httping.RedirectGuardedClient(scheme="http", hostname="8.8.8.8",
                                         port=80, maxRedirects=maxRedirects)


def _hop(location, host="8.8.8.8", scheme="http", port=80, path="/"):
    return {"status": 301,
            "headers": {"location": location},
            "request": {"scheme": scheme, "host": host, "port": port, "path": path}}


def test_one_hop_http_to_https_allowed():
    c = _client()
    # http://8.8.8.8/  -> https://8.8.8.8/secure  (allowed public host)
    c.redirects = [_hop("https://8.8.8.8/secure")]
    assert c._redirectPermitted() is True


def test_relative_redirect_stays_on_validated_host():
    c = _client()
    c.redirects = [_hop("/elsewhere")]
    assert c._redirectPermitted() is True


def test_redirect_to_metadata_blocked():
    c = _client()
    c.redirects = [_hop("http://169.254.169.254/latest/")]
    assert c._redirectPermitted() is False


def test_redirect_to_metadata_decimal_form_blocked():
    c = _client()
    c.redirects = [_hop("http://2852039166/")]
    assert c._redirectPermitted() is False


def test_over_budget_refused():
    c = _client(maxRedirects=1)
    # two redirects already accumulated -> exceeds the budget of 1
    c.redirects = [_hop("https://8.8.8.8/a"), _hop("https://8.8.8.8/b")]
    assert c._redirectPermitted() is False


def test_redirect_override_finalizes_blocked_hop_without_following():
    c = _client()
    c.redirects = [_hop("http://169.254.169.254/latest/")]
    c.waited = True
    c.redirect()  # must NOT follow; must surface the 3xx as terminal
    assert len(c.responses) == 1
    assert c.responses[-1]["status"] == 301
    assert c.redirects == []
    assert c.waited is False
