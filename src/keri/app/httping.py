# -*- encoding: utf-8 -*-
"""
keri.peer.httping module

"""
import datetime
import ipaddress
import json
import socket
from dataclasses import dataclass
from urllib import parse

import falcon
from hio.base import doing
from hio.core import http
from hio.help import Hict, ogler

from ..kering import (ShortageError, ExtractionError,
                      ColdStartError, ValidationError, sniff, Colds)
from ..core import SerderKERI
from ..end import designature
from ..help import nowUTC


logger = ogler.getLogger()

CESR_CONTENT_TYPE = "application/cesr"
CESR_ATTACHMENT_HEADER = "CESR-ATTACHMENT"
CESR_DESTINATION_HEADER = "CESR-DESTINATION"

#: Maximum size in bytes of an inbound HTTP request body keripy will read from a
#: front-door route. A KERI event plus its CESR attachment set is a few KB even
#: for a large multisig or credential-chain POST; 5 MiB leaves room for hundreds
#: of events while refusing the unbounded body that exhausts memory. NOTE:
#: this is a PARTIAL mitigation. hio buffers the whole request body before falcon
#: dispatches, so this handler-level check runs after the bytes are resident; it
#: removes the json.load amplification and rejects an over-declared Content-Length
#: without parsing, but full closure of the oversize-body case requires a
#: body limit in the hio HTTP server layer.
MAX_CESR_BODY_SIZE = 5 * 1024 * 1024

#: URL schemes keripy will fetch. Anything else (file://, gopher://, ...) is an
#: fetch target, never a legitimate KERI endpoint.
ALLOWED_URL_SCHEMES = ("http", "https")

#: When True, checkUrl additionally refuses RFC-1918 / ULA private ranges
#: (10/8, 172.16/12, 192.168/16, fc00::/7). Default False: private-network
#: witnesses / OOBIs are a normal KERI deployment and a private-IP fetch carries
#: no KERI trust risk (the KEL/TEL is cryptographically verified regardless of
#: fetch origin), so blocking them is availability loss for no doctrinal gain.
#: This opt-in is DECOUPLED from the link-local / cloud-metadata block below,
#: which is unconditional: flipping this flag never re-arms metadata access.
BLOCK_PRIVATE_ADDRESSES = False


def _addressBlocked(ip, blockPrivate):
    """Return True if ip (an ipaddress object) is a destination keripy must not
    fetch.

    The truly-unroutable / infrastructure classes are blocked UNCONDITIONALLY
    with no opt-out: link-local (169.254.0.0/16 and fe80::/10, which is how the
    169.254.169.254 cloud-metadata access is reached), multicast, reserved and the
    unspecified address. Loopback is always allowed (local dev / tests). RFC-1918
    / ULA private ranges are allowed by default and only blocked when the
    blockPrivate opt-in is set — decoupled from the classes above so an operator
    can permit private OOBIs without ever re-arming metadata access.
    """
    if ip.is_loopback:  # local dev / tests use 127.0.0.1 / ::1
        return False
    # IPv4-mapped IPv6 (::ffff:169.254.169.254) already reports is_link_local via
    # ipaddress, so the metadata block below covers the mapped form too.
    if ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    if ip.is_private:  # RFC-1918 / ULA: opt-in only
        return blockPrivate
    return False


def checkUrl(url, *, blockPrivate=None):
    """Validate a URL before keripy fetches it, guarding against fetches steered by a
    malicious designated witness or an introduced OOBI.

    Enforces a scheme allow-list and refuses hosts that resolve to a link-local
    (169.254.169.254 cloud metadata), multicast, reserved or unspecified address
    unconditionally. RFC-1918 / ULA private ranges are allowed by default and
    refused only when blockPrivate (or the module BLOCK_PRIVATE_ADDRESSES flag)
    is set. Loopback is allowed. Literal-IP metadata/private targets are caught
    directly; a hostname is resolved and each resolved address is checked, so
    decimal/hex/octal-encoded and IPv4-mapped metadata forms are caught via the
    resolver. A hostname that cannot be resolved is passed through (the fetch
    fails on its own).

    Parameters:
        url (str): the URL about to be fetched.
        blockPrivate (bool|None): opt-in to also block private ranges; None uses
            the module default BLOCK_PRIVATE_ADDRESSES.

    Returns:
        the urlparse result on success.

    Raises:
        kering.ValidationError: if the scheme is not allowed or the host is a
            blocked destination.
    """
    if blockPrivate is None:
        blockPrivate = BLOCK_PRIVATE_ADDRESSES

    purl = parse.urlparse(url)
    if purl.scheme not in ALLOWED_URL_SCHEMES:
        raise ValidationError(f"Invalid URL scheme {purl.scheme!r}; only "
                              f"{ALLOWED_URL_SCHEMES} are fetched. url={url!r}")
    host = purl.hostname
    if not host:
        raise ValidationError(f"URL {url!r} has no host.")

    try:  # literal IP address?
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if ip is not None:
        if _addressBlocked(ip, blockPrivate):
            raise ValidationError(f"URL host {host} is a blocked non-public "
                                  f"address; refusing to fetch (address policy). url={url!r}")
        return purl

    # a hostname (which may be a decimal/hex/octal-encoded IP): block if it
    # resolves to a blocked address; if it cannot be resolved, let the fetch
    # itself fail rather than false-positive here.
    try:
        infos = socket.getaddrinfo(host, purl.port, proto=socket.IPPROTO_TCP)
    except OSError:
        infos = []
    for info in infos:
        try:
            rip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _addressBlocked(rip, blockPrivate):
            raise ValidationError(f"URL host {host} resolves to blocked "
                                  f"non-public address {rip}; refusing to fetch "
                                  f"(address policy). url={url!r}")
    return purl


#: Default maximum number of HTTP redirects keripy will follow. redirectable=False
#: (a zero budget) breaks endpoints behind an http->https ingress (k8s 301/308);
#: a small budget with per-hop revalidation keeps those working without letting a
#: peer redirect keripy into a blocked range.
MAX_REDIRECTS = 3


class RedirectGuardedClient(http.clienting.Client):
    """hio HTTP Client that follows a bounded number of redirects and re-runs the
    address policy (checkUrl) on each redirect target before following it.

    hio's Client redirects unconditionally when redirectable is True; setting it
    False (a zero budget) breaks endpoints behind an http->https ingress. This
    subclass allows redirects but caps them at maxRedirects and refuses any hop
    whose resolved target fails checkUrl, so a peer cannot use a 3xx to redirect
    keripy into 169.254.169.254 or another blocked range. A refused/over-budget redirect surfaces the 3xx as the terminal
    response instead of being followed, so nothing crashes and the caller simply
    sees a non-2xx result.
    """

    def __init__(self, *args, maxRedirects=MAX_REDIRECTS, blockPrivate=None, **kwa):
        self.maxRedirects = maxRedirects
        self._blockPrivate = blockPrivate
        kwa.setdefault("redirectable", True)
        super(RedirectGuardedClient, self).__init__(*args, **kwa)

    def _redirectPermitted(self):
        """Return True if the pending redirect (self.redirects[-1]) may be
        followed: within the redirect budget AND its resolved target passes the
        address policy. A relative/self redirect stays on the already-validated host,
        so it re-validates trivially."""
        if not self.redirects:
            return True
        if len(self.redirects) > self.maxRedirects:
            logger.error(f"refusing redirect: exceeds budget of {self.maxRedirects}")
            return False

        latest = self.redirects[-1]
        headers = latest.get("headers") or {}
        location = headers.get("location")
        if not location:
            return True

        req = latest.get("request") or {}
        scheme = req.get("scheme") or getattr(self.requester, "scheme", "http")
        host = req.get("host") or getattr(self.requester, "hostname", "")
        port = req.get("port") or getattr(self.requester, "port", None)
        base = f"{scheme}://{host}:{port}{req.get('path') or '/'}"
        target = parse.urljoin(base, location)
        try:
            checkUrl(target, blockPrivate=self._blockPrivate)
        except ValidationError as e:
            logger.error(f"refusing redirect to {location!r}: {e}")
            return False
        return True

    def redirect(self):
        """Revalidate and budget-check before delegating to hio's redirect."""
        if self.redirects and not self._redirectPermitted():
            # Surface the 3xx as the terminal response rather than following it.
            resp = self.redirects.pop()
            if self.redirects:
                resp["redirects"] = list(self.redirects)
            self.redirects = []
            self.responses.append(resp)
            self.waited = False
            if self.respondent is not None:
                self.respondent.redirectant = False
                self.respondent.redirected = False
            return
        return super(RedirectGuardedClient, self).redirect()


class SignatureValidationComponent(object):
    """ Validate SKWA signatures """

    def __init__(self, hby, pre):
        self.hby = hby
        self.pre = pre

    def process_request(self, req, resp):
        """ Process request to ensure has a valid signature from controller

        Parameters:
            req: Http request object
            resp: Http response object

        """
        sig = req.headers.get("SIGNATURE")
        # Bound the body before parsing it.
        raw = readBoundedBody(req)
        ked = json.loads(raw)
        ser = json.dumps(ked).encode("utf-8")
        if not self.validate(sig=sig, ser=ser):
            resp.complete = True
            resp.status = falcon.HTTP_401
            return

    def validate(self, sig, ser):
        signages = designature(sig)
        markers = signages[0].markers

        if self.pre not in self.hby.kevers:
            return False

        verfers = self.hby.kevers[self.pre].verfers
        for idx, verfer in enumerate(verfers):
            key = str(idx)
            if key not in markers:
                return False
            siger = markers[key]
            siger.verfer = verfer

            if not verfer.verify(siger.raw, ser):
                return False

        return True


def enforceMaxBody(req, limit=MAX_CESR_BODY_SIZE):
    """Reject a declared Content-Length over ``limit`` with 413 before the body is
    read at all. PARTIAL: hio has already buffered the body by the time a falcon
    handler runs, so this cannot fully close the oversize-body case (that
    needs an hio server-layer limit); it removes parse amplification and refuses
    an honestly-declared over-cap request without copying it.

    Parameters:
        req (falcon.Request): inbound request.
        limit (int): maximum allowed body size in bytes.
    """
    clen = req.content_length
    if clen is not None and clen > limit:
        raise falcon.HTTPError(falcon.HTTP_413,
                               title="Request body too large",
                               description=f"Request body of {clen} bytes exceeds "
                                           f"the maximum allowed size of {limit} bytes.")


def readBoundedBody(req, limit=MAX_CESR_BODY_SIZE):
    """Reject an over-cap declared Content-Length, then read at most ``limit`` bytes
    (+1 to detect overflow) so an undeclared / chunked body is bounded on read
    too. Returns the raw body bytes. Raises falcon HTTP 413 if over the cap.

    Parameters:
        req (falcon.Request): inbound request.
        limit (int): maximum allowed body size in bytes.
    """
    enforceMaxBody(req, limit)
    raw = req.bounded_stream.read(limit + 1)
    if len(raw) > limit:
        raise falcon.HTTPError(falcon.HTTP_413,
                               title="Request body too large",
                               description=f"Request body exceeds the maximum "
                                           f"allowed size of {limit} bytes.")
    return raw


@dataclass
class CesrRequest:
    payload: dict
    attachments: str


def parseCesrHttpRequest(req):
    """
    Parse Falcon HTTP request and create a CESR message from the body of the request and the two
    CESR HTTP headers (Date, Attachment).

    Parameters
        req (falcon.Request) http request object in CESR format:

    """
    if req.content_type != CESR_CONTENT_TYPE:
        raise falcon.HTTPError(falcon.HTTP_NOT_ACCEPTABLE,
                               title="Content type error",
                               description="Unacceptable content type.")

    # Bound the body before parsing: rejects an over-cap declared Content-Length
    # with 413 and removes the json.load amplification.
    raw = readBoundedBody(req)
    try:
        data = json.loads(raw)
    except ValueError:
        raise falcon.HTTPError(falcon.HTTP_400,
                               title="Malformed JSON",
                               description="Could not decode the request body. The "
                                           "JSON was incorrect.")

    if CESR_ATTACHMENT_HEADER not in req.headers:
        raise falcon.HTTPError(falcon.HTTP_PRECONDITION_FAILED,
                               title="Attachment error",
                               description="Missing required attachment header.")
    attachment = req.headers[CESR_ATTACHMENT_HEADER]

    cr = CesrRequest(
        payload=data,
        attachments=attachment)

    return cr


def createCESRRequest(msg, client, dest, path=None):
    """
    Turns a KERI message into a CESR http request against the provided hio http Client

    Parameters
       msg:  KERI message parsable as Serder.raw
       dest (str): qb64 identifier prefix of destination controller
       client: hio http Client that will send the message as a CESR request
       path (str): path to post to

    """
    path = path if path is not None else "/"

    try:
        serder = SerderKERI(raw=msg)
    except ShortageError as ex:  # need more bytes
        raise ExtractionError("unable to extract a valid message to send as HTTP")
    else:  # extracted successfully
        del msg[:serder.size]  # strip off event from front of ims

    attachments = bytearray(msg)
    body = serder.raw

    headers = Hict([
        ("Content-Type", CESR_CONTENT_TYPE),
        ("Content-Length", len(body)),
        ("connection", "close"),
        (CESR_ATTACHMENT_HEADER, attachments),
        (CESR_DESTINATION_HEADER, dest)
    ])

    client.request(
        method="POST",
        path=path,
        headers=headers,
        body=body
    )


def streamCESRRequests(client, ims, dest, path=None, headers=None):
    """
    Turns a stream of KERI messages into CESR http requests against the provided hio http Client

    Parameters
       client (Client): hio http Client that will send the message as a CESR request
       ims (bytearray):  stream of KERI messages parsable as Serder.raw
       dest (str): qb64 identifier prefix of destination controller
       path (str): path to post to

    Returns
       int: Number of individual requests posted

    """
    path = path if path is not None else "/"
    path = parse.urljoin(client.requester.path, path)

    cold = sniff(ims)  # check for spurious counters at front of stream
    if cold in (Colds.txt, Colds.bny):  # not message error out to flush stream
        # replace with pipelining here once CESR message format supported.
        raise ColdStartError("Expecting message counter tritet={}"
                                    "".format(cold))

    # Otherwise its a message cold start
    cnt = 0
    while ims:  # extract and deserialize message from ims
        try:
            serder = SerderKERI(raw=ims)
        except ShortageError as ex:  # need more bytes
            raise ExtractionError("unable to extract a valid message to send as HTTP")
        else:  # extracted successfully
            del ims[:serder.size]  # strip off event from front of ims

        attachment = bytearray()
        while ims and ims[0] != 0x7b:  # not new message so process attachments, must support CBOR and MsgPack
            attachment.append(ims[0])
            del ims[:1]

        body = serder.raw

        headers = headers if headers is not None else Hict()
        heads = (Hict([
            ("Content-Type", CESR_CONTENT_TYPE),
            ("Content-Length", len(body)),
            (CESR_ATTACHMENT_HEADER, attachment),
            (CESR_DESTINATION_HEADER, dest)
        ]))
        heads.update(headers)

        client.request(
            method="POST",
            path=path,
            headers=heads,
            body=body
        )
        cnt += 1

    return cnt


class Clienter(doing.DoDoer):
    """
    Clienter is a DoDoer that manages hio HTTP clients using a ClientDoer for each HTTP request.
    It executes HTTP requests using a HIO HTTP Client run by a ClientDoer. Once a request has
    received a response then the corresponding Doer is removed from this Clienter.

    Doers:
        - clientDo: Periodically checks for stale clients and removes them if they have not received a response
          within the specified timeout period.
    """

    TimeoutClient = 300  # seconds to wait for response before removing client, default is 5 minutes

    def __init__(self):
        """Initialize clienter with an empty list of client tuples.

        Attributes:
            clients (list[tuple]): Active client tuples, each containing a
                ``ClientDoer`` instance, an hio HTTP ``Client`` instance,
                and a ``datetime`` timestamp.
            doers (list): Doers managed by this Clienter, initialized with clientDo.
        """
        self.clients = []
        doers = [doing.doify(self.clientDo)]
        super(Clienter, self).__init__(doers=doers)

    def request(self, method, url, body=None, headers=None):
        """
        Perform an HTTP request using a hio http Client and ClientDoer and returns the Client.

        Parameters:
            method (str): HTTP method to use (e.g., "GET", "POST")
            url (str): URL to send the request to
            body (str or bytes, optional): Body of the request, defaults to None
            headers (dict, optional): Headers to include in the request, defaults to None

        Returns:
            http.clienting.Client: The hio HTTP Client used for the request, or None if an error occurs.
        """
        try:  # address policy: scheme allow-list + block non-public hosts
            purl = checkUrl(url)
        except ValidationError as e:
            logger.error(f"refusing to fetch blocked url={url!r}: {e}")
            return None

        try:
            client = RedirectGuardedClient(scheme=purl.scheme,
                                           hostname=purl.hostname,
                                           port=purl.port,
                                           portOptional=True)
        except Exception as e:
            print(f"error establishing client connection={e}")
            return None

        if hasattr(body, "encode"):
            body = body.encode("utf-8")

        client.request(
            method=method,
            path=f"{purl.path}?{purl.query}",
            qargs=None,
            headers=headers,
            body=body
        )

        clientDoer = http.clienting.ClientDoer(client=client)
        self.extend([clientDoer])
        self.clients.append((client, clientDoer, nowUTC()))

        return client

    def remove(self, client):
        """
        Find a client tuple by hio HTTP Client and remove it and its Doer from the Clienter.

        Parameters:
            client (http.clienting.Client): The hio HTTP Client to remove from the Clienter.
        """
        doers = [(c, d, dt) for (c, d, dt) in self.clients if c == client]
        if len(doers) == 0:
            return

        tup = doers[0]
        self.clients.remove(doers[0])
        (_, doer, _) = tup
        super(Clienter, self).remove([doer])

    def clientDo(self, tymth, tock=0.0, **kwa):
        """ Periodically prune stale clients

        Process existing clients and prune any that have receieved a response longer than timeout

        Parameters:
            tymth (function): injected function wrapper closure returned by .tymen() of
                Tymist instance. Calling tymth() returns associated Tymist .tyme.
            tock (float): injected initial tock value

        """
        self.wind(tymth)
        self.tock = tock
        yield self.tock

        while True:
            toRemove = []
            for (client, doer, dt) in self.clients:
                if client.responses:
                    now = nowUTC()
                    if (now - dt) > datetime.timedelta(seconds=self.TimeoutClient):
                        toRemove.append(client)

                yield self.tock

            for client in toRemove:
                self.remove(client)

            yield self.tock
