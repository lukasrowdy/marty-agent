"""Media-only mitmdump addon for the guest: the second proxy that yt-dlp fetches through.

NEW FILE, 2026-09-28 (Jr overnight build, item 8 "video"). GUEST-SIDE code, staged on the
host; item 4's deploy installs it. Not run here.

Why a second proxy (skeptic, verified against setup_guard_guest.py): the page proxy
cannot carry media (non-page MIME refused, mitmdump body_size_limit=2m), and the guest
nftables let uid jrproxy reach any public :443 raw while user jr is dropped. So yt-dlp
must never run as jrproxy. Instead: this addon runs in a second mitmdump instance AS
jrproxy on 127.0.0.1:8081, yt-dlp runs as user jr with --proxy http://127.0.0.1:8081,
and nftables do not change.

CHANGED 2026-09-28 (fix helper, after the skeptic's item 8 verdict), what and why:
- A player-js response class: YouTube's player at www.youtube.com/s/player/.../base.js is
  2.97 MB of text/javascript, which the page class (2 MB, no javascript MIME) refused, so
  yt-dlp could never solve the n/sig challenge. Allowed only from host www.youtube.com,
  path prefix /s/player/, MIME text/javascript or application/javascript, 4 MB cap.
- MAX_REQUESTS per proxy session (200; refused requests count too).
- SESSION_CAP down from 150 MB to 110 MB: --max-filesize checks only the first response's
  Content-Length, chunked googlevideo transfers never abort on it, so this cap is the real
  stop: one 100 MB video plus its pages, player JS and captions, never a second video.
- The mitmdump command below carries the page proxy's flags: confdir=/var/lib/jrproxy so
  the SAME CA is used (a second instance without it mints a second CA the guest does not
  trust), upstream_cert=false, rawtcp=false, http2=false.
- _resolve asks for IPv4 only: the guest nftables drop IPv6, so an AAAA answer would pass
  the gate and then fail to connect.

Intended guest command (as jrproxy), also in MITMDUMP_ARGS below:
    mitmdump --listen-host 127.0.0.1 --listen-port 8081
             --set confdir=/var/lib/jrproxy --set upstream_cert=false
             --set rawtcp=false --set http2=false
             --set body_size_limit=100m --set connection_strategy=lazy
             -s /opt/jr-computer/guest_media_proxy.py
Host list: /etc/jr-computer/media-hosts.txt, one entry per line, the video site and its
CDN only (an exact host, or a leading dot for a suffix). Empty list = everything refused.
THIS FILE AND THE HOST LIST MUST BE HASHED INTO THE GUARD BASELINE (deploy notes).

What it enforces, in addition to mitmdump's own body_size_limit:
- https to port 443 only; GET and HEAD, plus POST only to the player endpoint paths
  (default /youtubei/v1/player) with a body of at most 64 KB;
- host on the list; upstream address must be global (no loopback, RFC1918, link-local,
  CGNAT 100.64/10, multicast, reserved), resolved before the request is let through;
- no cookies in or out (Cookie and Set-Cookie stripped);
- response MIME: media (video/*, audio/*, octet-stream) up to the 100 MB per-video cap,
  page/API/subtitle/manifest types up to 2 MB, the YouTube player script up to 4 MB from
  its own host and path only, everything else refused;
- at most 200 requests and a running total of 110 MB per proxy session, then everything
  is refused.

The hooks take duck-typed flow objects so the tests run without mitmproxy installed.
"""

from __future__ import annotations

import ipaddress
import os
import socket

try:  # only present inside the guest
    from mitmproxy import http as _mitm_http
except ImportError:  # pragma: no cover - the host has no mitmproxy
    _mitm_http = None


MEDIA_CAP = 100 * 1024 * 1024
PAGE_CAP = 2 * 1024 * 1024
PLAYER_JS_CAP = 4 * 1024 * 1024
POST_BODY_CAP = 64 * 1024
SESSION_CAP = 110 * 1024 * 1024
MAX_REQUESTS = 200
MEDIA_MIME = ("video/", "audio/", "application/octet-stream")
PAGE_MIME = ("text/html", "application/json", "text/vtt", "application/x-subrip",
             "text/xml", "application/xml", "text/plain", "application/x-mpegurl",
             "application/vnd.apple.mpegurl", "application/dash+xml", "application/ttml+xml")
PLAYER_JS_HOST = "www.youtube.com"
PLAYER_JS_PREFIX = "/s/player/"
PLAYER_JS_MIME = ("text/javascript", "application/javascript")
DEFAULT_POST_PATHS = ("/youtubei/v1/player",)
HOSTS_FILE = "/etc/jr-computer/media-hosts.txt"
MITMDUMP_ARGS = ("mitmdump", "--listen-host", "127.0.0.1", "--listen-port", "8081",
                 "--set", "confdir=/var/lib/jrproxy", "--set", "upstream_cert=false",
                 "--set", "rawtcp=false", "--set", "http2=false",
                 "--set", "body_size_limit=100m", "--set", "connection_strategy=lazy",
                 "-s", "/opt/jr-computer/guest_media_proxy.py")


def load_hosts(path=HOSTS_FILE) -> list:
    try:
        with open(path, encoding="utf-8") as stream:
            rows = [line.strip().lower() for line in stream]
    except OSError:
        return []
    return [row for row in rows if row and not row.startswith("#")]


def is_global_address(text) -> bool:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if (address.is_loopback or address.is_private or address.is_link_local or
        address.is_multicast or address.is_reserved or address.is_unspecified or
        not address.is_global):
        return False
    if isinstance(address, ipaddress.IPv4Address) and address in ipaddress.ip_network("100.64.0.0/10"):  # secret-scan: allow (the CGNAT block, not an address)
        return False
    return True


def _resolve(host) -> list:
    """IPv4 answers only: the guest nftables drop IPv6."""
    try:
        return sorted({row[4][0] for row in socket.getaddrinfo(host, 443, family=socket.AF_INET,
                                                               type=socket.SOCK_STREAM)})
    except OSError:
        return []


def is_player_js(host, path, mime) -> bool:
    """YouTube's player script and nothing else: its host, its path prefix (no dot segments),
    a javascript MIME."""
    if type(host) is not str or type(path) is not str:
        return False
    clean = path.split("?", 1)[0]
    return (host.lower().rstrip(".") == PLAYER_JS_HOST and clean.startswith(PLAYER_JS_PREFIX) and
            ".." not in clean.split("/") and mime in PLAYER_JS_MIME)


class MediaGate:
    def __init__(self, hosts, *, post_paths=DEFAULT_POST_PATHS, resolver=_resolve,
                 media_cap=MEDIA_CAP, page_cap=PAGE_CAP, session_cap=SESSION_CAP,
                 max_requests=MAX_REQUESTS):
        self.hosts = [h.lower() for h in hosts]
        self.post_paths = tuple(post_paths)
        self.resolver = resolver
        self.media_cap = media_cap
        self.page_cap = page_cap
        self.session_cap = session_cap
        self.max_requests = max_requests
        self.session_bytes = 0
        self.requests = 0
        self.refusals = []

    @classmethod
    def from_env(cls):
        paths = os.environ.get("JR_MEDIA_POST_PATHS")
        post_paths = tuple(p for p in paths.split(",") if p) if paths else DEFAULT_POST_PATHS
        return cls(load_hosts(os.environ.get("JR_MEDIA_HOSTS", HOSTS_FILE)), post_paths=post_paths)

    def host_allowed(self, host) -> bool:
        if type(host) is not str or not host:
            return False
        host = host.lower().rstrip(".")
        for entry in self.hosts:
            if entry.startswith("."):
                if host.endswith(entry) or host == entry[1:]:
                    return True
            elif host == entry:
                return True
        return False

    def _refuse(self, flow, code, reason):
        self.refusals.append((code, reason))
        if _mitm_http is not None:
            flow.response = _mitm_http.Response.make(code, reason.encode("ascii"),
                                                     {"Content-Type": "text/plain"})
        else:
            flow.kill()

    # ---- mitmproxy hooks

    def request(self, flow):
        request = flow.request
        headers = request.headers
        for name in [h for h in headers.keys() if h.lower() in {"cookie", "proxy-authorization"}]:
            del headers[name]
        self.requests += 1
        if self.requests > self.max_requests:
            return self._refuse(flow, 429, "media session request cap reached")
        if request.scheme != "https" or int(request.port) != 443:
            return self._refuse(flow, 403, "https to port 443 only")
        if not self.host_allowed(request.host):
            return self._refuse(flow, 403, "host is not on the media list")
        method = request.method.upper()
        if method == "POST":
            if request.path.split("?", 1)[0] not in self.post_paths:
                return self._refuse(flow, 405, "POST only to the player endpoint")
            if len(request.content or b"") > POST_BODY_CAP:
                return self._refuse(flow, 413, "POST body too large")
        elif method not in {"GET", "HEAD"}:
            return self._refuse(flow, 405, "GET, HEAD or player POST only")
        addresses = self.resolver(request.host)
        if not addresses or not all(is_global_address(a) for a in addresses):
            return self._refuse(flow, 403, "upstream address is not global")
        if self.session_bytes >= self.session_cap:
            return self._refuse(flow, 429, "media session byte cap reached")

    def responseheaders(self, flow):
        response = flow.response
        headers = response.headers
        for name in [h for h in headers.keys() if h.lower() == "set-cookie"]:
            del headers[name]
        mime = headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        request = getattr(flow, "request", None)
        if any(mime.startswith(prefix) for prefix in MEDIA_MIME):
            cap = self.media_cap
        elif mime in PAGE_MIME:
            cap = self.page_cap
        elif request is not None and is_player_js(getattr(request, "host", None),
                                                  getattr(request, "path", None), mime):
            cap = PLAYER_JS_CAP
        else:
            return self._refuse(flow, 415, "response type is neither media, a page, nor the player script")
        length = headers.get("Content-Length")
        if length is not None:
            try:
                declared = int(length)
            except ValueError:
                return self._refuse(flow, 502, "bad content length")
            if declared > cap or self.session_bytes + declared > self.session_cap:
                return self._refuse(flow, 413, "response over its byte cap")
            self.session_bytes += declared

    def response(self, flow):
        response = flow.response
        if response is None or response.headers.get("Content-Length") is not None:
            return
        size = len(response.content or b"")
        self.session_bytes += size
        if size > self.media_cap or self.session_bytes > self.session_cap:
            self._refuse(flow, 413, "streamed response over its byte cap")


if _mitm_http is not None:  # pragma: no cover - guest only
    addons = [MediaGate.from_env()]
