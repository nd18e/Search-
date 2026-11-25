"""search.py - quick website safety check for the terminal.

DNS, server country, TLS, security headers, visitor data leaks, exposed files
and mail DNS (SPF / DMARC). No scanning, no exploitation: only test sites you
own or have permission to test. Standard library only (Python 3.9+).
  python search.py example.com --yes --save history.json

Exit codes: 0 safe, 1 caution, 2 not safe, 3 unknown, 64 bad input.
"""
from __future__ import annotations

import argparse
import html.parser
import http.client
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import sys
import textwrap
import threading
import time
import urllib.request
import warnings
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

UA = "Search/3.1 (safety check)"
EVIL = "https://search.invalid"
DNS_FALLBACK = ("1.1.1.1", "8.8.8.8")
REDIR = {301, 302, 303, 307, 308}
WAF_HEADERS = ("cf-mitigated", "x-sucuri-id", "x-iinfo", "x-datadome", "x-amzn-waf-action")
BODY_MAX = 256 * 1024
PATH_TIMEOUT = 5
HSTS_MIN = 15552000
CERT_WARN = 30
LOW, GOOD = 55, 77
HISTORY_KEEP = 50

WEIGHTS = {"tls": 25, "tls_versions": 4, "redirect": 8, "http": 4, "hsts": 12, "csp": 14,
     "xfo": 6, "xcto": 6, "referrer": 6, "permissions": 5, "cookies": 5, "cors": 8,
     "versions": 4, "content": 8, "exposed": 15}
HEADER_W = sum(WEIGHTS[k] for k in ("hsts", "csp", "xfo", "xcto", "referrer", "permissions"))
POINTS = {"ok": 1.0, "info": 1.0, "warn": 0.5, "miss": 0.0, "bad": 0.0}
EXIT = {"SAFE": 0, "CAUTION": 1, "NOT SAFE": 2, "UNKNOWN": 3}

M = {
  "a.dns": "DNS address", "a.location": "Server location", "a.tls": "TLS certificate",
  "a.tls_versions": "TLS versions", "a.caa": "CAA record", "a.redirect": "HTTP -> HTTPS", "a.http": "HTTP response",
  "a.https": "HTTPS", "a.headers": "Security headers", "a.hsts": "HSTS", "a.csp": "Content-Security-Policy",
  "a.xfo": "X-Frame-Options", "a.xcto": "X-Content-Type-Options", "a.referrer": "Referrer-Policy",
  "a.permissions": "Permissions-Policy", "a.cookies": "Cookies", "a.cors": "CORS", "a.versions": "Version leaks",
  "a.content": "Forms, mixed content", "a.scripts": "Third-party hosts", "a.sri": "SRI", "a.leaks": "Data leaks",
  "a.exposed": "Exposed files", "a.security_txt": "security.txt", "a.mx": "Mail MX", "a.spf": "Mail SPF",
  "a.dmarc": "Mail DMARC", "a.mtasts": "Mail MTA-STS", "a.step": "Check", "lookup": "Lookup failed: {err}.",
  "dns.ok": "{v4} IPv4 / {v6} IPv6: {shown}.", "dns.more": " (+{n} more)", "dns.none": "No A/AAAA record.",
  "loc.noip": "No IP to look up.", "loc.off": "Skipped (--no-geo).", "loc.private": "{ip} is not a public address.",
  "loc.fail": "No country data for {ip}.", "loc.ok": "{ip} is in {place} ({code}), network: {org}.{cdn}",
  "loc.cdn": " Looks like a CDN, the real server may be elsewhere.",
  "tls.ok": "Trusted cert from {issuer}, {ver}, {days} days left.{soon}", "tls.soon": " Renew soon.",
  "tls.bad": "Certificate not trusted ({why}). Browsers will warn visitors.",
  "tls.chain": "Incomplete chain ({why}). Server should send intermediate certs.",
  "tls.nores": "Name does not resolve.", "tls.timeout": "Port {port} did not answer in time.",
  "tls.old": "Only old TLS ({v}); browsers refuse it.", "tls.hs": "Handshake failed ({why}).",
  "tls.conn": "Cannot connect to port {port} ({why}).", "tlsv.legacy": "Still accepts TLS 1.0/1.1. ALPN: {alpn}.",
  "tlsv.both": "TLS 1.2 and 1.3. ALPN: {alpn}.", "tlsv.t13": "Only TLS 1.3. ALPN: {alpn}.",
  "tlsv.t12": "No TLS 1.3, only 1.2. ALPN: {alpn}.", "tlsv.unk": "Versions unconfirmed. ALPN: {alpn}.",
  "caa.ok": "CAA limits certificate issuers: {rec}.", "caa.none": "No CAA record (optional).",
  "red.ok": "HTTP redirects to HTTPS ({code}).", "red.unclear": "HTTP redirects ({code}), not clearly to HTTPS.",
  "red.none": "HTTP answers {code}, no redirect to HTTPS.", "red.noans": "Port 80 closed (HTTPS-only is fine).",
  "red.port": "Custom port, not checked.", "http.none": "No answer ({why}).",
  "http.ok": "{code}. Home page answers normally.", "http.redir": "{code} to {to}; not scored.",
  "http.waf": "{code}. Looks like a WAF/bot challenge; not scored.",
  "http.other": "{code}. Some sites treat bots differently.", "http.via": " via {host}",
  "https.bad": "Only plain HTTP: anything visitors type can be read on the network.", "hdr.noresp": "No response.",
  "hdr.nohttps": "Skipped, no HTTPS.", "hdr.skip": "Not scored: redirect or WAF, not the real page.",
  "hsts.ok": "max-age={age}{flags}.", "hsts.nosub": "max-age={age}{flags}; no includeSubDomains.",
  "hsts.short": "max-age={age} is under 180 days.", "hsts.miss": "Not sent; browsers aren't forced to use HTTPS.",
  "csp.ok": "Policy present and limits content sources.", "csp.weak": "{d} is weak: {items}.",
  "csp.style": "style-src allows 'unsafe-inline'.", "csp.report": "Report-only, not enforced.",
  "csp.miss": "Not sent (optional).", "xfo.ok": "Set to {v}.", "xfo.csp": "CSP frame-ancestors covers it.",
  "xfo.odd": "Unusual value: {v}.", "xfo.miss": "Not sent; page can be framed.", "xcto.ok": "nosniff set.",
  "xcto.odd": "Value is not nosniff.", "xcto.miss": "Not sent.", "ref.weak": "'{v}' leaks full URLs.",
  "ref.ok": "Set to {v}.", "ref.miss": "Not sent, browser default.", "perm.ok": "Restricts browser features.",
  "perm.old": "Only old Feature-Policy.", "perm.miss": "Not sent (optional).",
  "leaks.skip": "Skipped, no real page.", "cookies.none": "No cookies on the home page.",
  "cookies.warn": "{n} cookie(s); {problems}.", "cookies.nosecure": "no Secure: {names}",
  "cookies.nohttp": "session cookie without HttpOnly: {names}",
  "cookies.samesite": "{n} cookie(s); some lack SameSite.", "cookies.ok": "{n} cookie(s), flags fine.",
  "cors.bad": "Trusts foreign origins ({names}) with credentials: other sites could read a logged-in visitor's data.",
  "cors.warn": "Reflects foreign Origin ({names}).", "cors.star": "Any site may read public responses.",
  "cors.ok": "No access for foreign origins.", "ver.warn": "Headers reveal software: {items}.",
  "ver.ok": "No versions in headers.", "content.nohtml": "No HTML to inspect.",
  "content.form": "Form posts over plain HTTP: {url}", "content.mixed": "{n} plain-HTTP resource(s), e.g. {url}",
  "content.ok": "No HTTP forms or mixed content.", "scripts.tracker": "{n} external host(s), trackers: {names}.",
  "scripts.ext": "{n} external host(s): {names}.", "scripts.ok": "No third-party resources.",
  "sri.missing": "No integrity attribute for: {names}.", "sri.ok": "External scripts/styles use SRI.",
  "exp.skip": "Skipped, no answer from site.", "exp.hit": "Publicly readable: {hits}.",
  "exp.early": "Stopped early, server stopped answering.",
  "exp.redirects": "Every path redirected, nothing checked.", "exp.ok": "None of {n} sensitive paths exposed.",
  "exp.hitlog": "EXPOSED {path} - {label}", "exp.clean": "clean {path} (HTTP {status})",
  "exp.nores": "no answer for {path}", "sectxt.ok": "security.txt published.",
  "sectxt.none": "No security.txt (optional).", "mx.ok": "Mail servers: {servers}.", "mx.none": "No MX records.",
  "r.web": "web/platform host", "r.nomx": "no MX", "r.mxfail": "MX lookup failed", "spf.ok": "SPF ends with {q}all.",
  "spf.open": "SPF ends with +all: anyone can send as this domain.",
  "spf.weak": "SPF final 'all' is permissive or missing.",
  "spf.multi": "{n} SPF records; receivers treat that as an error.", "spf.miss": "No SPF; mail is easier to fake.",
  "spf.none": "No SPF (not expected: {reason}).", "dmarc.ok": "DMARC p={policy}{src}.",
  "dmarc.mon": "DMARC monitoring only (p={policy}){src}.", "dmarc.src": " (from {org})",
  "dmarc.miss": "No DMARC record.", "dmarc.none": "No DMARC (not expected: {reason}).",
  "mta.ok": "MTA-STS published.", "mta.none": "No MTA-STS (optional).", "run.start": "Starting: {name}",
  "run.fail": "{name} failed: {err}", "s.dns": "DNS lookup", "s.location": "Server country",
  "s.tls": "TLS certificate", "s.redirect": "HTTP redirect", "s.page": "Page and headers", "s.leaks": "Data leaks",
  "s.exposed": "Exposed files", "s.mail": "Mail DNS", "v.SAFE": "SAFE", "v.CAUTION": "CAUTION",
  "v.NOT SAFE": "NOT SAFE", "v.UNKNOWN": "UNKNOWN",
  "adv.UNKNOWN": "The site did not answer, safety can't be judged.",
  "adv.NOT SAFE": "Do not enter passwords or personal data here.",
  "adv.CAUTION": "No critical problem, but several weaknesses. Don't share sensitive data unless you trust the owner.",
  "adv.MID": "No critical problem, but the score is only mid.", "adv.SAFE": "No obvious problems for visitors.",
  "sc.LOW": "LOW", "sc.MID": "MID", "sc.GOOD": "GOOD", "lv.ok": "OK", "lv.info": "INFO", "lv.warn": "WARN",
  "lv.miss": "MISS", "lv.bad": "BAD", "i.ip": "IP address", "i.loc": "Location", "i.net": "Network", "i.tls": "TLS",
  "i.http": "HTTP", "ui.title": "website safety check", "ui.results": "RESULTS FOR ",
  "ui.cols": "CHECK|STATUS|DETAILS", "ui.score": "SCORE", "ui.reasons": "Main reasons:", "ui.log": "LOG",
  "ui.status": "SAFETY STATUS", "ui.changes": "CHANGES SINCE {when}",
  "ui.delta": "Score: {old} -> {new} ({delta:+d})", "ui.nochg": "No check changed.",
  "ui.first": "First saved run, nothing to compare yet.",
  "ui.disc": "One-moment technical check. It can't see malware, phishing reputation or what the site does with your data.",
  "ui.consent": "I own this site or may test it [y/N]: ", "ui.noconsent": "  No consent, nothing was sent.",
  "ui.needyes": "--json needs --yes.", "ui.domain": "\nDomain (example.com), Q to quit: ",
  "ui.another": "Another domain? [y/N]: ", "ui.invalid": "  '{raw}' is not a valid domain.",
  "ui.savefail": "Could not save to {path}: {err}",
}

def t(key, **kw):
  s = M[key]
  return s.format(**kw) if kw else s

COLOR = False
PAL = {"ok": 82, "info": 45, "warn": 220, "miss": 214, "bad": 203, "dim": 244, "text": 252, "title": 255}

def use_color(off):
  global COLOR
  COLOR = not (off or os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb" or not sys.stdout.isatty())
  if COLOR and os.name == "nt":
    os.system("")

def paint(s, color, bold=False):
  if not COLOR:
    return s
  return f"\033[{'1;' if bold else ''}38;5;{PAL.get(color, color)}m{s}\033[0m"

def clean(x, n=0):
  s = re.sub(r"[\x00-\x1f\x7f-\x9f\s]+", " ", str(x)).strip()
  return s[:n] if n else s

def clip(s, n):
  return s if len(s) <= n else s[:max(0, n - 3)] + "..."

@dataclass
class Config:
  timeout: int = 8
  port: int = 443
  resolvers: list = field(default_factory=lambda: list(DNS_FALLBACK))
  geo: bool = True

@dataclass
class Finding:
  key: str
  area: str
  level: str
  detail: str
  w: float = 0
  pts: float | None = None

def F(key, level, msg, pts=None, w=None, **kw):
  return Finding(key, t("a." + key), level, t(msg, **kw), WEIGHTS.get(key, 0) if w is None else w, pts)

@dataclass
class Response:
  status: int
  reason: str
  headers: dict
  cookies: list
  body: bytes
  host: str
  port: int

class Probe:
  """Shared state: the worker thread writes, the screen only reads."""
  def __init__(self, host, port, cfg):
    self.host, self.port, self.cfg = host, port, cfg
    self.target = host if port == 443 else f"{host}:{port}"
    self.findings, self.logs, self.info, self.ips = [], [], {}, []
    self.step, self.done = "", 0
    self.total = sum(s[2] for s in STEPS)
    self.tls_up = self.cert_ok = self.web_up = self.assessable = False
    self.page = None
  @property
  def percent(self):
    return min(100, round(100 * self.done / self.total))
  def put(self, key, value):
    self.info[key] = clean(value, 120)
  def log(self, level, msg):
    self.logs.append((time.strftime("%H:%M:%S"), level, clean(msg, 220)))
  def add(self, items):
    for f in items:
      self.findings.append(f)
      self.log(f.level, f"{f.area}: {f.detail}")

def score(findings):
  total = sum(f.w for f in findings)
  if total <= 0:
    return None
  got = sum(f.w * (POINTS[f.level] if f.pts is None else f.pts) for f in findings)
  return round(100 * got / total)

def score_look(pts):
  if pts <= LOW:
    return "bad", "LOW"
  return ("warn", "MID") if pts < GOOD else ("ok", "GOOD")

HOST_RE = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9\-]{1,59})")
TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.pl", "org.pl", "net.pl", "com.au", "net.au",
      "org.au", "co.jp", "co.nz", "com.br", "co.za", "com.tr", "com.mx", "co.in"}

def parse_target(raw):
  """'https://user@Example.com:8443/x' -> ('example.com', 8443), None if not a domain."""
  a = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", raw.strip().lower())
  a = re.split(r"[/?#\\]", a, maxsplit=1)[0].split("@")[-1]
  host, _, port = a.partition(":")
  try:
    host = host.strip(".").encode("idna").decode("ascii")
  except UnicodeError:
    return None
  if not HOST_RE.fullmatch(host) or (port and not (port.isdigit() and 0 < int(port) < 65536)):
    return None
  return host, int(port) if port else None

def org_domain(host):
  parts = host.split(".")
  return ".".join(parts[-3:] if ".".join(parts[-2:]) in TWO_LEVEL and len(parts) > 2 else parts[-2:])

def same_site(a, b):
  return a.lower().removeprefix("www.") == b.lower().removeprefix("www.")

QTYPES = {"A": 1, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}

def parse_ip(s):
  try:
    ip = ipaddress.ip_address(s.split("%")[0].strip())
  except ValueError:
    return None
  return None if ip.is_link_local or ip.is_unspecified else str(ip)

def build_resolvers(custom):
  if custom:
    return custom
  found = []
  try:
    with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as fh:
      for line in fh:
        w = line.split()
        if len(w) >= 2 and w[0] == "nameserver" and parse_ip(w[1]) and w[1] not in found:
          found.append(w[1])
  except OSError:
    pass
  return found[:2] + [r for r in DNS_FALLBACK if r not in found[:2]]

def read_name(data, off):
  labels, end, hops = [], None, 0
  while True:
    n = data[off]
    if n == 0:
      off += 1
      break
    if n & 0xC0 == 0xC0:
      end = end or off + 2
      off = ((n & 0x3F) << 8) | data[off + 1]
      hops += 1
      if hops > 20:
        raise ValueError("compression loop")
      continue
    labels.append(data[off + 1:off + 1 + n].decode("ascii", "replace"))
    off += 1 + n
  return ".".join(labels), end or off

def recv_exact(sock, n):
  buf = b""
  while len(buf) < n:
    chunk = sock.recv(n - len(buf))
    if not chunk:
      raise ConnectionError("connection closed")
    buf += chunk
  return buf

def ask_server(server, name, qtype, timeout, tcp=False):
  qid = secrets.randbelow(0x10000)
  q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".")) + b"\0"
  msg = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", qtype, 1)
  fam = socket.AF_INET6 if ":" in server else socket.AF_INET
  with socket.socket(fam, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
    s.settimeout(timeout)
    s.connect((server, 53))
    if tcp:
      s.sendall(struct.pack(">H", len(msg)) + msg)
      data = recv_exact(s, struct.unpack(">H", recv_exact(s, 2))[0])
    else:
      s.send(msg)
      data = s.recv(4096)
  if len(data) < 12 or struct.unpack(">H", data[:2])[0] != qid:
    raise ValueError("bad DNS reply")
  return data

def parse_answers(data, qtype):
  qd, an = struct.unpack(">HH", data[4:8])
  off = 12
  for _ in range(qd):
    off = read_name(data, off)[1] + 4
  out = []
  for _ in range(an):
    off = read_name(data, off)[1]
    rtype, _, _, n = struct.unpack(">HHIH", data[off:off + 10])
    off += 10
    rd = data[off:off + n]
    if rtype == qtype:
      if qtype == 1:
        out.append(socket.inet_ntoa(rd))
      elif qtype == 28:
        out.append(socket.inet_ntop(socket.AF_INET6, rd))
      elif qtype == 15:
        out.append(f"{struct.unpack('>H', rd[:2])[0]} {read_name(data, off + 2)[0]}")
      elif qtype == 16:
        parts, i = [], 0
        while i < len(rd):
          parts.append(rd[i + 1:i + 1 + rd[i]].decode("utf-8", "replace"))
          i += 1 + rd[i]
        out.append("".join(parts))
      else:
        tag = rd[2:2 + rd[1]].decode("ascii", "replace")
        out.append(f"{tag} {rd[2 + rd[1]:].decode('utf-8', 'replace')}")
    off += n
  return out

def query_dns(cfg, name, rtype):
  """Returns (error, records). No error and no records means the record does not exist."""
  qtype, err = QTYPES[rtype], "no resolver answered"
  for server in cfg.resolvers:
    try:
      data = ask_server(server, name, qtype, cfg.timeout)
      if data[2] & 0x02:
        data = ask_server(server, name, qtype, cfg.timeout, tcp=True)
      rcode = data[3] & 0x0F
      if rcode == 3:
        return "", []
      if rcode:
        err = f"resolver returned code {rcode}"
        continue
      return "", parse_answers(data, qtype)
    except socket.timeout:
      err = "timed out"
    except Exception as e:
      err = clean(e, 50)
  return err, []

def tls_ctx(verify=True):
  ctx = ssl.create_default_context()
  if not verify:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
  return ctx

def fetch(host, path="/", *, port=None, https=True, verify=True, max_body=0, extra=None, timeout=8):
  port = port or (443 if https else 80)
  if https:
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=tls_ctx(verify))
  else:
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
  try:
    conn.request("GET", path, headers={"User-Agent": UA, "Accept": "*/*", "Connection": "close", **(extra or {})})
    resp = conn.getresponse()
    hdr = {}
    for k, v in resp.getheaders():
      k = k.lower()
      if k != "set-cookie":
        hdr[k] = f"{hdr[k]}, {v}" if k in hdr else v
    body = resp.read(max_body) if max_body else b""
    return Response(resp.status, clean(resp.reason), hdr, resp.msg.get_all("Set-Cookie") or [], body, host, port)
  finally:
    conn.close()

def fetch_follow(host, port, verify, timeout, extra):
  """GET / over HTTPS, following up to 5 redirects that stay on the same site."""
  cur, cport, path = host, port, "/"
  for _ in range(5):
    r = fetch(cur, path, port=cport, verify=verify, max_body=BODY_MAX, extra=extra, timeout=timeout)
    loc = r.headers.get("location")
    if r.status in REDIR and loc:
      u = urlsplit(urljoin(f"https://{cur}:{cport}{path}", loc))
      if u.scheme == "https" and u.hostname and same_site(u.hostname, host):
        cur, cport = u.hostname, u.port or 443
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        continue
    break
  return r

def is_waf(r):
  if r.status not in (403, 429, 503):
    return False
  srv = r.headers.get("server", "").lower()
  return any(h in r.headers for h in WAF_HEADERS) or "cloudflare" in srv or "akamai" in srv

CDN = re.compile(r"cloudflare|akamai|fastly|cloudfront|amazon|google|microsoft|azure|incapsula|imperva", re.I)

def check_dns(p):
  e4, a = query_dns(p.cfg, p.host, "A")
  e6, aaaa = query_dns(p.cfg, p.host, "AAAA")
  p.ips = a + aaaa
  if not p.ips:
    try:
      p.ips = sorted({i[4][0] for i in socket.getaddrinfo(p.host, p.port, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
      pass
  if p.ips:
    more = len(p.ips) - 2
    shown = ", ".join(p.ips[:2]) + (t("dns.more", n=more) if more > 0 else "")
    p.put("ip", shown)
    v6 = sum(":" in i for i in p.ips)
    return [F("dns", "ok", "dns.ok", v4=len(p.ips) - v6, v6=v6, shown=shown)]
  if e4 and e6:
    return [F("dns", "warn", "lookup", err=e4)]
  return [F("dns", "miss", "dns.none")]

def geo_lookup(ip, timeout):
  urls = (f"https://ipwho.is/{ip}", f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org")
  for url in urls:
    try:
      req = urllib.request.Request(url, headers={"User-Agent": UA})
      with urllib.request.urlopen(req, timeout=timeout) as r:
        d = json.loads(r.read(20000))
    except Exception:
      continue
    if d.get("success") or d.get("status") == "success":
      net = d.get("connection") or d
      geo = {"country": d.get("country"), "code": d.get("country_code") or d.get("countryCode"),
         "city": d.get("city"), "org": net.get("org") or net.get("isp")}
      return {k: clean(v or "", 80) for k, v in geo.items()}
  return None

def check_location(p):
  if not p.ips:
    return [F("location", "info", "loc.noip")]
  if not p.cfg.geo:
    return [F("location", "info", "loc.off")]
  ip = next((i for i in p.ips if ":" not in i), p.ips[0])
  if not ipaddress.ip_address(ip).is_global:
    return [F("location", "warn", "loc.private", ip=ip)]
  g = geo_lookup(ip, p.cfg.timeout)
  if not g:
    return [F("location", "info", "loc.fail", ip=ip)]
  place = ", ".join(x for x in (g["city"], g["country"]) if x) or "?"
  org = g["org"] or "?"
  p.put("loc", f"{g['code'] or '?'} - {place}")
  p.put("net", org)
  return [F("location", "info", "loc.ok", ip=ip, place=place, code=g["code"] or "?", org=org,
       cdn=t("loc.cdn") if CDN.search(org) else "")]

VERSIONS = (("TLS 1.3", ssl.TLSVersion.TLSv1_3), ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
      ("TLS 1.1", ssl.TLSVersion.TLSv1_1), ("TLS 1.0", ssl.TLSVersion.TLSv1))
OLD = ("TLS 1.1", "TLS 1.0")

def tls_connect(host, port, verify, timeout):
  raw = socket.create_connection((host, port), timeout=timeout)
  ctx = tls_ctx(verify)
  ctx.set_alpn_protocols(["h2", "http/1.1"])
  try:
    return ctx.wrap_socket(raw, server_hostname=host)
  except BaseException:
    raw.close()
    raise

def tls_supports(host, port, timeout, ver):
  """True if a handshake pinned to exactly this TLS version succeeds."""
  try:
    with warnings.catch_warnings():
      warnings.simplefilter("ignore", DeprecationWarning)
      ctx = tls_ctx(False)
      ctx.minimum_version = ctx.maximum_version = ver
      if ver <= ssl.TLSVersion.TLSv1_1:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    with socket.create_connection((host, port), timeout=timeout) as raw:
      with ctx.wrap_socket(raw, server_hostname=host):
        return True
  except (OSError, ValueError):
    return False

def probe_versions(host, port, timeout):
  with ThreadPoolExecutor(4) as ex:
    res = list(ex.map(lambda v: tls_supports(host, port, timeout, v[1]), VERSIONS))
  return {name: ok for (name, _), ok in zip(VERSIONS, res)}

def check_caa(p):
  err, rec = query_dns(p.cfg, p.host, "CAA")
  if not err and not rec and org_domain(p.host) != p.host:
    err, rec = query_dns(p.cfg, org_domain(p.host), "CAA")
  if err:
    return F("caa", "info", "lookup", err=err)
  if rec:
    return F("caa", "ok", "caa.ok", rec=clean("; ".join(rec[:3]), 80))
  return F("caa", "info", "caa.none")

def check_tls(p):
  host, port, to = p.host, p.port, p.cfg.timeout
  sock, out = None, []
  try:
    why, chain = "", False
    try:
      sock = tls_connect(host, port, True, to)
      p.cert_ok = True
    except ssl.SSLCertVerificationError as e:
      why = clean(e.verify_message or e.reason or "?", 80)
      chain = "local issuer" in why or "verify the first" in why
      sock = tls_connect(host, port, False, to)
    p.tls_up = True
    ver = sock.version() or "?"
    alpn = sock.selected_alpn_protocol() or "-"
    if p.cert_ok:
      cert = sock.getpeercert()
      days = int((ssl.cert_time_to_seconds(cert["notAfter"]) - time.time()) // 86400)
      names = {k: v for rdn in cert.get("issuer", ()) for k, v in rdn}
      issuer = clean(names.get("organizationName") or names.get("commonName") or "?", 40)
      p.put("tls", f"{ver}, {issuer}, {days}d")
      soon = days <= CERT_WARN
      out.append(F("tls", "warn" if soon else "ok", "tls.ok", pts=0.5 if soon else 1.0,
            issuer=issuer, ver=ver, days=days, soon=t("tls.soon") if soon else ""))
    elif chain:
      p.put("tls", f"{ver}, incomplete chain")
      out.append(F("tls", "warn", "tls.chain", pts=0.5, why=why))
    else:
      p.put("tls", f"{ver}, NOT trusted")
      out.append(F("tls", "bad", "tls.bad", pts=0.0, why=why))
    v = probe_versions(host, port, to)
    if any(v[n] for n in OLD):
      out.append(F("tls_versions", "warn", "tlsv.legacy", pts=0.5, alpn=alpn))
    elif v["TLS 1.3"] and v["TLS 1.2"]:
      out.append(F("tls_versions", "ok", "tlsv.both", pts=1.0, alpn=alpn))
    elif v["TLS 1.3"]:
      out.append(F("tls_versions", "ok", "tlsv.t13", pts=1.0, alpn=alpn))
    elif v["TLS 1.2"]:
      out.append(F("tls_versions", "info", "tlsv.t12", pts=0.9, alpn=alpn))
    else:
      out.append(F("tls_versions", "info", "tlsv.unk", pts=1.0, alpn=alpn))
    out.append(check_caa(p))
  except socket.gaierror:
    out.append(F("tls", "miss", "tls.nores", pts=0.0))
  except socket.timeout:
    out.append(F("tls", "miss", "tls.timeout", pts=0.0, port=port))
  except ssl.SSLError as e:
    reason = clean(e.reason or e, 50)
    old = []
    if any(k in reason.upper() for k in ("UNSUPPORTED_PROTOCOL", "PROTOCOL_VERSION", "NO_PROTOCOLS_AVAILABLE")):
      old = [n for n, ok in probe_versions(host, port, to).items() if ok and n in OLD]
    if old:
      out.append(F("tls", "bad", "tls.old", pts=0.0, v=", ".join(old)))
    else:
      out.append(F("tls", "miss", "tls.hs", pts=0.0, why=reason))
  except OSError as e:
    out.append(F("tls", "miss", "tls.conn", pts=0.0, port=port, why=clean(e, 50)))
  finally:
    if sock:
      sock.close()
  return out

def check_redirect(p):
  if p.port != 443:
    return [F("redirect", "info", "red.port", pts=1.0)]
  try:
    r = fetch(p.host, "/", port=80, https=False, timeout=p.cfg.timeout)
  except Exception:
    return [F("redirect", "info", "red.noans", pts=1.0)]
  if r.status in REDIR:
    if r.headers.get("location", "").lower().startswith("https://"):
      return [F("redirect", "ok", "red.ok", pts=1.0, code=r.status)]
    return [F("redirect", "warn", "red.unclear", pts=0.5, code=r.status)]
  return [F("redirect", "warn", "red.none", pts=0.0, code=r.status)]

def parse_csp(raw):
  d = {}
  for part in raw.split(";"):
    tok = part.split()
    if tok:
      d.setdefault(tok[0].lower(), [x.lower() for x in tok[1:]])
  return d

def check_hsts(h):
  raw = h.get("strict-transport-security", "")
  if not raw:
    return F("hsts", "miss", "hsts.miss", pts=0.0)
  m = re.search(r"max-age\s*=\s*\"?(\d+)", raw, re.I)
  age, low = int(m.group(1)) if m else 0, raw.lower()
  sub = "includesubdomains" in low
  flags = (", includeSubDomains" if sub else "") + (", preload" if "preload" in low else "")
  if age < HSTS_MIN:
    return F("hsts", "warn", "hsts.short", pts=0.5, age=age)
  if not sub:
    return F("hsts", "info", "hsts.nosub", pts=0.9, age=age, flags=flags)
  return F("hsts", "ok", "hsts.ok", pts=1.0, age=age, flags=flags)

def check_csp(h):
  raw = h.get("content-security-policy", "")
  if not raw:
    if "content-security-policy-report-only" in h:
      return F("csp", "warn", "csp.report", pts=0.5)
    return F("csp", "miss", "csp.miss", pts=0.0)
  d = parse_csp(raw)
  name = "script-src" if "script-src" in d else "default-src"
  script, style = d.get(name, []), d.get("style-src", d.get("default-src", []))
  hashed = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
  guarded = any(x.startswith(hashed) or x == "'strict-dynamic'" for x in script)
  weak = ["'unsafe-inline'"] if "'unsafe-inline'" in script and not guarded else []
  weak += [x for x in script if x in ("'unsafe-eval'", "*", "http:", "https:", "data:")]
  if weak:
    return F("csp", "warn", "csp.weak", pts=0.5, d=name, items=", ".join(weak))
  if "'unsafe-inline'" in style and not any(x.startswith(hashed) for x in style):
    return F("csp", "info", "csp.style", pts=0.85)
  return F("csp", "ok", "csp.ok", pts=1.0)

def check_xfo(h):
  v = h.get("x-frame-options", "").strip().upper()
  if v in ("DENY", "SAMEORIGIN"):
    return F("xfo", "ok", "xfo.ok", pts=1.0, v=v)
  if "frame-ancestors" in parse_csp(h.get("content-security-policy", "")):
    return F("xfo", "ok", "xfo.csp", pts=1.0)
  if v:
    return F("xfo", "warn", "xfo.odd", pts=0.5, v=clean(v, 30))
  return F("xfo", "miss", "xfo.miss", pts=0.0)

def check_xcto(h):
  v = h.get("x-content-type-options", "").lower()
  if "nosniff" in v:
    return F("xcto", "ok", "xcto.ok", pts=1.0)
  return F("xcto", "warn", "xcto.odd", pts=0.5) if v else F("xcto", "miss", "xcto.miss", pts=0.0)

def check_referrer(h):
  raw = h.get("referrer-policy", "")
  if not raw:
    return F("referrer", "miss", "ref.miss", pts=0.0)
  last = raw.split(",")[-1].strip().lower()
  if last in ("", "unsafe-url", "no-referrer-when-downgrade"):
    return F("referrer", "warn", "ref.weak", pts=0.5, v=clean(last, 40))
  return F("referrer", "ok", "ref.ok", pts=1.0, v=clean(last, 40))

def check_permissions(h):
  if h.get("permissions-policy"):
    return F("permissions", "ok", "perm.ok", pts=1.0)
  if h.get("feature-policy"):
    return F("permissions", "warn", "perm.old", pts=0.5)
  return F("permissions", "miss", "perm.miss", pts=0.0)

def check_page(p):
  extra = {"Origin": EVIL}
  r, why = None, ""
  try:
    if p.tls_up:
      r = fetch_follow(p.host, p.port, p.cert_ok, p.cfg.timeout, extra)
    else:
      r = fetch(p.host, "/", port=80 if p.port == 443 else p.port, https=False,
           max_body=BODY_MAX, extra=extra, timeout=p.cfg.timeout)
  except Exception as e:
    why = clean(e, 60)
  if r is None:
    return [F("http", "miss", "http.none", pts=0.0, why=why),
        F("headers", "info", "hdr.noresp", pts=0.0, w=HEADER_W)]
  p.web_up, p.page = True, r
  code = f"{r.status} {r.reason}" + (t("http.via", host=r.host) if r.host != p.host else "")
  p.put("http", f"{code} ({'https' if p.tls_up else 'http'})")
  if not p.tls_up:
    p.assessable = True
    return [F("https", "bad", "https.bad"), F("headers", "info", "hdr.nohttps", pts=0.0, w=HEADER_W)]
  if r.status in REDIR:
    return [F("http", "info", "http.redir", pts=1.0, code=code, to=clean(r.headers.get("location", "?"), 60)),
        F("headers", "info", "hdr.skip")]
  if is_waf(r):
    return [F("http", "info", "http.waf", pts=1.0, code=code), F("headers", "info", "hdr.skip")]
  p.assessable = True
  h = r.headers
  first = F("http", "ok", "http.ok", pts=1.0, code=code) if 200 <= r.status < 300 else \
    F("http", "warn", "http.other", pts=0.5, code=code)
  return [first, check_hsts(h), check_csp(h), check_xfo(h), check_xcto(h), check_referrer(h), check_permissions(h)]

TRACKERS = ("google-analytics.com", "googletagmanager.com", "doubleclick.net", "googlesyndication.com",
      "facebook.net", "facebook.com", "hotjar.com", "clarity.ms", "segment.com", "mixpanel.com",
      "amplitude.com", "tiktok.com", "ads-twitter.com", "linkedin.com", "licdn.com", "criteo.com",
      "taboola.com", "outbrain.com", "fullstory.com", "mouseflow.com", "mc.yandex.ru", "bat.bing.com",
      "hubspot.com", "hs-scripts.com", "adobedtm.com", "quantserve.com", "scorecardresearch.com")
SESSION = re.compile(r"sess|sid$|^sid|auth|token|jwt|login", re.I)

class PageScan(html.parser.HTMLParser):
  def __init__(self):
    super().__init__()
    self.http_forms, self.mixed, self.res = [], [], []
  def handle_starttag(self, tag, attrs):
    a = {k: v or "" for k, v in attrs}
    if tag == "form":
      if a.get("action", "").strip().lower().startswith("http://"):
        self.http_forms.append(a["action"].strip())
      return
    kind, url = tag, ""
    if tag in ("script", "img", "iframe", "source", "audio", "video", "embed", "track"):
      url = a.get("src", "")
    elif tag == "object":
      url = a.get("data", "")
    elif tag == "link" and re.search(r"stylesheet|icon|preload", a.get("rel", ""), re.I):
      url = a.get("href", "")
      kind = "style" if "stylesheet" in a["rel"].lower() else "link"
    url = url.strip()
    if url.startswith("//"):
      url = "https:" + url
    try:
      u = urlsplit(url)
      host = (u.hostname or "").lower()
    except ValueError:
      return
    if url and u.scheme == "http":
      self.mixed.append(url)
    if host and u.scheme in ("http", "https"):
      self.res.append((kind, host, "integrity" in a))

def check_cookies(r, tls):
  if not r.cookies:
    return F("cookies", "ok", "cookies.none", pts=1.0)
  nosec, nohttp, nosame = [], [], []
  for raw in r.cookies:
    name = raw.split("=", 1)[0].strip()[:30]
    attrs = [x.strip().lower() for x in raw.split(";")[1:]]
    if tls and "secure" not in attrs:
      nosec.append(name)
    if SESSION.search(name) and "httponly" not in attrs:
      nohttp.append(name)
    if not any(x.startswith("samesite=") for x in attrs):
      nosame.append(name)
  problems = []
  if nosec:
    problems.append(t("cookies.nosecure", names=", ".join(nosec[:4])))
  if nohttp:
    problems.append(t("cookies.nohttp", names=", ".join(nohttp[:4])))
  n = len(r.cookies)
  if problems:
    return F("cookies", "warn", "cookies.warn", pts=0.5, n=n, problems="; ".join(problems))
  if nosame:
    return F("cookies", "info", "cookies.samesite", pts=0.8, n=n)
  return F("cookies", "ok", "cookies.ok", pts=1.0, n=n)

def cors_of(r):
  return r.headers.get("access-control-allow-origin", ""), r.headers.get("access-control-allow-credentials", "").lower() == "true"

def check_cors(p, r):
  sent = {"foreign": EVIL, "null": "null",
      "prefix": f"https://{p.host}.search.invalid",
      "suffix": f"https://search-{p.host}"}
  seen = {"foreign": cors_of(r)}
  def probe(name):
    try:
      return name, cors_of(fetch(r.host, "/", port=r.port, verify=p.cert_ok, extra={"Origin": sent[name]},
                   timeout=p.cfg.timeout))
    except Exception:
      return name, None
  with ThreadPoolExecutor(3) as ex:
    for name, res in ex.map(probe, ["null", "prefix", "suffix"]):
      if res:
        seen[name] = res
  refl = [n for n, (o, _) in seen.items() if o and o == sent[n]]
  names = ", ".join(refl)
  if refl and any(seen[n][1] for n in refl):
    return F("cors", "bad", "cors.bad", pts=0.0, names=names)
  if refl:
    return F("cors", "warn", "cors.warn", pts=0.5, names=names)
  if any(o == "*" for o, _ in seen.values()):
    return F("cors", "info", "cors.star", pts=1.0)
  return F("cors", "ok", "cors.ok", pts=1.0)

def check_versions(r):
  leaks = []
  if re.search(r"\d+\.\d+", r.headers.get("server", "")):
    leaks.append("Server: " + clean(r.headers["server"], 40))
  leaks += [f"{n}: {clean(r.headers[n], 40)}" for n in ("x-powered-by", "x-aspnet-version", "x-generator") if r.headers.get(n)]
  if leaks:
    return F("versions", "warn", "ver.warn", pts=0.5, items="; ".join(leaks))
  return F("versions", "ok", "ver.ok", pts=1.0)

def check_content(p, r):
  if "html" not in r.headers.get("content-type", "").lower() or r.status >= 400 or not r.body:
    return [F("content", "info", "content.nohtml", pts=1.0), F("scripts", "info", "content.nohtml"),
        F("sri", "info", "content.nohtml")]
  scan = PageScan()
  try:
    scan.feed(r.body.decode("utf-8", "replace"))
    scan.close()
  except Exception:
    pass
  if scan.http_forms:
    out = [F("content", "bad", "content.form", pts=0.0, url=clip(scan.http_forms[0], 60))]
  elif scan.mixed:
    out = [F("content", "warn", "content.mixed", pts=0.5, n=len(scan.mixed), url=clip(scan.mixed[0], 60))]
  else:
    out = [F("content", "ok", "content.ok", pts=1.0)]
  mine = org_domain(p.host)
  outside = sorted({h for _, h, _ in scan.res if org_domain(h) != mine})
  trackers = sorted({tr for h in outside for tr in TRACKERS if h == tr or h.endswith("." + tr)})
  if trackers:
    out.append(F("scripts", "info", "scripts.tracker", n=len(outside), names=", ".join(trackers[:6])))
  elif outside:
    out.append(F("scripts", "info", "scripts.ext", n=len(outside), names=", ".join(outside[:4])))
  else:
    out.append(F("scripts", "ok", "scripts.ok"))
  code_hosts = [(h, sri) for kind, h, sri in scan.res if kind in ("script", "style") and h in outside]
  no_sri = sorted({h for h, sri in code_hosts if not sri})
  if no_sri:
    out.append(F("sri", "info", "sri.missing", n=len(no_sri), names=", ".join(no_sri[:4])))
  elif code_hosts:
    out.append(F("sri", "ok", "sri.ok"))
  return out

def check_leaks(p):
  if not p.assessable:
    return [F("leaks", "info", "leaks.skip")]
  r = p.page
  out = [check_cookies(r, p.tls_up)]
  if p.tls_up:
    out.append(check_cors(p, r))
  return out + [check_versions(r)] + check_content(p, r)

ENV = re.compile(rb"^\s*[A-Z][A-Z0-9_]{2,}\s*=", re.M)
LISTING = re.compile(rb"<title>\s*Index of /", re.I)
DIRLIST = "open directory listing"
SENSITIVE = [
  ("/.env", ENV, "environment file with secrets"),
  ("/.env.production", ENV, "environment file with secrets"),
  ("/.git/HEAD", re.compile(rb"^ref: refs/"), "git repository"),
  ("/.git/config", re.compile(rb"\[core\]"), "git config"),
  ("/.svn/entries", re.compile(rb"\A\d{1,2}\s+dir\b"), "svn metadata"),
  ("/.htpasswd", re.compile(rb"^[\w.@-]+:(\$apr1\$|\$2[aby]\$|\{SHA\}|[./0-9A-Za-z]{13})", re.M),
  "password file"),
  ("/.DS_Store", re.compile(rb"^\x00\x00\x00\x01Bud1"), "macOS folder index"),
  ("/wp-config.php.bak", re.compile(rb"DB_PASSWORD|<\?php"), "WordPress config backup"),
  ("/phpinfo.php", re.compile(rb"PHP Version"), "phpinfo page"),
  ("/server-status", re.compile(rb"Apache Server Status"), "Apache status page"),
  ("/backup.sql", re.compile(rb"CREATE TABLE|INSERT INTO|DROP TABLE", re.I), "SQL dump"),
  ("/backup.zip", re.compile(rb"^PK\x03\x04"), "zip backup"),
  ("/uploads/", LISTING, DIRLIST), ("/backup/", LISTING, DIRLIST),
  ("/backups/", LISTING, DIRLIST), ("/files/", LISTING, DIRLIST),
]
MAX_FAILS = 3

def check_exposed(p):
  if not p.web_up:
    return [F("exposed", "info", "exp.skip")]
  host, port = p.page.host, p.page.port
  fails, stop = [], threading.Event()
  def get(item):
    if stop.is_set():
      return None
    try:
      return fetch(host, item[0], port=port, https=p.tls_up, verify=p.cert_ok, max_body=1024, timeout=PATH_TIMEOUT)
    except Exception:
      fails.append(item[0])
      if len(fails) >= MAX_FAILS:
        stop.set()
      return None
  hits, answered, redirects = [], 0, 0
  with ThreadPoolExecutor(4) as ex:
    for (path, sig, label), r in zip(SENSITIVE, ex.map(get, SENSITIVE)):
      p.done += 1
      p.step = f"{t('s.exposed')}: {path}"
      if r is None:
        p.log("info", t("exp.nores", path=path))
        continue
      answered += 1
      redirects += r.status in REDIR
      if r.status in (200, 206) and sig.search(r.body):
        hits.append(f"{path} ({label})")
        p.log("bad", t("exp.hitlog", path=path, label=label))
      else:
        p.log("ok", t("exp.clean", path=path, status=r.status))
  if hits:
    out = [F("exposed", "bad", "exp.hit", pts=0.0, hits="; ".join(hits))]
  elif len(fails) >= MAX_FAILS:
    out = [F("exposed", "info", "exp.early", pts=0.5)]
  elif answered and redirects == answered:
    out = [F("exposed", "info", "exp.redirects", pts=0.5)]
  else:
    out = [F("exposed", "ok", "exp.ok", pts=1.0, n=len(SENSITIVE))]
  if len(fails) < MAX_FAILS:
    found = False
    try:
      r = fetch(host, "/.well-known/security.txt", port=port, https=p.tls_up, verify=p.cert_ok,
           max_body=2048, timeout=PATH_TIMEOUT)
      found = r.status == 200 and re.search(rb"^\s*contact\s*:", r.body, re.I | re.M)
    except Exception:
      pass
    out.append(F("security_txt", "ok" if found else "info", "sectxt.ok" if found else "sectxt.none"))
  return out

NO_MAIL_START = ("www.", "cdn.", "static.", "assets.", "img.", "media.")
NO_MAIL_END = ("workers.dev", "pages.dev", "cloudfront.net", "azureedge.net", "netlify.app", "vercel.app",
       "herokuapp.com", "github.io", "fastly.net", "akamaized.net", "appspot.com")

def spf_all(rec):
  m = re.search(r"(?:^|\s)([+\-~?]?)all(?:\s|$)", rec, re.I)
  return None if not m else (m.group(1) or "+")

def check_spf(p, expected, reason):
  host = p.host
  for _ in range(4):
    err, txt = query_dns(p.cfg, host, "TXT")
    if err:
      return F("spf", "info", "lookup", err=err)
    recs = [x for x in txt if x.lower().startswith("v=spf1")]
    m = re.search(r"(?:^|\s)redirect=(\S+)", recs[0], re.I) if len(recs) == 1 else None
    if m and spf_all(recs[0]) is None:
      host = m.group(1).strip(".").lower()
      continue
    break
  if len(recs) > 1:
    return F("spf", "warn", "spf.multi", n=len(recs))
  if not recs:
    return F("spf", "miss", "spf.miss") if expected else F("spf", "info", "spf.none", reason=reason)
  q = spf_all(recs[0])
  if q in ("-", "~"):
    return F("spf", "ok", "spf.ok", q=q)
  return F("spf", "warn", "spf.open") if q == "+" else F("spf", "info", "spf.weak")

def check_dmarc(p, expected, reason):
  names = [p.host] + ([org_domain(p.host)] if org_domain(p.host) != p.host else [])
  for name in names:
    err, txt = query_dns(p.cfg, "_dmarc." + name, "TXT")
    if err:
      return F("dmarc", "info", "lookup", err=err)
    rec = next((x for x in txt if x.strip().lower().startswith("v=dmarc1")), None)
    if rec:
      tags = {k.strip().lower(): v.strip().lower() for k, _, v in (x.partition("=") for x in rec.split(";")) if _}
      inherited = name != p.host
      policy = clean(tags.get("sp") if inherited and "sp" in tags else tags.get("p", "none"), 20)
      src = t("dmarc.src", org=name) if inherited else ""
      if policy in ("reject", "quarantine"):
        return F("dmarc", "ok", "dmarc.ok", policy=policy, src=src)
      return F("dmarc", "info", "dmarc.mon", policy=policy, src=src)
  return F("dmarc", "miss", "dmarc.miss") if expected else F("dmarc", "info", "dmarc.none", reason=reason)

def check_mail(p):
  err, mx = query_dns(p.cfg, p.host, "MX")
  if err:
    out = [F("mx", "info", "lookup", err=err)]
  else:
    out = [F("mx", "info", "mx.ok", servers="; ".join(mx[:3])) if mx else F("mx", "info", "mx.none")]
  if p.host.startswith(NO_MAIL_START) or p.host.endswith(NO_MAIL_END):
    expected, reason = False, t("r.web")
  elif err or not mx:
    expected, reason = False, t("r.mxfail" if err else "r.nomx")
  else:
    expected, reason = True, ""
  out += [check_spf(p, expected, reason), check_dmarc(p, expected, reason)]
  if expected:
    e, txt = query_dns(p.cfg, "_mta-sts." + p.host, "TXT")
    ok = not e and any(x.lower().startswith("v=stsv1") for x in txt)
    out.append(F("mtasts", "ok" if ok else "info", "mta.ok" if ok else "mta.none"))
  return out

STEPS = [("s.dns", check_dns, 1), ("s.location", check_location, 1), ("s.tls", check_tls, 1),
    ("s.redirect", check_redirect, 1), ("s.page", check_page, 1), ("s.leaks", check_leaks, 1),
    ("s.exposed", check_exposed, len(SENSITIVE)), ("s.mail", check_mail, 1)]

def run_checks(p):
  for key, fn, units in STEPS:
    name, start = t(key), p.done
    p.step = name
    p.log("info", t("run.start", name=name))
    try:
      p.add(fn(p))
    except Exception as e:
      p.add([F("step", "info", "run.fail", name=name, err=clean(e, 60))])
    p.done = start + units

def verdict(p, pts):
  """Returns (code, color, advice); same thresholds as score_look()."""
  if not p.web_up:
    return "UNKNOWN", "miss", t("adv.UNKNOWN")
  if any(f.level == "bad" for f in p.findings):
    return "NOT SAFE", "bad", t("adv.NOT SAFE")
  weak = sum(f.level in ("warn", "miss") for f in p.findings)
  if (pts is not None and pts <= LOW) or weak >= 3:
    return "CAUTION", "warn", t("adv.CAUTION")
  if pts is not None and pts < GOOD:
    return "CAUTION", "warn", t("adv.MID")
  return "SAFE", "ok", t("adv.SAFE")

def result_dict(p):
  pts = score(p.findings)
  code, _, advice = verdict(p, pts)
  return {"host": p.host, "port": p.port, "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
      "score": pts, "verdict": code, "advice": advice, "info": dict(p.info),
      "findings": [{"key": f.key, "level": f.level, "detail": f.detail} for f in p.findings]}

def save_result(path, res):
  """Appends the result to the history file, returns the diff against the last run."""
  try:
    with open(path, encoding="utf-8") as fh:
      hist = json.load(fh)
    hist = hist if isinstance(hist, dict) else {}
  except (OSError, ValueError):
    hist = {}
  key = f"{res['host']}:{res['port']}"
  runs, diff = hist.get(key, []), None
  if runs:
    prev = runs[-1]
    old = {f["key"]: f["level"] for f in prev.get("findings", [])}
    new = {f["key"]: f["level"] for f in res["findings"]}
    delta = res["score"] - prev["score"] if prev.get("score") is not None and res["score"] is not None else None
    diff = {"previous_at": prev.get("checked_at"), "previous_score": prev.get("score"), "score_delta": delta,
        "verdict_before": prev.get("verdict"),
        "changes": [{"check": k, "from": old.get(k), "to": new.get(k)}
              for k in sorted(set(old) | set(new)) if old.get(k) != new.get(k)]}
  hist[key] = (runs + [res])[-HISTORY_KEEP:]
  tmp = path + ".tmp"
  with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(hist, fh, indent=2, ensure_ascii=False)
  os.replace(tmp, path)
  return diff

def report(p, diff, saved):
  width = max(70, min(shutil.get_terminal_size((100, 30)).columns, 110))
  pts = score(p.findings)
  code, color, advice = verdict(p, pts)
  out = ["  " + paint(t("ui.results"), "title", True) + paint(p.target, "info", True), ""]
  for k in ("ip", "loc", "net", "tls", "http"):
    v = p.info.get(k)
    out.append("  " + paint(t("i." + k).ljust(13), "dim") + (paint(clip(v, width - 16), "text") if v else paint("-", "dim")))
  c1, c2 = 24, 6
  c3 = max(30, width - c1 - c2 - 8)
  head = t("ui.cols").split("|")
  out += ["", "  " + paint(f"{head[0]:<{c1}} {head[1]:<{c2}} {head[2]}", "dim"), "  " + paint("-" * (width - 4), "dim")]
  for f in p.findings:
    for i, part in enumerate(textwrap.wrap(f.detail, c3) or [""]):
      name = clip(f.area, c1).ljust(c1) if i == 0 else " " * c1
      tag = paint(t("lv." + f.level)[:c2].ljust(c2), f.level, True) if i == 0 else " " * c2
      out.append(f"  {paint(name, 'text')} {tag} {part}")
  out += ["", "  " + paint(t("ui.score"), "title", True)]
  if pts is None:
    out.append("  n/a")
  else:
    sc, name = score_look(pts)
    n = round(30 * pts / 100)
    out.append(f"  [{paint('#' * n, sc)}{paint('-' * (30 - n), 'dim')}] " + paint(f"{pts}/100  {t('sc.' + name)}", sc, True))
  out += ["", "  " + paint(t("ui.status"), "title", True),
      "  " + paint(f"  >>  {t('v.' + code)}  <<  ", color, True), "  " + paint(advice, color)]
  issues = [f for f in p.findings if f.level == "bad"] + [f for f in p.findings if f.level == "warn"]
  if issues:
    out.append("  " + paint(t("ui.reasons"), "dim"))
    for f in issues[:6]:
      for i, part in enumerate(textwrap.wrap(f"{f.area}: {f.detail}", width - 10)):
        out.append(f"    {paint('-' if i == 0 else ' ', f.level)} {part}")
  if saved:
    if diff is None:
      out += ["", "  " + paint(t("ui.first"), "dim")]
    else:
      out += ["", "  " + paint(t("ui.changes", when=diff["previous_at"]), "title", True)]
      d = diff["score_delta"]
      if d is not None:
        out.append("  " + paint(t("ui.delta", old=diff["previous_score"], new=pts, delta=d),
                    "ok" if d > 0 else "bad" if d < 0 else "dim"))
      out += [f"  {paint('-', 'dim')} {c['check']}: {c['from'] or '-'} -> {c['to'] or '-'}" for c in diff["changes"]]
      if not diff["changes"]:
        out.append("  " + paint(t("ui.nochg"), "dim"))
  out += ["", "  " + paint(t("ui.disc"), "dim"), "", "  " + paint(t("ui.log"), "title", True)]
  for stamp, level, msg in p.logs:
    out.append(f"  {paint(stamp, 'dim')} {paint(t('lv.' + level).ljust(5), level, True)} {paint(clip(msg, width - 19), level)}")
  print("\n".join(out) + "\n")

def audit(host, port, cfg, quiet):
  p = Probe(host, port, cfg)
  worker = threading.Thread(target=run_checks, args=(p,), daemon=True)
  worker.start()
  live = sys.stdout.isatty() and not quiet
  i = 0
  while live and worker.is_alive():
    n = p.percent * 24 // 100
    sys.stdout.write(f"\r  {'|/-\\'[i % 4]} [{'#' * n}{'-' * (24 - n)}] {p.percent:3d}%  {clip(p.step, 40):<40}")
    sys.stdout.flush()
    i += 1
    time.sleep(0.1)
  worker.join()
  if live:
    sys.stdout.write("\r" + " " * 80 + "\r")
  return p

class Parser(argparse.ArgumentParser):
  def error(self, message):
    self.print_usage(sys.stderr)
    self.exit(64, f"{self.prog}: error: {message}\n")

def main(argv=None):
  ap = Parser(description="Website safety checker (DNS, IP/country, TLS, headers, data leaks).")
  ap.add_argument("domains", nargs="*", help="domains or URLs to check (asks interactively if none)")
  ap.add_argument("--yes", action="store_true", help="confirm you are allowed to test the site")
  ap.add_argument("--json", action="store_true", help="print machine-readable JSON, nothing else")
  ap.add_argument("--no-color", action="store_true", help="no colors")
  ap.add_argument("--port", type=int, default=443, help="HTTPS port (default 443)")
  ap.add_argument("--resolver", action="append", default=[], metavar="IP", help="DNS server instead of the system one (repeatable)")
  ap.add_argument("--timeout", type=int, default=8, help="network timeout in seconds (default 8)")
  ap.add_argument("--no-geo", action="store_true", help="do not look up the server IP country")
  ap.add_argument("--save", metavar="FILE", help="append results to a JSON history file and compare with the last run")
  args = ap.parse_args(argv)
  for r in args.resolver:
    if parse_ip(r) is None:
      ap.error(f"--resolver {r!r} is not an IP address")
  if not 0 < args.port < 65536 or args.timeout < 1:
    ap.error("--port must be 1-65535 and --timeout at least 1")
  use_color(args.no_color or args.json)
  cfg = Config(args.timeout, args.port, build_resolvers(args.resolver), not args.no_geo)
  yes = ("y", "yes", "t", "tak")
  results, code, bad_input = [], 0, False
  ask = lambda prompt: input(paint(prompt, "title")).strip()
  try:
    if args.json and not args.yes:
      print(t("ui.needyes"), file=sys.stderr)
      return 64
    if not args.json:
      print("\n  " + paint("SEARCH", "info", True) + paint("  " + t("ui.title"), "dim") + "\n")
    if not args.yes and ask(t("ui.consent")).lower() not in yes:
      print(paint(t("ui.noconsent"), "warn"))
      return 0
    queue = list(args.domains)
    interactive = not queue
    while True:
      if queue:
        raw = queue.pop(0)
      elif interactive:
        raw = ask(t("ui.domain"))
      else:
        break
      if raw.lower() in ("q", "quit", "exit"):
        break
      target = parse_target(raw)
      if not target:
        bad_input = True
        if not args.json:
          print(paint(t("ui.invalid", raw=clean(raw, 60)), "bad"))
        continue
      p = audit(target[0], target[1] or cfg.port, cfg, args.json)
      res = result_dict(p)
      diff, saved = None, False
      if args.save:
        try:
          diff, saved = save_result(args.save, res), True
        except OSError as e:
          print(t("ui.savefail", path=args.save, err=clean(e, 60)), file=sys.stderr)
      if args.json:
        if diff:
          res["diff"] = diff
        results.append(res)
      else:
        report(p, diff, saved)
      code = max(code, EXIT[res["verdict"]])
      if interactive and not queue and ask(t("ui.another")).lower() not in yes:
        break
  except (EOFError, KeyboardInterrupt):
    print()
  finally:
    if COLOR:
      sys.stdout.write("\033[0m")
  if args.json:
    print(json.dumps(results[0] if len(results) == 1 else results, indent=2, ensure_ascii=False))
  return 64 if bad_input else code

if __name__ == "__main__":
  sys.exit(main())
