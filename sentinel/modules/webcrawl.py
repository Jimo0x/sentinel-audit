"""Web application mapping (bounded, same-host crawler).

Spiders an authorized web target to a small depth/page budget, inventories
reachable pages and HTML forms (candidate input points for a later authorized
assessment), and checks robots.txt, sitemap.xml and security.txt. Flags
mixed-content references (HTTPS pages linking to HTTP resources).

This is reconnaissance only: it follows links with GET requests and never
submits forms or payloads.
"""
from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from sentinel.core.models import Finding, Severity, Target
from sentinel.modules._http import fetch
from sentinel.modules.base import AuditModule, ModuleContext, register
from sentinel.modules.http_audit import WEB_PORTS

MAX_PAGES = 40
MAX_DEPTH = 2


class _LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self.resources: list[str] = []  # src/href to static assets (mixed-content check)
        self._cur_form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._cur_form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                              "inputs": []}
        elif tag in ("input", "textarea", "select") and self._cur_form is not None:
            self._cur_form["inputs"].append(a.get("name") or a.get("type") or tag)
        elif tag in ("script", "img", "link", "iframe"):
            ref = a.get("src") or a.get("href")
            if ref:
                self.resources.append(ref)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur_form is not None:
            self.forms.append(self._cur_form)
            self._cur_form = None


def _base_urls(ctx: ModuleContext, ip: str, host: str) -> list[str]:
    bases = []
    for port, scheme in sorted(WEB_PORTS.items(), key=lambda kv: 0 if kv[1] == "https" else 1):
        if ctx.is_open(ip, port):
            netloc = host if port in (80, 443) else f"{host}:{port}"
            bases.append(f"{scheme}://{netloc}")
    return bases


@register
class WebCrawlModule(AuditModule):
    name = "webcrawl"
    description = "Map a web app: pages, forms, robots/sitemap/security.txt, mixed content"

    def run(self, target: Target, ctx: ModuleContext) -> list[Finding]:
        ip = target.ip or target.spec
        host = target.hostname or target.spec
        bases = _base_urls(ctx, ip, host)
        if not bases:
            return [self.finding(target, "No web service to crawl", severity=Severity.INFO)]

        base = bases[0]
        origin = urlparse(base)
        findings: list[Finding] = []

        # --- well-known files ---------------------------------------------
        findings += self._well_known(target, base, ctx)

        # --- bounded BFS crawl --------------------------------------------
        seen: set[str] = set()
        forms_found: list[dict] = []
        mixed: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(base + "/", 0)])

        while queue and len(seen) < MAX_PAGES:
            url, depth = queue.popleft()
            if url in seen or depth > MAX_DEPTH:
                continue
            seen.add(url)
            ctx.throttle()
            resp = fetch(url, timeout=ctx.timeout)
            if resp.error or resp.status == 0:
                continue
            ctype = (resp.header("content-type") or "").lower()
            if "html" not in ctype:
                continue
            parser = _LinkFormParser()
            try:
                parser.feed(resp.text)
            except Exception:
                continue

            for f in parser.forms:
                forms_found.append({"page": url, **f})

            # mixed content: https page referencing http:// resource
            if origin.scheme == "https":
                for ref in parser.resources:
                    absu = urljoin(url, ref)
                    if absu.startswith("http://"):
                        mixed.add(absu)

            for href in parser.links:
                nxt = urljoin(url, href)
                p = urlparse(nxt)
                if p.scheme in ("http", "https") and p.netloc == origin.netloc:
                    clean = nxt.split("#")[0]
                    if clean not in seen:
                        queue.append((clean, depth + 1))

        findings.append(self.finding(
            target, f"Crawled {len(seen)} page(s)",
            severity=Severity.INFO,
            detail=f"Base: {base}. Depth<= {MAX_DEPTH}, budget {MAX_PAGES}.",
            evidence={"base": base, "pages": sorted(seen)[:MAX_PAGES]}))

        if forms_found:
            findings.append(self.finding(
                target, f"{len(forms_found)} HTML form(s) found",
                severity=Severity.INFO,
                detail="Candidate input points for authorized testing.",
                recommendation="Ensure forms have CSRF protection and server-side validation.",
                evidence={"forms": forms_found[:25]}))

        if mixed:
            findings.append(self.finding(
                target, f"Mixed content: {len(mixed)} insecure resource(s)",
                severity=Severity.MEDIUM,
                detail="HTTPS pages reference http:// resources.",
                recommendation="Serve all resources over HTTPS to avoid downgrade/MITM risks.",
                evidence={"resources": sorted(mixed)[:25]}))
        return findings

    def _well_known(self, target: Target, base: str, ctx: ModuleContext) -> list[Finding]:
        out: list[Finding] = []
        ctx.throttle()
        robots = fetch(base + "/robots.txt", timeout=2.0)
        if robots.status == 200 and robots.body:
            disallows = [ln.split(":", 1)[1].strip()
                         for ln in robots.text.splitlines()
                         if ln.lower().startswith("disallow:")]
            out.append(self.finding(
                target, "robots.txt present",
                severity=Severity.INFO,
                detail=f"{len(disallows)} Disallow rule(s).",
                evidence={"disallow": disallows[:40]}))

        sitemap = fetch(base + "/sitemap.xml", timeout=2.0)
        if sitemap.status == 200:
            out.append(self.finding(target, "sitemap.xml present", severity=Severity.INFO,
                                    evidence={"url": base + "/sitemap.xml"}))

        sec = fetch(base + "/.well-known/security.txt", timeout=2.0)
        if sec.status != 200:
            out.append(self.finding(
                target, "No security.txt",
                severity=Severity.LOW,
                detail="No /.well-known/security.txt published.",
                recommendation="Publish a security.txt with a contact for vulnerability reports (RFC 9116)."))
        else:
            out.append(self.finding(target, "security.txt published", severity=Severity.INFO))
        return out
