"""Vendor research utilities for autonomous assessment mode."""

from __future__ import annotations

import html
import ipaddress
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

USER_AGENT = "BriskRiskTracker/0.1 (+internal-security-review)"


@dataclass
class SourceSnippet:
    title: str
    url: str
    snippet: str


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _is_safe_url(newurl):
            raise urllib.error.URLError("Blocked unsafe redirect target")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _is_safe_url(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    host = parsed.hostname
    if not host:
        return False
    try:
        addr = socket.gethostbyname(host)
        ip = ipaddress.ip_address(addr)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    except Exception:
        return False
    return True


def _fetch(url: str, timeout: int = 8) -> str:
    if not _is_safe_url(url):
        return ""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(SafeRedirectHandler())
    with opener.open(req, timeout=timeout) as resp:  # nosec B310
        final_url = resp.geturl()
        if not _is_safe_url(final_url):
            return ""
        content_type = (resp.headers.get("Content-Type") or "").lower()
        if "text/html" not in content_type:
            return ""
        raw = resp.read(250_000)
        return raw.decode("utf-8", errors="ignore")


def _strip_html(value: str) -> str:
    value = re.sub(r"<script\b[^<]*(?:(?!</script>)<[^<]*)*</script>", " ", value, flags=re.I)
    value = re.sub(r"<style\b[^<]*(?:(?!</style>)<[^<]*)*</style>", " ", value, flags=re.I)
    value = re.sub(r"<[^>]+>", " ", value)
    value = html.unescape(value)
    value = re.sub(r"\s+", " ", value).strip()
    return value


def _search_duckduckgo(query: str, limit: int = 5) -> list[SourceSnippet]:
    encoded = urllib.parse.urlencode({"q": query})
    search_url = f"https://duckduckgo.com/html/?{encoded}"
    page = _fetch(search_url)
    if not page:
        return []

    results: list[SourceSnippet] = []
    for match in re.finditer(r'<a rel="nofollow" class="result__a" href="([^"]+)">(.*?)</a>', page):
        href = html.unescape(match.group(1))
        title = _strip_html(match.group(2))
        if "/l/?uddg=" in href:
            parsed = urllib.parse.urlparse(href)
            qs = urllib.parse.parse_qs(parsed.query)
            href = urllib.parse.unquote(qs.get("uddg", [""])[0])
        if not _is_safe_url(href):
            continue
        results.append(SourceSnippet(title=title, url=href, snippet=""))
        if len(results) >= limit:
            break
    return results


def gather_vendor_evidence(vendor_name: str, max_sources: int = 5) -> tuple[str, list[dict[str, str]]]:
    queries = [
        f"{vendor_name} official documentation",
        f"{vendor_name} trust center security",
        f"{vendor_name} compliance SOC 2 ISO 27001",
    ]

    collected: list[SourceSnippet] = []
    seen: set[str] = set()
    for query in queries:
        for result in _search_duckduckgo(query, limit=max_sources):
            if result.url in seen:
                continue
            seen.add(result.url)
            page = _fetch(result.url)
            if not page:
                continue
            text = _strip_html(page)
            snippet = text[:1200]
            collected.append(SourceSnippet(title=result.title, url=result.url, snippet=snippet))
            if len(collected) >= max_sources:
                break
        if len(collected) >= max_sources:
            break

    evidence_lines = []
    for source in collected:
        evidence_lines.append(f"SOURCE: {source.title} | {source.url}\n{source.snippet}\n")
    evidence_text = "\n".join(evidence_lines).strip()

    source_objects = [{"title": s.title, "url": s.url, "snippet": s.snippet[:400]} for s in collected]
    return evidence_text, source_objects
