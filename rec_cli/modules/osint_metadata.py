"""Public document discovery and PDF/Office/image metadata extraction."""

from __future__ import annotations

import io
import re
import zipfile
from typing import TYPE_CHECKING
from urllib.parse import urlparse
from xml.etree import ElementTree

from rec_cli.modules import is_domain_like
from rec_cli.modules.osint_social import web_search
from rec_cli.schema import DocumentMetadata
from rec_cli.utils.logger import safe_text
from rec_cli.utils.runner import dedupe

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_DOC_EXTENSIONS = {
    ".pdf", ".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt",
    ".jpg", ".jpeg", ".png",
}
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}\b"
)
_PATH_PATTERNS = (
    re.compile(r"[A-Za-z]:\\[^\s<>\"'|]{3,160}"),
    re.compile(r"\\\\[A-Za-z0-9._\-]+\\[^\s<>\"'|]{2,160}"),
    re.compile(r"/(?:Users|home|mnt|srv|var|opt|etc|root)/[^\s<>\"'|]{2,160}"),
)
_PDF_INFO_RE = re.compile(
    r"/(Author|Creator|Producer|Title|Subject)\s*\(([^)]{0,800})\)"
)
_XMP_TAG_RE = r"<{tag}[^>]*>(.*?)</{tag}>"


def _document_type(url: str, content_type: str) -> str | None:
    lowered_type = content_type.lower()
    if "pdf" in lowered_type:
        return "pdf"
    if "wordprocessingml" in lowered_type:
        return "docx"
    if "spreadsheetml" in lowered_type:
        return "xlsx"
    if "presentationml" in lowered_type:
        return "pptx"
    if lowered_type.startswith("image/"):
        return "image"
    path = urlparse(url).path.lower()
    if path.endswith(".pdf"):
        return "pdf"
    if path.endswith(".docx"):
        return "docx"
    if path.endswith(".xlsx"):
        return "xlsx"
    if path.endswith(".pptx"):
        return "pptx"
    if path.endswith((".jpg", ".jpeg", ".png")):
        return "image"
    if path.endswith((".doc", ".xls", ".ppt")):
        return "legacy_office"
    return None


def _clean_meta(value: str) -> str:
    return safe_text(" ".join(value.replace("\\(", "(").replace("\\)", ")").split()), 500)


def _extract_paths(text: str) -> list[str]:
    paths: list[str] = []
    for pattern in _PATH_PATTERNS:
        for match in pattern.findall(text):
            cleaned = match.strip(" .,;:)]}>\"'")
            if len(cleaned) >= 5 and cleaned not in paths:
                paths.append(cleaned)
    return paths[:25]


def _extract_emails_and_domains(text: str) -> tuple[list[str], list[str]]:
    emails = dedupe([email.lower() for email in _EMAIL_RE.findall(text)], 50)
    domains: list[str] = []
    for domain in _DOMAIN_RE.findall(text):
        lowered = domain.lower()
        if not is_domain_like(lowered):
            continue
        if lowered.endswith(
            (".pdf", ".docx", ".xlsx", ".pptx", ".jpg", ".jpeg", ".png")
        ):
            continue
        if lowered not in domains:
            domains.append(lowered)
    return emails, domains[:50]


def _parse_pdf(content: bytes) -> tuple[str, str, list[str]]:
    author = ""
    creator = ""
    text_samples: list[str] = []
    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(io.BytesIO(content), strict=False)
        metadata = reader.metadata or {}
        author = str(metadata.get("/Author", "") or "")
        creator = str(
            metadata.get("/Creator", "")
            or metadata.get("/Producer", "")
            or ""
        )
        text_samples.extend(str(value) for value in metadata.values() if value)
        for page in reader.pages[:2]:
            try:
                page_text = page.extract_text() or ""
            except Exception:
                page_text = ""
            text_samples.append(page_text[:50_000])
    except Exception:
        pass

    raw = content[:3_000_000].decode("latin-1", errors="replace")
    if not author or not creator:
        for key, value in _PDF_INFO_RE.findall(raw):
            cleaned = _clean_meta(value)
            if key == "Author" and not author:
                author = cleaned
            elif key in ("Creator", "Producer") and not creator:
                creator = cleaned
            text_samples.append(cleaned)
    for tag in ("dc:creator", "xmp:CreatorTool", "pdf:Producer", "dc:title"):
        for value in re.findall(_XMP_TAG_RE.format(tag=tag), raw, re.DOTALL):
            text_samples.append(value)
            if tag == "xmp:CreatorTool" and not creator:
                creator = _clean_meta(value)
        for value in re.findall(
            rf"<{tag}>\s*<rdf:Seq>\s*<rdf:li[^>]*>(.*?)</rdf:li>",
            raw,
            re.DOTALL,
        ):
            text_samples.append(value)

    paths = _extract_paths(" ".join(text_samples))
    return _clean_meta(author), _clean_meta(creator), paths


def _xml_local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _safe_xml(data: bytes) -> ElementTree.Element:
    upper = data[:200_000].upper()
    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
        raise ElementTree.ParseError("DTD and entity declarations are not allowed")
    try:
        from defusedxml.ElementTree import fromstring  # type: ignore

        return fromstring(data)
    except ImportError:
        return ElementTree.fromstring(data)


def _parse_office(content: bytes) -> tuple[str, str, list[str]]:
    author = ""
    creator_tool = ""
    text_samples: list[str] = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            compressed_total = 0
            for info in archive.infolist():
                if info.file_size > 5_000_000:
                    continue
                compressed_total += info.file_size
                if compressed_total > 20_000_000:
                    break
                if info.filename in ("docProps/core.xml", "docProps/app.xml"):
                    try:
                        data = archive.read(info)
                    except Exception:
                        continue
                    text_samples.append(data.decode("utf-8", errors="replace"))
                    try:
                        root = _safe_xml(data)
                    except (ElementTree.ParseError, ValueError):
                        continue
                    for element in root.iter():
                        local = _xml_local(element.tag).lower()
                        value = (element.text or "").strip()
                        if not value:
                            continue
                        if local in ("creator", "lastmodifiedby") and not author:
                            author = value
                        elif local in ("creator", "lastmodifiedby"):
                            continue
                        elif local == "application" and not creator_tool:
                            creator_tool = value
                        elif local == "company" and not creator_tool:
                            creator_tool = value
                elif info.filename.endswith(
                    (".xml", ".rels")
                ) and (
                    info.filename.startswith(("word/", "xl/", "ppt/"))
                    or info.filename.endswith(".xml")
                ):
                    try:
                        data = archive.read(info)[:2_000_000]
                    except Exception:
                        continue
                    text_samples.append(data.decode("utf-8", errors="replace"))
    except (zipfile.BadZipFile, OSError):
        pass

    joined = " ".join(text_samples)
    paths = _extract_paths(joined)
    return _clean_meta(author), _clean_meta(creator_tool), paths


def _parse_image(content: bytes) -> tuple[str, str, list[str]]:
    author = ""
    creator_tool = ""
    values: list[str] = []
    try:
        from PIL import Image  # type: ignore

        with Image.open(io.BytesIO(content)) as image:
            exif = image.getexif()
            for tag, value in exif.items():
                if tag == 315:
                    author = str(value)
                elif tag == 305:
                    creator_tool = str(value)
                elif tag in (270, 306, 33432):
                    values.append(str(value))
    except Exception:
        pass
    paths = _extract_paths(" ".join(values))
    return _clean_meta(author), _clean_meta(creator_tool), paths


def _parse_legacy_office(content: bytes) -> tuple[str, str, list[str]]:
    text = content[:5_000_000].decode("latin-1", errors="replace")
    printable = " ".join(re.findall(r"[\x20-\x7e]{5,300}", text))
    author = ""
    creator = ""
    author_match = re.search(
        r"(?i)\\?author\\?\s*[:=]\s*([A-Za-z][A-Za-z0-9 ._'\-]{2,80})",
        printable,
    )
    if author_match:
        author = author_match.group(1)
    software_match = re.search(
        r"(?i)(Microsoft (?:Word|Excel|PowerPoint) [0-9.]+)", printable
    )
    if software_match:
        creator = software_match.group(1)
    return _clean_meta(author), _clean_meta(creator), _extract_paths(printable)


def extract_document_metadata(
    content: bytes, url: str, content_type: str = ""
) -> DocumentMetadata | None:
    """Extract author, creator tool, and internal paths from a document."""
    doc_type = _document_type(url, content_type)
    if doc_type is None:
        return None
    if doc_type == "pdf":
        author, creator, paths = _parse_pdf(content)
    elif doc_type in ("docx", "xlsx", "pptx"):
        author, creator, paths = _parse_office(content)
    elif doc_type == "image":
        author, creator, paths = _parse_image(content)
    else:
        author, creator, paths = _parse_legacy_office(content)
    return DocumentMetadata(
        file_url=url,
        author=author,
        creator_tool=creator,
        internal_paths=paths,
    )


def _queries(ctx: "ReconContext") -> list[str]:
    identity = ctx.osint.target_identity
    base_values = dedupe(
        [
            value
            for value in (identity.name, ctx.target, *identity.emails[:2], *identity.usernames[:1])
            if value
        ],
        4,
    )
    queries: list[str] = []
    for value in base_values:
        escaped = value.replace('"', "")
        queries.append(
            f'"{escaped}" (filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx)'
        )
    if identity.organization:
        queries.append(
            f'"{identity.organization}" filetype:pdf metadata'
        )
    return dedupe(queries, 3)


async def run(ctx: "ReconContext") -> None:
    urls: list[str] = []
    for query in _queries(ctx):
        results = await web_search(ctx.http, ctx.logger, ctx.settings, query, limit=8)
        for result in results:
            url = result.get("url", "")
            try:
                if urlparse(url).path.lower().endswith(tuple(_DOC_EXTENSIONS)):
                    urls.append(url)
            except ValueError:
                continue
    urls = dedupe(urls, 8 if not ctx.settings.stealth else 4)
    if not urls:
        ctx.logger.info("no public documents discovered for the target")
        return

    ctx.logger.info(f"downloading {len(urls)} public document(s) for metadata")
    for url in urls:
        response = await ctx.http.get(
            url,
            max_bytes=ctx.settings.max_document_bytes,
            headers={"Accept": "application/pdf,application/octet-stream,*/*"},
        )
        if response.error or response.status_code >= 400 or not response.content:
            continue
        metadata = extract_document_metadata(
            response.content, response.url, response.header("content-type")
        )
        if metadata is None:
            continue
        ctx.osint.document_metadata.append(metadata)
        ctx.logger.found(
            f"document metadata: {metadata.file_url} "
            f"author={metadata.author or 'unknown'} "
            f"tool={metadata.creator_tool or 'unknown'} "
            f"paths={len(metadata.internal_paths)}"
        )
        joined = " ".join(
            [metadata.author, metadata.creator_tool, *metadata.internal_paths]
        )
        emails, domains = _extract_emails_and_domains(joined)
        for email in emails:
            if email not in ctx.osint.target_identity.emails:
                ctx.osint.target_identity.emails.append(email)
        for domain in domains:
            ctx.osint_to_infra_candidates.append(
                (
                    "document_metadata",
                    domain,
                    "domain or host reference found in document metadata",
                )
            )

    if not ctx.osint.document_metadata:
        ctx.logger.info("no parseable document metadata was recovered")
