"""Strict Pydantic output models for ReconEveryThings JSON results."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from rec_cli import TOOL_NAME, __version__


class Mode(str, Enum):
    INFRA = "infra"
    OSINT = "osint"


class PivotType(str, Enum):
    INFRA_TO_OSINT = "infra_to_osint"
    OSINT_TO_INFRA = "osint_to_infra"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Meta(StrictModel):
    tool: str = TOOL_NAME
    version: str = __version__
    target: str
    mode: Mode
    stealth_enabled: bool
    strict_level: int = Field(default=0, ge=0, le=1)
    timestamp_utc: str
    modules_executed: list[str] = Field(default_factory=list)


class ASNRecord(StrictModel):
    asn: str = ""
    cidr: list[str] = Field(default_factory=list)
    description: str = ""


class WhoisASN(StrictModel):
    registrar: str = ""
    registrant_org: str = ""
    registrant_emails: list[str] = Field(default_factory=list)
    asns: list[ASNRecord] = Field(default_factory=list)


class Technology(StrictModel):
    name: str
    version: str | None = None


class HTTPInfo(StrictModel):
    url: str = ""
    status_code: int = 0
    title: str = ""
    technologies: list[Technology] = Field(default_factory=list)
    tls_cn: list[str] = Field(default_factory=list)


class PathFinding(StrictModel):
    url: str = ""
    path: str = ""
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    category: str = "discovered"
    sensitive: bool = False
    redirect_to: str = ""
    depth: int = 0
    source: str = ""


class AssetFinding(StrictModel):
    url: str = ""
    kind: Literal["js", "css", "html"] = "html"
    host: str = ""
    source_url: str = ""
    depth: int = 0


class VHostFinding(StrictModel):
    hostname: str = ""
    base_host: str = ""
    ip: str = ""
    url: str = ""
    status_code: int = 0
    content_length: int = 0
    content_type: str = ""
    title: str = ""


class ArchivedURL(StrictModel):
    url: str = ""
    timestamp: str = ""
    wayback_url: str = ""
    status_code: int = 0
    mime_type: str = ""


class SecretFinding(StrictModel):
    type: str
    match: str
    source_url: str


class JSFindings(StrictModel):
    js_urls: list[str] = Field(default_factory=list)
    extracted_endpoints: list[str] = Field(default_factory=list)
    discovered_emails_or_authors: list[str] = Field(default_factory=list)
    potential_secrets: list[SecretFinding] = Field(default_factory=list)


class Vulnerability(StrictModel):
    cve_id: str
    cvss: float = 0.0
    affected_Component: str
    summary: str = ""


class WAFInfo(StrictModel):
    detected: bool = False
    name: str | None = None
    manufacturer: str = ""
    source: str = ""
    evidence: list[str] = Field(default_factory=list)


class HostRecord(StrictModel):
    hostname: str
    ip: str = ""
    cdn_waf: str | None = None
    waf: WAFInfo = Field(default_factory=WAFInfo)
    open_ports: list[int] = Field(default_factory=list)
    http_info: HTTPInfo = Field(default_factory=HTTPInfo)
    path_findings: list[PathFinding] = Field(default_factory=list)
    assets: list[AssetFinding] = Field(default_factory=list)
    vhosts: list[VHostFinding] = Field(default_factory=list)
    historical_urls: list[ArchivedURL] = Field(default_factory=list)
    js_findings: JSFindings = Field(default_factory=JSFindings)
    potential_vulnerabilities: list[Vulnerability] = Field(default_factory=list)


class InfraData(StrictModel):
    whois_asn: WhoisASN = Field(default_factory=WhoisASN)
    hosts: list[HostRecord] = Field(default_factory=list)


class TargetIdentity(StrictModel):
    name: str | None = None
    usernames: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    organization: str | None = None


class SocialProfile(StrictModel):
    platform: str
    url: str
    bio_or_notes: str = ""


class UsernameCheckSummary(StrictModel):
    source: str = ""
    usernames_checked: list[str] = Field(default_factory=list)
    sites_checked: int = 0
    matches: int = 0
    errors: int = 0


class BreachFinding(StrictModel):
    identifier: str = ""
    provider: str = ""
    breach: str = ""
    title: str = ""
    domain: str = ""
    breach_date: str = ""
    data_classes: list[str] = Field(default_factory=list)
    pwn_count: int = 0
    verified: bool = False
    sensitive: bool = False


class BreachSummary(StrictModel):
    providers_used: list[str] = Field(default_factory=list)
    providers_skipped: list[str] = Field(default_factory=list)
    provider_errors: list[str] = Field(default_factory=list)
    identifiers_checked: list[str] = Field(default_factory=list)
    findings: list[BreachFinding] = Field(default_factory=list)


class GitFinding(StrictModel):
    repo_url: str
    commit_emails: list[str] = Field(default_factory=list)
    leaked_indicators: list[str] = Field(default_factory=list)


class DocumentMetadata(StrictModel):
    file_url: str
    author: str = ""
    creator_tool: str = ""
    internal_paths: list[str] = Field(default_factory=list)


class OSINTData(StrictModel):
    target_identity: TargetIdentity = Field(default_factory=TargetIdentity)
    username_enum: UsernameCheckSummary = Field(
        default_factory=UsernameCheckSummary
    )
    social_profiles: list[SocialProfile] = Field(default_factory=list)
    breach: BreachSummary = Field(default_factory=BreachSummary)
    git_findings: list[GitFinding] = Field(default_factory=list)
    document_metadata: list[DocumentMetadata] = Field(default_factory=list)
    strict_filtered: int = 0


class PivotSuggestion(StrictModel):
    source: str
    pivot_type: PivotType
    target_value: str
    reason: str


class ReconResult(StrictModel):
    meta: Meta
    infra_data: InfraData = Field(default_factory=InfraData)
    osint_data: OSINTData = Field(default_factory=OSINTData)
    pivots_suggested: list[PivotSuggestion] = Field(default_factory=list)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def build_meta(
    target: str,
    mode: Mode,
    stealth: bool,
    modules: list[str],
    strict_level: int = 0,
) -> Meta:
    return Meta(
        tool=TOOL_NAME,
        version=__version__,
        target=target,
        mode=mode,
        stealth_enabled=stealth,
        strict_level=strict_level,
        timestamp_utc=utc_now_iso(),
        modules_executed=modules,
    )


__all__ = [
    "Mode",
    "PivotType",
    "Meta",
    "ASNRecord",
    "WhoisASN",
    "Technology",
    "HTTPInfo",
    "PathFinding",
    "AssetFinding",
    "VHostFinding",
    "ArchivedURL",
    "SecretFinding",
    "JSFindings",
    "Vulnerability",
    "WAFInfo",
    "HostRecord",
    "InfraData",
    "TargetIdentity",
    "SocialProfile",
    "UsernameCheckSummary",
    "BreachFinding",
    "BreachSummary",
    "GitFinding",
    "DocumentMetadata",
    "OSINTData",
    "PivotSuggestion",
    "ReconResult",
    "build_meta",
    "utc_now_iso",
]
