"""Public repository commit history and configuration leak analysis."""

from __future__ import annotations

import base64
import re
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from rec_cli.config import API_ENDPOINTS
from rec_cli.modules import is_domain_like
from rec_cli.schema import GitFinding
from rec_cli.utils.logger import safe_text
from rec_cli.utils.runner import dedupe, gather_limited

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,24}\b"
)
_IMAGE_RE = re.compile(
    r"\b(?:image:\s*|FROM\s+)([A-Za-z0-9._/\-]+):([A-Za-z0-9._\-]+)",
    re.IGNORECASE,
)
_TICKET_RE = re.compile(r"\b([A-Z][A-Z0-9]{1,9}-\d{1,6})\b")
_SENSITIVE_LINE_RE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"access[_-]?key|connection[_-]?string)"
)
_INTERNAL_LINE_RE = re.compile(
    r"(?i)(?:host|hostname|url|endpoint|domain|project|app[_-]?name|"
    r"service[_-]?name|environment|image|version)\s*[:=]"
)
_CONFIG_PATHS = (
    "README.md",
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env.example",
    ".env.sample",
    "config.yml",
    "config.yaml",
    "application.properties",
    "application.yml",
    "package.json",
)
_PUBLIC_DOMAIN_MARKERS = (
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "npmjs.com",
    "pypi.org",
    "python.org",
    "nodejs.org",
    "docker.com",
    "docker.io",
    "google.com",
    "microsoft.com",
    "example.com",
    "localhost",
    "schema.org",
    "w3.org",
    "json-schema.org",
    "apache.org",
    "openssl.org",
    "cloudflare.com",
    "amazonaws.com",
    "azure.com",
    "medium.com",
    "stackoverflow.com",
)
_FILE_EXTENSIONS = (
    ".js", ".ts", ".py", ".rb", ".go", ".java", ".json", ".yml", ".yaml",
    ".md", ".html", ".css", ".xml", ".lock", ".toml", ".ini", ".txt",
)


def _github_headers(ctx: "ReconContext") -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if ctx.settings.github_token:
        headers["Authorization"] = f"Bearer {ctx.settings.github_token}"
    return headers


def _gitlab_headers(ctx: "ReconContext") -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if ctx.settings.gitlab_token:
        headers["PRIVATE-TOKEN"] = ctx.settings.gitlab_token
    return headers


def _is_public_domain(domain: str) -> bool:
    lowered = domain.lower()
    if lowered.endswith(_FILE_EXTENSIONS):
        return True
    return any(
        lowered == marker or lowered.endswith("." + marker)
        for marker in _PUBLIC_DOMAIN_MARKERS
    )


def _extract_domains(text: str) -> list[str]:
    domains: list[str] = []
    for match in _DOMAIN_RE.findall(text):
        domain = match.lower().strip(".")
        if not is_domain_like(domain) or _is_public_domain(domain):
            continue
        if domain not in domains:
            domains.append(domain)
    return domains[:50]


def _extract_config_indicators(text: str, source: str) -> list[str]:
    indicators: list[str] = []
    for raw_line in text.splitlines()[:5000]:
        line = " ".join(raw_line.strip().split())
        if not line or line.startswith(("#", "//", ";")):
            continue
        if _SENSITIVE_LINE_RE.search(line):
            indicators.append(f"config sensitive line in {source}: {line[:220]}")
        elif _INTERNAL_LINE_RE.search(line) and len(line) <= 240:
            indicators.append(f"config line in {source}: {line[:220]}")
        if len(indicators) >= 25:
            break
    for match in _IMAGE_RE.finditer(text):
        indicators.append(f"container image in {source}: {match.group(1)}:{match.group(2)}")
    for domain in _extract_domains(text):
        indicators.append(f"domain in {source}: {domain}")
    for match in _TICKET_RE.findall(text):
        if match in {"CVE", "RFC", "HTTP", "ISO", "UTF", "SHA", "AES"}:
            continue
        if not match.startswith("CVE-"):
            indicators.append(f"project/ticket key in {source}: {match}")
    return dedupe(indicators, 60)


def _commit_indicators(
    messages: list[str], emails: list[str]
) -> tuple[list[str], list[str]]:
    indicators: list[str] = []
    corporate: list[str] = []
    for email in emails:
        lowered = email.lower()
        if "noreply" in lowered or lowered.endswith("@users.noreply.github.com"):
            continue
        corporate.append(lowered)
    for message in messages:
        indicators.extend(
            f"commit message indicator: {item}"
            for item in _extract_domains(message)
        )
        for match in _TICKET_RE.findall(message):
            if not match.startswith(("CVE-", "RFC-")):
                indicators.append(f"project/ticket key in commit: {match}")
        for match in _IMAGE_RE.finditer(message):
            indicators.append(
                f"container image in commit: {match.group(1)}:{match.group(2)}"
            )
    return dedupe(corporate, 100), dedupe(indicators, 100)


def _decode_github_content(payload: Any) -> str:
    if not isinstance(payload, dict):
        return ""
    content = payload.get("content")
    encoding = payload.get("encoding")
    if not content or encoding != "base64":
        return ""
    try:
        raw = base64.b64decode(content)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return ""


async def _github_file(
    ctx: "ReconContext", full_name: str, path: str
) -> str:
    data, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['github_api']}/repos/{full_name}/contents/"
        f"{quote(path, safe='')}",
        headers=_github_headers(ctx),
        max_bytes=2_000_000,
    )
    if response.error or not isinstance(data, dict):
        return ""
    if data.get("size", 0) and int(data.get("size", 0)) > 1_500_000:
        return ""
    return _decode_github_content(data)


async def _github_repo_finding(
    ctx: "ReconContext", repo: dict[str, Any]
) -> GitFinding | None:
    full_name = str(repo.get("full_name", ""))
    if not full_name:
        return None
    repo_url = str(repo.get("html_url", f"https://github.com/{full_name}"))
    if repo_url in ctx.git_seen_repos:
        return None
    ctx.git_seen_repos.add(repo_url)

    commits_data, commits_response = await ctx.http.get_json(
        f"{API_ENDPOINTS['github_api']}/repos/{full_name}/commits",
        params={"per_page": "50"},
        headers=_github_headers(ctx),
        max_bytes=3_000_000,
    )
    if commits_response.status_code == 403:
        ctx.logger.warn("GitHub API rate limit reached during commit collection")
        return None

    commit_emails: list[str] = []
    messages: list[str] = []
    if isinstance(commits_data, list):
        for entry in commits_data[:50]:
            if not isinstance(entry, dict):
                continue
            commit = entry.get("commit")
            if not isinstance(commit, dict):
                continue
            author = commit.get("author")
            if isinstance(author, dict):
                email = str(author.get("email", "")).strip().lower()
                if email and _EMAIL_RE.match(email):
                    commit_emails.append(email)
            message = str(commit.get("message", ""))
            if message:
                messages.append(message[:500])
    commit_emails = dedupe(commit_emails, 100)
    corporate_emails, indicators = _commit_indicators(messages, commit_emails)

    for path in _CONFIG_PATHS[:3]:
        content = await _github_file(ctx, full_name, path)
        if content:
            indicators.extend(_extract_config_indicators(content, path))
    indicators = dedupe(indicators, 150)

    for email in corporate_emails[:30]:
        if email not in ctx.osint.target_identity.emails:
            ctx.osint.target_identity.emails.append(email)
    for indicator in indicators:
        for domain in _extract_domains(indicator):
            ctx.osint_to_infra_candidates.append(
                (
                    f"git:{full_name}",
                    domain,
                    "domain referenced in public repository metadata",
                )
            )

    return GitFinding(
        repo_url=repo_url,
        commit_emails=commit_emails,
        leaked_indicators=[safe_text(item, 500) for item in indicators],
    )


async def _github_user_findings(
    ctx: "ReconContext", username: str
) -> list[GitFinding]:
    if ctx.github_exhausted:
        return []
    headers = _github_headers(ctx)
    data, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['github_api']}/users/{quote(username)}/repos",
        params={"per_page": "50", "type": "owner", "sort": "updated"},
        headers=headers,
        max_bytes=4_000_000,
    )
    if response.status_code == 403:
        ctx.github_exhausted = True
        ctx.logger.warn("GitHub API rate limit reached")
        return []
    if response.error or not isinstance(data, list):
        return []
    repo_limit = (
        12
        if ctx.settings.github_token
        else (4 if ctx.settings.stealth else 6)
    )
    repos = [repo for repo in data if isinstance(repo, dict) and not repo.get("fork")]
    if not repos:
        repos = [repo for repo in data if isinstance(repo, dict)]
    findings: list[GitFinding] = []
    for repo in repos[:repo_limit]:
        if ctx.github_exhausted:
            break
        finding = await _github_repo_finding(ctx, repo)
        if finding:
            findings.append(finding)
            ctx.logger.found(
                f"git repository: {finding.repo_url} "
                f"emails={len(finding.commit_emails)} "
                f"indicators={len(finding.leaked_indicators)}"
            )
    return findings


async def _gitlab_user_findings(
    ctx: "ReconContext", username: str
) -> list[GitFinding]:
    if ctx.gitlab_exhausted:
        return []
    headers = _gitlab_headers(ctx)
    users, response = await ctx.http.get_json(
        f"{API_ENDPOINTS['gitlab_api']}/users",
        params={"username": username},
        headers=headers,
        max_bytes=1_500_000,
    )
    if response.status_code in (403, 429):
        ctx.gitlab_exhausted = True
        return []
    if response.error or not isinstance(users, list):
        return []
    user_id = None
    for item in users:
        if isinstance(item, dict) and str(item.get("username", "")).lower() == username.lower():
            user_id = item.get("id")
            break
    if user_id is None:
        return []

    projects, projects_response = await ctx.http.get_json(
        f"{API_ENDPOINTS['gitlab_api']}/users/{user_id}/projects",
        params={"per_page": "30", "order_by": "last_activity_at"},
        headers=headers,
        max_bytes=3_000_000,
    )
    if projects_response.error or not isinstance(projects, list):
        return []
    project_limit = 4 if ctx.settings.stealth else 6
    findings: list[GitFinding] = []
    for project in projects[:project_limit]:
        if not isinstance(project, dict) or not project.get("id"):
            continue
        repo_url = str(
            project.get("web_url", f"https://gitlab.com/{project.get('path_with_namespace', '')}")
        )
        if repo_url in ctx.git_seen_repos:
            continue
        ctx.git_seen_repos.add(repo_url)
        commits, commits_response = await ctx.http.get_json(
            f"{API_ENDPOINTS['gitlab_api']}/projects/{project['id']}/repository/commits",
            params={"per_page": "50"},
            headers=headers,
            max_bytes=3_000_000,
        )
        if commits_response.error or not isinstance(commits, list):
            continue
        commit_emails: list[str] = []
        messages: list[str] = []
        for entry in commits[:50]:
            if not isinstance(entry, dict):
                continue
            email = str(entry.get("author_email", "")).strip().lower()
            if email and _EMAIL_RE.match(email):
                commit_emails.append(email)
            message = str(entry.get("message", ""))
            if message:
                messages.append(message[:500])
        commit_emails = dedupe(commit_emails, 100)
        corporate_emails, indicators = _commit_indicators(messages, commit_emails)
        for email in corporate_emails[:30]:
            if email not in ctx.osint.target_identity.emails:
                ctx.osint.target_identity.emails.append(email)
        for indicator in indicators:
            for domain in _extract_domains(indicator):
                ctx.osint_to_infra_candidates.append(
                    (
                        f"gitlab:{project.get('path_with_namespace', '')}",
                        domain,
                        "domain referenced in public GitLab metadata",
                    )
                )
        finding = GitFinding(
            repo_url=repo_url,
            commit_emails=commit_emails,
            leaked_indicators=[safe_text(item, 500) for item in indicators],
        )
        findings.append(finding)
        ctx.logger.found(
            f"git repository: {repo_url} emails={len(commit_emails)} "
            f"indicators={len(indicators)}"
        )
    return findings


async def run(ctx: "ReconContext") -> None:
    usernames = ctx.osint.target_identity.usernames[: 1 if ctx.settings.stealth else 2]
    if not usernames:
        ctx.logger.info("git analysis skipped: no username available")
        return

    tasks = []
    for username in usernames:
        tasks.append(_github_user_findings(ctx, username))
        tasks.append(_gitlab_user_findings(ctx, username))
    results = await gather_limited(tasks, limit=2)
    for findings in results:
        for finding in findings:
            if not any(
                item.repo_url == finding.repo_url
                for item in ctx.osint.git_findings
            ):
                ctx.osint.git_findings.append(finding)

    if not ctx.osint.git_findings:
        ctx.logger.info("no public repositories or commit history discovered")
    else:
        ctx.logger.info(
            f"git analysis complete: {len(ctx.osint.git_findings)} repositories"
        )
