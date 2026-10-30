"""Identity normalization and email/username permutation generation."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from rec_cli.modules import registrable_domain
from rec_cli.schema import TargetIdentity
from rec_cli.utils.runner import dedupe

if TYPE_CHECKING:
    from rec_cli.engine import ReconContext

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._\-]{2,64}$")
_FREE_MAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "ymail.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "gmx.com",
    "mail.com",
    "zoho.com",
    "yandex.com",
}
_SOCIAL_HOSTS = {
    "github.com",
    "gitlab.com",
    "linkedin.com",
    "www.linkedin.com",
    "stackoverflow.com",
    "reddit.com",
    "www.reddit.com",
    "medium.com",
    "x.com",
    "twitter.com",
}


def normalize_username(value: str) -> str:
    candidate = value.strip()
    if "://" in candidate:
        try:
            path = urlparse(candidate).path.strip("/")
            candidate = path.split("/", 1)[0] if path else ""
        except ValueError:
            candidate = ""
    candidate = candidate.lstrip("@").strip().lower()
    candidate = candidate.split("?", 1)[0].split("#", 1)[0]
    candidate = re.sub(r"[^a-z0-9._\-]", "", candidate)
    return candidate.strip("._-")[:64]


def _name_from_handle(handle: str) -> str | None:
    parts = [
        part
        for part in re.split(r"[._\-+]+", handle.split("@", 1)[0])
        if part and not part.isdigit()
    ]
    parts = [re.sub(r"\d+$", "", part) for part in parts]
    parts = [part for part in parts if part.isalpha() and len(part) >= 2]
    if not parts:
        return None
    return " ".join(part.capitalize() for part in parts[:3])


def _name_parts(name: str) -> list[str]:
    parts = [part for part in re.split(r"\s+", name.strip()) if part]
    cleaned = [re.sub(r"[^A-Za-z'\-]", "", part) for part in parts]
    return [part for part in cleaned if part]


def generate_username_variants(name: str | None, seed: str | None = None) -> list[str]:
    variants: list[str] = []
    if seed:
        variants.append(seed)
    if name:
        parts = _name_parts(name)
        lowered = [part.lower() for part in parts]
        if len(lowered) >= 2:
            first, last = lowered[0], lowered[-1]
            variants.extend(
                [
                    f"{first}.{last}",
                    f"{first}{last}",
                    f"{first}_{last}",
                    f"{first}-{last}",
                    f"{first[0]}.{last}",
                    f"{first}.{last[0]}",
                    f"{first[0]}{last}",
                    first,
                ]
            )
        elif lowered:
            variants.append(lowered[0])
    return dedupe([normalize_username(item) for item in variants if item], 10)


def _email_domain_org(domain: str) -> str | None:
    root = registrable_domain(domain)
    if root in _FREE_MAIL_DOMAINS:
        return None
    label = root.split(".", 1)[0]
    return label.replace("-", " ").replace("_", " ").title() or None


def _email_variants(name: str, domain: str) -> list[str]:
    parts = _name_parts(name)
    if len(parts) < 2:
        local = normalize_username(parts[0] if parts else name.split("@", 1)[0])
        return [f"{local}@{domain}"] if local else []
    first, last = parts[0].lower(), parts[-1].lower()
    locals_ = [
        f"{first}.{last}",
        f"{first}{last}",
        f"{first}_{last}",
        f"{first}-{last}",
        f"{first[0]}.{last}",
        f"{first}.{last[0]}",
        f"{first[0]}{last}",
        f"{last}.{first}",
    ]
    return dedupe([f"{local}@{domain}" for local in locals_], 12)


def _parse_target(target: str) -> dict[str, object]:
    value = target.strip()
    email_match = _EMAIL_RE.search(value)
    email = email_match.group(0).lower() if email_match else ""
    name_hint = ""
    if email:
        prefix = value[: email_match.start()].strip(" <>()[],;-")
        if prefix:
            name_hint = prefix

    username = ""
    if not email:
        if "://" in value:
            try:
                parsed = urlparse(value)
                host = (parsed.hostname or "").lower()
                path = parsed.path.strip("/")
                if host in _SOCIAL_HOSTS and path:
                    username = normalize_username(path.split("/", 1)[0])
            except ValueError:
                pass
        elif value.startswith("@"):
            username = normalize_username(value)
        elif " " not in value and _USERNAME_RE.match(value):
            username = normalize_username(value)
        elif " " not in value and "." in value:
            username = normalize_username(value)

    name = name_hint
    if not name and email:
        name = _name_from_handle(email) or ""
    if not name and username:
        name = _name_from_handle(username) or ""
    if not name and " " in value and not email:
        name = " ".join(part for part in value.split() if part.isalpha())

    return {
        "email": email,
        "username": username,
        "name": name or "",
        "raw": value,
    }


async def run(ctx: "ReconContext") -> None:
    parsed = _parse_target(ctx.target)
    email = str(parsed["email"])
    username_seed = str(parsed["username"])
    name = str(parsed["name"])
    raw = str(parsed["raw"])

    if not name and not username_seed and not email:
        name = " ".join(raw.split())[:120]

    domain = ""
    if email:
        domain = email.split("@", 1)[1].lower()

    usernames = generate_username_variants(name or None, username_seed or None)
    emails: list[str] = [email] if email else []
    if domain and name:
        emails.extend(_email_variants(name, domain))
    elif domain and username_seed:
        emails.extend(_email_variants(username_seed.replace(".", " "), domain))
    elif domain and "@" in raw and not email:
        emails.extend([f"{raw.split('@', 1)[0]}@{domain}"])

    organization = _email_domain_org(domain) if domain else None
    identity = TargetIdentity(
        name=name or None,
        usernames=usernames,
        emails=dedupe(emails, 20),
        organization=organization,
    )
    ctx.osint.target_identity = identity

    ctx.logger.info(
        f"identity normalized: name={identity.name or 'unknown'} "
        f"usernames={len(identity.usernames)} emails={len(identity.emails)}"
    )
    for username in identity.usernames:
        ctx.logger.found(f"username candidate: {username}")
    for candidate_email in identity.emails:
        ctx.logger.found(f"email candidate: {candidate_email}")
    if organization:
        ctx.logger.found(f"inferred organization: {organization}")
