# Pivoting Rules

This reference defines when to move between infrastructure and OSINT evidence.
The goal is to prevent unbounded expansion while preserving high-value leads.

## Core Rules

1. Pivot only on evidence that is attributable to the authorized target.
2. Require at least one strong signal or two independent weak signals.
3. Record the source, relation, and reason in the graph before running the next
   reconnaissance chain.
4. Do not pivot to generic public infrastructure providers or platform domains.
5. Do not pivot to personal accounts without explicit authorization for
   individual profiling.
6. Stop after two hops unless a new hop is supported by two independent
   sources.
7. Prefer a domain, email, or username that names the target organization or a
   verified individual. Avoid broad names that produce thousands of matches.

## Historical Archive Evidence

Wayback results describe past exposure, not current state.

1. Add a historical hostname as a `DOMAIN` node only when it falls inside the
   authorized registrable domain.
2. Record each archived URL as an `ARTIFACT` with
   `DOMAIN EXPOSES_ARCHIVED_URL ARTIFACT` and retain the replay link.
3. Confirm a historical host with current DNS, certificate, or HTTP evidence
   before active probing.
4. Do not request an archived URL from the live target solely because it appears
   in the archive.
5. Treat archived credentials, tokens, and personal data as historical evidence;
   do not attempt to use them.

## Breach Exposure Evidence

Breach findings are metadata about past exposure. They do not authorize use of
leaked credentials.

1. Record each finding as an `ARTIFACT` with a `breach:<16-char-hash>` identifier
   and relate it with `PERSON EXPOSED_IN_BREACH` or
   `ARTIFACT EXPOSED_IN_BREACH`.
2. Store only the provider, breach name, date, data classes, and counts.
3. Never retrieve, store, display, or use leaked records, passwords, hashes, or
   authentication tokens.
4. Do not attempt credential reuse, password spraying, or login testing.
5. If a live secret or credential is discovered, stop and escalate to the
   engagement owner before continuing.
6. Use breach exposure to prioritize defensive review, not to expand scope.

## Signal Strength

Strong signals:

- Registrant email from WHOIS or RDAP for the in-scope domain.
- Email or author name in target-owned JavaScript.
- Domain in a target-owned repository configuration file.
- Internal hostname in a target document's metadata.
- Verified social profile that links to the target domain.
- Certificate organization or SAN that names the target brand.
- Historical host from the Wayback Machine that is inside the authorized domain
  and absent from current passive DNS.
- Official breach API confirms an email address already linked to the target by
  WHOIS, first-party code, or a verified profile.

Weak signals:

- Username permutation that resolves to a profile with no target-linked
  content.
- Search engine result that mentions the target but is not owned by it.
- Technology match without a version.
- Single commit email on a repository with no target reference.
- Document author name without an organization or target domain.

Do not pivot on weak signals alone. Corroborate first.

Strict OSINT mode (`strict=1`) suppresses username and social profile
candidates that lack a second identity signal. A strict-accepted profile is
stronger than a level-0 match but is still an unverified lead. Candidates
counted in `strict_filtered` were suppressed and must not be used as pivot
evidence.

## Infrastructure To OSINT

### Trigger: Registrant Email

Condition: `whois_asn.registrant_emails` contains an address whose domain
matches the target or a related corporate domain.

Action:

1. Add `email:<address>` as an `ARTIFACT`.
2. Relate the domain to the email with `HAS_REGISTRANT_EMAIL`.
3. Run `rec_execute_cli` in OSINT mode with the email as target.
4. Restrict to `identity,social` first when the engagement does not authorize
   repository or document review.

Reason: registrant contacts are directly attributable to the domain record.

### Trigger: JavaScript Email Or Author

Condition: `crawler_js` reports an email or author string in target-owned
JavaScript, and the file URL is on an in-scope host.

Action:

1. Add `email:<address>` or `person:<normalized-name>` as a node.
2. Relate the host to the artifact with `REFERENCES_IDENTITY`.
3. Run OSINT mode with the artifact.
4. If the string is a generic library author, do not pivot.

Reason: first-party application code often contains real developer contacts.

### Trigger: Document Author

Condition: `document_metadata.author` is non-empty and the document is hosted on
an in-scope domain.

Action:

1. Add `person:<normalized-name>`.
2. Relate the document artifact to the person with `AUTHORED_BY`.
3. Search the person only if the name is specific and the scope permits
   individual profiling.
4. Treat matching names as unverified until a second link exists.

Reason: document metadata is easily stale and may name authors of templates.

### Trigger: JavaScript Internal Host

Condition: `extracted_endpoints` contains a hostname that is not the target and
not a public provider.

Action:

1. Add the hostname as a `DOMAIN` or `ARTIFACT`.
2. Relate the source file URL to the hostname with `REFERENCES_HOST`.
3. Confirm the hostname belongs to the target through certificate, WHOIS, or
   DNS evidence before running infrastructure mode.
4. Do not scan a third-party hostname.

Reason: internal hostnames can reveal unlisted infrastructure but may belong to
vendors.

## OSINT To Infrastructure

### Trigger: Corporate Email Domain

Condition: an identity email uses a domain other than the original target and
the email is attributable to the target organization.

Action:

1. Extract the registrable domain.
2. Confirm the domain is not a free mail provider.
3. Add the domain and relate it with `PIVOTED_TO`.
4. Run infrastructure mode with stealth enabled.
5. Compare ASN, certificate, and technology evidence with the original target.

Reason: corporate email domains often expose secondary attack surface.

### Trigger: Repository Configuration Domain

Condition: `git_findings.leaked_indicators` contains a domain or URL that is not
a public provider and appears in target-owned repository content.

Action:

1. Normalize the domain, strip credentials and paths.
2. Add the domain and relate the repository to it with `MENTIONS`.
3. Run infrastructure mode only if the domain is in scope or clearly owned by
   the target.
4. If ownership is uncertain, record it as an unverified lead and do not scan.

Reason: configuration files frequently reference internal or legacy domains.

### Trigger: Cloud Bucket Or Storage Host

Condition: document metadata or repository content contains a storage endpoint
that includes the target brand.

Action:

1. Record the endpoint as an `ARTIFACT`.
2. Do not enumerate bucket contents.
3. Do not attempt access control testing.
4. Note the exposure in the report for owner validation.

Reason: bucket enumeration can cross into unauthorized data access.

### Trigger: Social Profile Link

Condition: a verified social profile links to a personal or corporate domain.

Action:

1. Prefer corporate domains.
2. Run infrastructure mode only on domains confirmed to belong to the target.
3. Personal domains require explicit scope approval.

Reason: profile links are user-controlled and can point anywhere.

## Exclusions

Never pivot to or scan:

- Search engines, CDNs, public DNS resolvers, and certificate authorities.
- Package registries and code hosting platforms unless the target owns a
  dedicated organization namespace and the scope allows it.
- Government, healthcare, or financial third parties.
- Personal email providers, personal cloud drives, or private social accounts.
- Any host whose ownership cannot be tied to the target or an authorized
  related entity.

Generic domains blocked by the engine include `github.com`,
`githubusercontent.com`, `gitlab.com`, `linkedin.com`, `stackoverflow.com`,
`reddit.com`, `medium.com`, `google.com`, `cloudflare.com`,
`amazonaws.com`, `azure.com`, `npmjs.com`, `pypi.org`, `docker.com`, and
similar providers.

## Prioritization Matrix

Score each candidate from 0 to 3 on each dimension:

| Dimension | 0 | 1 | 2 | 3 |
| --- | --- | --- | --- | --- |
| Ownership confidence | Unknown | Brand match only | Certificate or WHOIS link | Direct registrant or first-party code |
| Exposure value | No service | Generic web | Admin or API surface | Remote access, CI/CD, or data store |
| Evidence independence | Single weak signal | Single strong signal | Two related signals | Multiple independent sources |
| Scope clarity | Out of scope | Ambiguous | In scope by domain | Explicitly listed in scope |

Pivot when the total is at least 7. Record the score in the graph metadata for
auditability.

## Pivot Logging Template

```text
rec_graph_add_relation(
  source_id="<source entity id>",
  source_type="<valid type>",
  relation="PIVOTED_TO",
  target_id="<target entity id>",
  target_type="<valid type>",
  metadata="score=<n>; evidence=<short ascii summary>; authorized=<yes/no>"
)
```

The metadata string must remain ASCII and must not contain secrets or full
personal contact details.

## Stop Conditions

Stop pivoting and report when:

- Two hops have been completed without a new strong signal.
- The next candidate is outside the authorized scope.
- Evidence requires accessing private or authenticated content.
- A live secret or personal data exposure is found; escalate to the engagement
  owner before continuing.
- Platform rate limits or blocks prevent reliable attribution.
