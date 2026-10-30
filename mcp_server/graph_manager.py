"""SQLite-backed entity relationship graph and report renderers."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from rec_cli.modules import extract_host, is_domain_like
from rec_cli.utils.logger import ascii_text

VALID_NODE_TYPES = {
    "ORG",
    "ASN",
    "DOMAIN",
    "IP",
    "PORT",
    "TECH",
    "VULN",
    "ARTIFACT",
    "PERSON",
    "SOCIAL_ACCOUNT",
    "REPO",
}
_HIGH_VALUE_TYPES = {"VULN", "PERSON", "SOCIAL_ACCOUNT", "REPO"}
_PIVOT_TYPES = {
    "PERSON",
    "SOCIAL_ACCOUNT",
    "REPO",
    "TECH",
    "VULN",
    "DOMAIN",
    "ARTIFACT",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _slug(value: str, limit: int = 160) -> str:
    cleaned = ascii_text(value).lower()
    cleaned = re.sub(r"[^a-z0-9._@:/\\-]+", "-", cleaned).strip("-")
    return (cleaned or "unknown")[:limit]


def _normalize_type(value: str) -> str:
    node_type = ascii_text(value).upper().strip().replace(" ", "_").replace("-", "_")
    if node_type not in VALID_NODE_TYPES:
        raise ValueError(
            f"invalid node type: {value}. Valid types: "
            + ", ".join(sorted(VALID_NODE_TYPES))
        )
    return node_type


def _normalize_relation(value: str) -> str:
    relation = re.sub(r"[^A-Za-z0-9_]+", "_", ascii_text(value).upper())
    relation = relation.strip("_")[:80]
    return relation or "RELATED_TO"


def _json_safe(value: Any) -> Any:
    if isinstance(value, str):
        return ascii_text(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {ascii_text(key): _json_safe(item) for key, item in value.items()}
    return ascii_text(value)


def _short_hash(value: str, length: int = 16) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


class GraphManager:
    """Entity graph persisted in SQLite with deterministic exports."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = str(db_path) if db_path else ":memory:"
        if self.db_path != ":memory:":
            path = Path(self.db_path)
            path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(
            self.db_path, check_same_thread=False
        )
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys = ON")
            if self.db_path != ":memory:":
                self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS nodes (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    label TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS edges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_id TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    created_at TEXT NOT NULL,
                    UNIQUE(source_id, relation, target_id)
                );
                CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_id);
                CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_id);
                CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
                """
            )
            self._connection.commit()

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _metadata_dict(self, raw: str) -> dict[str, Any]:
        try:
            value = json.loads(raw or "{}")
        except ValueError:
            return {}
        return value if isinstance(value, dict) else {}

    def _node_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "type": row["type"],
            "label": row["label"],
            "metadata": self._metadata_dict(row["metadata"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def _edge_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "source_id": row["source_id"],
            "relation": row["relation"],
            "target_id": row["target_id"],
            "metadata": self._metadata_dict(row["metadata"]),
            "created_at": row["created_at"],
        }

    def add_node(
        self,
        entity_id: str,
        node_type: str,
        label: str | None = None,
        metadata: dict[str, Any] | None = None,
        high_value: bool = False,
    ) -> dict[str, Any]:
        node_id = ascii_text(entity_id).strip()[:1000]
        if not node_id:
            raise ValueError("entity_id must not be empty")
        node_type = _normalize_type(node_type)
        node_label = ascii_text(label or entity_id).strip()[:500] or node_id
        payload = _json_safe(metadata or {})
        if not isinstance(payload, dict):
            payload = {"value": payload}
        if high_value:
            payload["high_value"] = True
        now = _now()

        with self._lock:
            existing = self._connection.execute(
                "SELECT * FROM nodes WHERE id = ?", (node_id,)
            ).fetchone()
            if existing:
                merged = self._metadata_dict(existing["metadata"])
                merged.update(payload)
                self._connection.execute(
                    "UPDATE nodes SET label = ?, metadata = ?, updated_at = ? WHERE id = ?",
                    (
                        node_label or existing["label"],
                        json.dumps(_json_safe(merged), ensure_ascii=True, sort_keys=True),
                        now,
                        node_id,
                    ),
                )
                created = False
                effective_type = existing["type"]
            else:
                self._connection.execute(
                    "INSERT INTO nodes (id, type, label, metadata, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        node_id,
                        node_type,
                        node_label,
                        json.dumps(payload, ensure_ascii=True, sort_keys=True),
                        now,
                        now,
                    ),
                )
                created = True
                effective_type = node_type
            self._connection.commit()
            row = self._connection.execute(
                "SELECT * FROM nodes WHERE id = ?", (node_id,)
            ).fetchone()
        result = self._node_dict(row)
        result["created"] = created
        result["type"] = effective_type
        return result

    def add_relation(
        self,
        source_id: str,
        source_type: str,
        relation: str,
        target_id: str,
        target_type: str,
        metadata: str = "",
    ) -> dict[str, Any]:
        self.add_node(source_id, source_type)
        self.add_node(target_id, target_type)
        source = ascii_text(source_id).strip()[:1000]
        target = ascii_text(target_id).strip()[:1000]
        relationship = _normalize_relation(relation)
        edge_metadata = {"note": ascii_text(metadata)} if metadata else {}
        now = _now()
        with self._lock:
            existing = self._connection.execute(
                "SELECT id FROM edges WHERE source_id = ? AND relation = ? AND target_id = ?",
                (source, relationship, target),
            ).fetchone()
            if existing:
                if edge_metadata:
                    self._connection.execute(
                        "UPDATE edges SET metadata = ? WHERE id = ?",
                        (
                            json.dumps(
                                _json_safe(edge_metadata),
                                ensure_ascii=True,
                                sort_keys=True,
                            ),
                            existing["id"],
                        ),
                    )
                    self._connection.commit()
                edge_id = int(existing["id"])
                created = False
            else:
                cursor = self._connection.execute(
                    "INSERT INTO edges "
                    "(source_id, relation, target_id, metadata, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        source,
                        relationship,
                        target,
                        json.dumps(
                            _json_safe(edge_metadata),
                            ensure_ascii=True,
                            sort_keys=True,
                        ),
                        now,
                    ),
                )
                self._connection.commit()
                edge_id = int(cursor.lastrowid)
                created = True
        return {
            "edge_id": edge_id,
            "source_id": source,
            "relation": relationship,
            "target_id": target,
            "created": created,
        }

    def node_count(self) -> int:
        with self._lock:
            return int(
                self._connection.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
            )

    def edge_count(self) -> int:
        with self._lock:
            return int(
                self._connection.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
            )

    def _all_nodes(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM nodes ORDER BY type, id"
            ).fetchall()
        return [self._node_dict(row) for row in rows]

    def _all_edges(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM edges ORDER BY id"
            ).fetchall()
        return [self._edge_dict(row) for row in rows]

    def _outgoing(self, entity_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM edges WHERE source_id = ? ORDER BY id",
                (entity_id,),
            ).fetchall()
        return [self._edge_dict(row) for row in rows]

    def _has_outgoing(self, entity_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM edges WHERE source_id = ? LIMIT 1", (entity_id,)
            ).fetchone()
        return row is not None

    def _type_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT type, COUNT(*) AS count FROM nodes GROUP BY type ORDER BY type"
            ).fetchall()
        return {row["type"]: int(row["count"]) for row in rows}

    @staticmethod
    def _is_high_value(node: dict[str, Any]) -> bool:
        if node["type"] in _HIGH_VALUE_TYPES:
            return True
        return bool(node["metadata"].get("high_value"))

    @staticmethod
    def _pivot_reason(node: dict[str, Any]) -> str:
        node_type = node["type"]
        metadata = node["metadata"]
        if node_type == "PERSON":
            return "Run identity, social profile, and public repository enumeration."
        if node_type == "SOCIAL_ACCOUNT":
            return "Inspect the profile for employer, domains, repository links, and contact data."
        if node_type == "REPO":
            return "Review commit history and configuration files for leaked infrastructure."
        if node_type == "TECH":
            return "Map the identified product and version to passive CVE data."
        if node_type == "VULN":
            return "Validate exposure and prioritize remediation."
        if node_type == "DOMAIN":
            return "Run infrastructure enumeration against this newly discovered domain."
        if metadata.get("kind") == "email":
            return "Pivot this email into OSINT identity and social profile research."
        if metadata.get("kind") in ("indicator", "path", "username"):
            return "Review this artifact for additional domains, identities, or credentials."
        return "Inspect this artifact for additional reconnaissance targets."

    def _high_value_targets(
        self, nodes: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        targets: list[dict[str, Any]] = []
        for node in nodes:
            if not self._is_high_value(node):
                continue
            entry = dict(node)
            if node["type"] == "VULN":
                try:
                    entry["cvss"] = float(node["metadata"].get("cvss", 0.0))
                except (TypeError, ValueError):
                    entry["cvss"] = 0.0
            targets.append(entry)
        targets.sort(
            key=lambda item: (
                -float(item.get("cvss", 0.0)),
                {
                    "VULN": 0,
                    "PERSON": 1,
                    "SOCIAL_ACCOUNT": 2,
                    "REPO": 3,
                }.get(item["type"], 4),
                item["id"],
            )
        )
        return targets[:100]

    def _unexplored_pivots(
        self, nodes: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        pivots: list[dict[str, Any]] = []
        for node in nodes:
            if node["type"] not in _PIVOT_TYPES:
                continue
            if self._has_outgoing(node["id"]):
                continue
            metadata = node["metadata"]
            if node["type"] == "ARTIFACT" and metadata.get("kind") not in (
                "email",
                "indicator",
                "path",
                "username",
            ):
                continue
            pivots.append(
                {
                    "id": node["id"],
                    "type": node["type"],
                    "label": node["label"],
                    "suggested_action": self._pivot_reason(node),
                }
            )
        return pivots[:100]

    def query(self, entity_id: str = "all") -> dict[str, Any]:
        if not entity_id or entity_id.lower() == "all":
            nodes = self._all_nodes()
            edges = self._all_edges()
            return {
                "scope": "all",
                "node_count": len(nodes),
                "edge_count": len(edges),
                "type_counts": self._type_counts(),
                "nodes": nodes,
                "edges": edges,
                "high_value_targets": self._high_value_targets(nodes),
                "unexplored_pivot_points": self._unexplored_pivots(nodes),
            }

        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM nodes WHERE id = ?", (entity_id,)
            ).fetchone()
            incoming_rows = self._connection.execute(
                "SELECT * FROM edges WHERE target_id = ? ORDER BY id",
                (entity_id,),
            ).fetchall()
            outgoing_rows = self._connection.execute(
                "SELECT * FROM edges WHERE source_id = ? ORDER BY id",
                (entity_id,),
            ).fetchall()
        if row is None:
            return {"scope": entity_id, "found": False}
        node = self._node_dict(row)
        return {
            "scope": entity_id,
            "found": True,
            "entity": node,
            "high_value": self._is_high_value(node),
            "unexplored": not self._has_outgoing(entity_id),
            "incoming": [
                self._edge_dict(edge) for edge in incoming_rows
            ],
            "outgoing": [
                self._edge_dict(edge) for edge in outgoing_rows
            ],
        }

    def export_data(self) -> dict[str, Any]:
        nodes = self._all_nodes()
        edges = self._all_edges()
        return {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "type_counts": self._type_counts(),
            "nodes": nodes,
            "edges": edges,
            "high_value_targets": self._high_value_targets(nodes),
            "unexplored_pivot_points": self._unexplored_pivots(nodes),
        }

    def _graph_snapshot(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        return self._all_nodes(), self._all_edges()

    def mermaid_graph(self) -> str:
        nodes, edges = self._graph_snapshot()
        if not nodes:
            return 'graph LR\n  empty["No entities discovered"]'
        aliases = {node["id"]: f"n{index}" for index, node in enumerate(nodes)}
        lines = ["graph LR"]
        for node in nodes:
            label = ascii_text(
                f"{node['type']} {node['label']}", 220
            ).replace('"', "'")
            lines.append(f'  {aliases[node["id"]]}["{label}"]')
        for edge in edges:
            source = aliases.get(edge["source_id"])
            target = aliases.get(edge["target_id"])
            if not source or not target:
                continue
            relation = re.sub(r"[^A-Za-z0-9_]", "_", edge["relation"])
            lines.append(f"  {source} -->|{relation}| {target}")
        return "\n".join(lines)

    def ascii_tree(self, max_nodes: int = 800) -> str:
        nodes, edges = self._graph_snapshot()
        if not nodes:
            return "No entities discovered."
        node_map = {node["id"]: node for node in nodes}
        outgoing: dict[str, list[dict[str, Any]]] = {}
        incoming: dict[str, int] = {}
        for edge in edges:
            outgoing.setdefault(edge["source_id"], []).append(edge)
            incoming[edge["target_id"]] = incoming.get(edge["target_id"], 0) + 1

        roots = [node["id"] for node in nodes if incoming.get(node["id"], 0) == 0]
        if not roots:
            roots = [nodes[0]["id"]]
        rendered: set[str] = set()
        lines: list[str] = []

        def label(node_id: str) -> str:
            node = node_map.get(node_id)
            if not node:
                return node_id
            return f"[{node['type']}] {node['label']}"

        def walk(node_id: str, prefix: str, depth: int, trail: set[str]) -> None:
            if len(rendered) >= max_nodes or depth > 12:
                return
            rendered.add(node_id)
            children = outgoing.get(node_id, [])
            for index, edge in enumerate(children):
                child_id = edge["target_id"]
                if child_id in trail:
                    lines.append(
                        f"{prefix}|-- {edge['relation']} -> {label(child_id)} (cycle)"
                    )
                    continue
                last = index == len(children) - 1
                branch = "`-- " if last else "|-- "
                suffix = " (see above)" if child_id in rendered else ""
                lines.append(
                    f"{prefix}{branch}{edge['relation']} -> {label(child_id)}{suffix}"
                )
                if child_id not in rendered:
                    next_prefix = prefix + ("    " if last else "|   ")
                    walk(child_id, next_prefix, depth + 1, trail | {child_id})

        for root in roots:
            if len(rendered) >= max_nodes:
                break
            if root in rendered:
                continue
            lines.append(label(root))
            walk(root, "", 0, {root})

        for node in nodes:
            if len(rendered) >= max_nodes:
                break
            if node["id"] in rendered:
                continue
            lines.append("")
            lines.append(label(node["id"]))
            walk(node["id"], "", 0, {node["id"]})
        if len(rendered) >= max_nodes and len(rendered) < len(nodes):
            lines.append("")
            lines.append(f"[truncated: rendered {max_nodes} of {len(nodes)} nodes]")
        return "\n".join(lines)

    def ingest_recon(self, result: dict[str, Any]) -> dict[str, int]:
        before_nodes = self.node_count()
        before_edges = self.edge_count()
        meta = result.get("meta", {})
        mode = str(meta.get("mode", "infra")).lower()
        if mode == "osint":
            self._ingest_osint(result)
        else:
            self._ingest_infra(result)
        return {
            "nodes_added": self.node_count() - before_nodes,
            "edges_added": self.edge_count() - before_edges,
            "total_nodes": self.node_count(),
            "total_edges": self.edge_count(),
        }

    def _edge(
        self,
        source_id: str,
        source_type: str,
        relation: str,
        target_id: str,
        target_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self.add_node(source_id, source_type)
        self.add_node(target_id, target_type, metadata=metadata)
        self.add_relation(
            source_id,
            source_type,
            relation,
            target_id,
            target_type,
            metadata=json.dumps(_json_safe(metadata or {}), ensure_ascii=True)
            if metadata
            else "",
        )

    def _target_node(self, target: str) -> tuple[str, str]:
        host = extract_host(target)
        try:
            ipaddress.ip_address(host)
            return host, "IP"
        except ValueError:
            return host, "DOMAIN"

    def _ingest_infra(self, result: dict[str, Any]) -> None:
        meta = result.get("meta", {})
        target = str(meta.get("target", ""))
        target_id, target_type = self._target_node(target)
        if target_id:
            self.add_node(target_id, target_type, metadata={"target": True})
        infra = result.get("infra_data", {})
        whois = infra.get("whois_asn", {})

        registrar = str(whois.get("registrar", "") or "")
        if registrar and target_id:
            org_id = f"org:{_slug(registrar)}"
            self._edge(
                target_id, target_type, "REGISTERED_WITH", org_id, "ORG",
                {"role": "registrar"},
            )
        registrant_org = str(whois.get("registrant_org", "") or "")
        if registrant_org and target_id:
            org_id = f"org:{_slug(registrant_org)}"
            self._edge(
                target_id, target_type, "REGISTERED_BY", org_id, "ORG",
                {"role": "registrant"},
            )
        for email in whois.get("registrant_emails", []):
            if not email:
                continue
            email_id = f"email:{email.lower()}"
            self._edge(
                target_id, target_type, "MENTIONS_EMAIL", email_id, "ARTIFACT",
                {"kind": "email", "value": email},
            )
        for asn in whois.get("asns", []):
            asn_id = str(asn.get("asn", "") or "")
            if not asn_id:
                continue
            self._edge(
                target_id, target_type, "USES_ASN", asn_id, "ASN",
                {"description": asn.get("description", "")},
            )
            for cidr in asn.get("cidr", []):
                if cidr:
                    self._edge(
                        asn_id, "ASN", "ANNOUNCES", f"cidr:{cidr}", "ARTIFACT",
                        {"kind": "cidr", "value": cidr},
                    )

        for host in infra.get("hosts", []):
            hostname = str(host.get("hostname", "") or "")
            ip = str(host.get("ip", "") or "")
            if not hostname:
                continue
            try:
                ipaddress.ip_address(hostname)
                host_type = "IP"
            except ValueError:
                host_type = "DOMAIN"
            host_node = self.add_node(
                hostname,
                host_type,
                metadata={"target": hostname == target_id},
            )
            del host_node
            if target_id and hostname != target_id and target_type == "DOMAIN":
                self._edge(
                    target_id, target_type, "HAS_HOST", hostname, host_type
                )
            if ip:
                self._edge(
                    hostname, host_type, "RESOLVES_TO", ip, "IP",
                    {"cdn_waf": host.get("cdn_waf")},
                )
                for port in host.get("open_ports", []):
                    self._edge(
                        ip, "IP", "EXPOSES", f"{ip}:{int(port)}", "PORT",
                        {"port": int(port), "protocol": "tcp"},
                    )
            cdn = host.get("cdn_waf")
            waf_name = str((host.get("waf") or {}).get("name") or "")
            for label, role in ((cdn, "cdn_waf"), (waf_name, "waf")):
                if not label or (role == "waf" and label == cdn):
                    continue
                self._edge(
                    hostname, host_type, "PROTECTED_BY",
                    f"tech:{_slug(label)}", "TECH", {"role": role},
                )

            http_info = host.get("http_info", {}) or {}
            for tech in http_info.get("technologies", []):
                name = str(tech.get("name", "") or "")
                version = tech.get("version")
                if not name:
                    continue
                tech_id = f"tech:{_slug(name)}"
                if version:
                    tech_id += f"@{_slug(str(version), 40)}"
                self._edge(
                    hostname, host_type, "RUNS_TECH", tech_id, "TECH",
                    {"name": name, "version": version},
                )
            for cn in http_info.get("tls_cn", []):
                cn_value = str(cn or "").replace("*.", "").strip().lower()
                if cn_value and is_domain_like(cn_value):
                    self._edge(
                        hostname, host_type, "CERTIFICATE_CN", cn_value, "DOMAIN",
                    )

            js = host.get("js_findings", {}) or {}
            for identity in js.get("discovered_emails_or_authors", [])[:30]:
                text = str(identity or "")
                if "@" in text:
                    self._edge(
                        hostname, host_type, "MENTIONS_EMAIL",
                        f"email:{text.lower()}", "ARTIFACT",
                        {"kind": "email", "value": text},
                    )
                elif text:
                    self._edge(
                        hostname, host_type, "MENTIONS_PERSON",
                        f"person:{_slug(text)}", "PERSON", {"name": text},
                    )
            for endpoint in js.get("extracted_endpoints", [])[:40]:
                text = str(endpoint or "")
                if not text:
                    continue
                endpoint_id = f"endpoint:{_short_hash(text)}"
                self._edge(
                    hostname, host_type, "EXPOSES_ENDPOINT",
                    endpoint_id, "ARTIFACT",
                    {"kind": "endpoint", "value": text[:500]},
                )
            for secret in js.get("potential_secrets", [])[:25]:
                secret_type = str(secret.get("type", "secret") or "secret")
                source_url = str(secret.get("source_url", "") or "")
                secret_id = f"secret:{_short_hash(secret_type + source_url)}"
                self._edge(
                    hostname, host_type, "LEAKS_SECRET", secret_id, "ARTIFACT",
                    {"kind": "secret", "secret_type": secret_type, "source_url": source_url},
                )
            for vulnerability in host.get("potential_vulnerabilities", []):
                cve_id = str(vulnerability.get("cve_id", "") or "")
                if not cve_id:
                    continue
                try:
                    cvss = float(vulnerability.get("cvss", 0.0) or 0.0)
                except (TypeError, ValueError):
                    cvss = 0.0
                self._edge(
                    hostname, host_type, "HAS_VULN", cve_id, "VULN",
                    {
                        "cvss": cvss,
                        "component": vulnerability.get("affected_Component", ""),
                        "summary": vulnerability.get("summary", ""),
                        "high_value": cvss >= 7.0,
                    },
                )
            for finding in host.get("path_findings", [])[:80]:
                path = str(finding.get("path", "") or "")
                if not path:
                    continue
                url = str(finding.get("url", "") or "")
                category = str(finding.get("category", "") or "discovered")
                sensitive = bool(finding.get("sensitive"))
                path_id = f"path:{_short_hash(url or path)}"
                self._edge(
                    hostname, host_type, "EXPOSES_PATH", path_id, "ARTIFACT",
                    {
                        "kind": "path",
                        "path": path[:500],
                        "url": url[:500],
                        "status_code": finding.get("status_code", 0),
                        "category": category,
                        "sensitive": sensitive,
                        "high_value": sensitive,
                    },
                )
            for asset in host.get("assets", [])[:120]:
                url = str(asset.get("url", "") or "")
                if not url:
                    continue
                asset_kind = str(asset.get("kind", "") or "html")
                asset_id = f"asset:{_short_hash(url)}"
                self._edge(
                    hostname, host_type, "EXPOSES_ASSET", asset_id, "ARTIFACT",
                    {
                        "kind": "asset",
                        "asset_kind": asset_kind,
                        "url": url[:500],
                        "source_url": str(asset.get("source_url", "") or "")[:500],
                    },
                )
            for vhost in host.get("vhosts", [])[:100]:
                vhost_name = str(vhost.get("hostname", "") or "")
                if not vhost_name:
                    continue
                vhost_ip = str(vhost.get("ip", "") or ip)
                vhost_id = f"vhost:{_short_hash(vhost_ip + '|' + vhost_name)}"
                self._edge(
                    vhost_ip or hostname,
                    "IP" if vhost_ip else host_type,
                    "SERVES_VHOST",
                    vhost_id,
                    "ARTIFACT",
                    {
                        "kind": "vhost",
                        "hostname": vhost_name[:500],
                        "base_host": hostname,
                        "ip": vhost_ip[:200],
                        "status_code": vhost.get("status_code", 0),
                        "title": str(vhost.get("title", "") or "")[:300],
                    },
                )
            for archived in host.get("historical_urls", [])[:100]:
                original = str(archived.get("url", "") or "")
                wayback_url = str(archived.get("wayback_url", "") or "")
                if not original or not wayback_url:
                    continue
                archive_id = f"wayback:{_short_hash(wayback_url)}"
                self._edge(
                    hostname,
                    host_type,
                    "EXPOSES_ARCHIVED_URL",
                    archive_id,
                    "ARTIFACT",
                    {
                        "kind": "wayback",
                        "url": original[:500],
                        "wayback_url": wayback_url[:500],
                        "timestamp": str(archived.get("timestamp", "") or "")[:20],
                        "status_code": archived.get("status_code", 0),
                        "mime_type": str(archived.get("mime_type", "") or "")[:100],
                    },
                )

    def _ingest_osint(self, result: dict[str, Any]) -> None:
        meta = result.get("meta", {})
        target = str(meta.get("target", ""))
        osint = result.get("osint_data", {})
        identity = osint.get("target_identity", {}) or {}
        name = str(identity.get("name", "") or "").strip()
        usernames = [str(value) for value in identity.get("usernames", []) if value]
        person_label = name or (usernames[0] if usernames else target)
        person_id = f"person:{_slug(person_label)}"
        self.add_node(
            person_id,
            "PERSON",
            label=person_label,
            metadata={
                "name": name,
                "usernames": usernames,
                "target": target,
                "high_value": True,
            },
            high_value=True,
        )
        organization = identity.get("organization")
        if organization:
            org_id = f"org:{_slug(str(organization))}"
            self._edge(
                person_id, "PERSON", "AFFILIATED_WITH", org_id, "ORG",
                {"inferred": True},
            )
        for email in identity.get("emails", []):
            if not email:
                continue
            self._edge(
                person_id, "PERSON", "OWNS_EMAIL", f"email:{str(email).lower()}",
                "ARTIFACT", {"kind": "email", "value": email},
            )
        breach = osint.get("breach", {}) or {}
        breach_findings = breach.get("findings") if isinstance(breach, dict) else None
        if not isinstance(breach_findings, list):
            breach_findings = []
        for finding in breach_findings[:100]:
            if not isinstance(finding, dict):
                continue
            identifier = str(finding.get("identifier", "") or "").strip()
            breach_name = str(finding.get("breach", "") or "").strip()
            provider = str(finding.get("provider", "") or "").strip()
            if not identifier or not breach_name:
                continue
            exposure_id = (
                f"breach:{_short_hash(provider + '|' + breach_name + '|' + identifier)}"
            )
            if "@" in identifier:
                source_id, source_type = f"email:{identifier.lower()}", "ARTIFACT"
            else:
                source_id, source_type = person_id, "PERSON"
            classes = finding.get("data_classes")
            if not isinstance(classes, list):
                classes = []
            self._edge(
                source_id, source_type, "EXPOSED_IN_BREACH", exposure_id,
                "ARTIFACT",
                {
                    "kind": "breach",
                    "identifier": identifier[:200],
                    "provider": provider[:100],
                    "breach": breach_name[:200],
                    "date": str(finding.get("breach_date", "") or "")[:20],
                    "data_classes": [str(value)[:80] for value in classes[:20]],
                    "verified": bool(finding.get("verified", False)),
                },
            )
        for username in usernames:
            self._edge(
                person_id, "PERSON", "HAS_ALIAS",
                f"username:{_slug(username)}", "ARTIFACT",
                {"kind": "username", "value": username},
            )
        for profile in osint.get("social_profiles", []):
            url = str(profile.get("url", "") or "")
            if not url:
                continue
            self._edge(
                person_id, "PERSON", "HAS_ACCOUNT", url, "SOCIAL_ACCOUNT",
                {
                    "platform": profile.get("platform", ""),
                    "bio_or_notes": profile.get("bio_or_notes", ""),
                    "high_value": True,
                },
            )
        for finding in osint.get("git_findings", []):
            repo_url = str(finding.get("repo_url", "") or "")
            if not repo_url:
                continue
            self._edge(
                person_id, "PERSON", "OWNS_REPO", repo_url, "REPO",
                {"high_value": True},
            )
            for email in finding.get("commit_emails", []):
                if email:
                    self._edge(
                        repo_url, "REPO", "HAS_CONTRIBUTOR_EMAIL",
                        f"email:{str(email).lower()}", "ARTIFACT",
                        {"kind": "email", "value": email},
                    )
            for indicator in finding.get("leaked_indicators", [])[:30]:
                text = str(indicator or "")
                if not text:
                    continue
                self._edge(
                    repo_url, "REPO", "LEAKS_INDICATOR",
                    f"indicator:{_short_hash(text)}", "ARTIFACT",
                    {"kind": "indicator", "value": text[:500]},
                )
        for document in osint.get("document_metadata", []):
            url = str(document.get("file_url", "") or "")
            if not url:
                continue
            doc_id = f"document:{_short_hash(url)}"
            self._edge(
                person_id, "PERSON", "LINKED_DOCUMENT", doc_id, "ARTIFACT",
                {
                    "kind": "document",
                    "url": url,
                    "author": document.get("author", ""),
                    "creator_tool": document.get("creator_tool", ""),
                },
            )
            author = str(document.get("author", "") or "").strip()
            if author:
                self._edge(
                    doc_id, "ARTIFACT", "AUTHORED_BY",
                    f"person:{_slug(author)}", "PERSON",
                    {"name": author},
                )
            for path in document.get("internal_paths", [])[:20]:
                if path:
                    self._edge(
                        doc_id, "ARTIFACT", "REFERENCES_PATH",
                        f"path:{_short_hash(str(path))}", "ARTIFACT",
                        {"kind": "path", "value": path},
                    )

    def report_counts(self) -> dict[str, int]:
        return {
            "nodes": self.node_count(),
            "edges": self.edge_count(),
            "vulnerabilities": len(
                [node for node in self._all_nodes() if node["type"] == "VULN"]
            ),
            "people": len(
                [node for node in self._all_nodes() if node["type"] == "PERSON"]
            ),
            "social_accounts": len(
                [
                    node
                    for node in self._all_nodes()
                    if node["type"] == "SOCIAL_ACCOUNT"
                ]
            ),
            "repositories": len(
                [node for node in self._all_nodes() if node["type"] == "REPO"]
            ),
        }


def iter_node_ids(nodes: Iterable[dict[str, Any]]) -> list[str]:
    return [str(node.get("id", "")) for node in nodes if node.get("id")]
