"""Local-only metadata extraction and graph updates for authorized technical documents."""
from __future__ import annotations

import ipaddress
import json
import re
import tempfile
from pathlib import Path

try:
    from . import backup_vault
except ImportError:
    import backup_vault

ROOT = Path(__file__).resolve().parent
VAULT = ROOT / "Vault"
TARGETS_DIR = VAULT / "OSINT_Targets"
GRAPH_PATH = VAULT / "graph_state.json"
INDEX_PATH = VAULT / "Targets_Index.md"
MAX_SOURCE_BYTES = 5 * 1024 * 1024

EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(?![\w-]|\.[A-Za-z0-9])")
IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
TAG_RE = re.compile(r"(?<!\w)#([A-Za-z][A-Za-z0-9_-]{0,63})")
WIKI_RE = re.compile(r"\[\[([^\]\n|#]{1,180})(?:[|#][^\]\n]*)?\]\]")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
HASH_RE = re.compile(r"(?<![A-Fa-f0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40})(?![A-Fa-f0-9])")
DOMAIN_RE = re.compile(r"(?<![@\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63})(?![\w-]|\.[A-Za-z0-9])")


def _authorized_source(file_path: str | Path) -> Path:
    path = Path(file_path)
    if not path.is_absolute():
        path = TARGETS_DIR / path
    resolved = path.resolve(strict=True)
    root = TARGETS_DIR.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PermissionError(f"source is outside authorized target documents: {resolved}") from exc
    if resolved.suffix.casefold() not in {".md", ".txt"}:
        raise ValueError("only Markdown and text reference documents are accepted")
    if not resolved.is_file() or resolved.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("source must be a regular file no larger than 5 MiB")
    return resolved


def _unique(values):
    return sorted(set(values), key=str.casefold)


def parse_target_metadata(file_path: str | Path) -> dict:
    """Extract local document and technical indicators; never creates person records."""
    path = _authorized_source(file_path)
    text = path.read_text(encoding="utf-8", errors="replace")
    id_match = re.search(r"(?m)^\s*(?:id|document_id)\s*:\s*['\"]?([A-Za-z0-9._:-]{1,120})", text[:12000])
    document_id = id_match.group(1).strip("'\"") if id_match else path.stem
    ips = []
    for candidate in IP_RE.findall(text):
        try:
            ips.append(str(ipaddress.IPv4Address(candidate)))
        except ipaddress.AddressValueError:
            continue
    emails = _unique(EMAIL_RE.findall(text))
    email_domains = {email.rsplit("@", 1)[-1].casefold() for email in emails}
    domains = []
    for candidate in DOMAIN_RE.findall(text):
        candidate = candidate.rstrip(".").lower()
        if candidate.casefold() not in email_domains:
            domains.append(candidate)
    technical = _unique(
        [value.upper() for value in CVE_RE.findall(text)]
        + [value.lower() for value in HASH_RE.findall(text)]
        + domains
    )
    return {
        "id": document_id,
        "path": path.relative_to(TARGETS_DIR.resolve()).as_posix(),
        "hashtags": _unique(TAG_RE.findall(text)),
        "ip_indicators": _unique(ips),
        "email_indicators": emails,
        "wiki_links": _unique(x.strip() for x in WIKI_RE.findall(text) if x.strip()),
        "technical_indicators": technical,
    }


def _doc_node_id(document_id: str) -> str:
    return "doc:" + document_id


def _target_node_id(kind: str, value: str) -> str:
    return f"{kind}:{value.casefold()}"


def _atomic_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent,
                                     prefix=f".{path.name}.", suffix=".tmp", delete=False) as temp:
        temp.write(text)
        temp.flush()
        temp_name = temp.name
    try:
        Path(temp_name).replace(path)
    except Exception:
        Path(temp_name).unlink(missing_ok=True)
        raise


def _write_targets_index(graph: dict) -> None:
    docs = sorted((node for node in graph["nodes"] if node.get("type") == "document" and node.get("metadata")),
                  key=lambda node: node["id"].casefold())
    lines = ["# Authorized Technical Target Index", "",
             "Generated from local files in Vault/OSINT_Targets. Email indicators remain local metadata; no person nodes are created.", ""]
    if not docs:
        lines.extend(["No target documents indexed.", ""])
    for node in docs:
        meta = node.get("metadata") or {}
        lines.append(f"## {meta.get('id', node['id'])}")
        lines.append(f"- File: {meta.get('path', '')}")
        for field, label in (("hashtags", "Tags"), ("ip_indicators", "IPv4"),
                             ("email_indicators", "Email indicators"),
                             ("wiki_links", "Document links"),
                             ("technical_indicators", "Technical indicators")):
            values = meta.get(field) or []
            if values:
                lines.append(f"- {label}: " + ", ".join(str(value) for value in values))
        lines.append("")
    _atomic_text(INDEX_PATH, "\n".join(lines))


def _process_identity_mutations(target_file_path: str | Path) -> dict:
    """Reindex one authorized technical document and remove its stale outgoing edges."""
    metadata = parse_target_metadata(target_file_path)
    graph = backup_vault.read_graph(GRAPH_PATH)
    document_node = _doc_node_id(metadata["id"])
    for node in graph["nodes"]:
        existing_path = (node.get("metadata") or {}).get("path")
        if node["id"] == document_node and existing_path and existing_path != metadata["path"]:
            raise ValueError("document identifier is already used by another source file")
    previous_ids = {node["id"] for node in graph["nodes"]
                    if node.get("type") == "document"
                    and (node.get("metadata") or {}).get("path") == metadata["path"]}
    previous_ids.add(document_node)
    old_related = {
        edge["target"] for edge in graph["links"]
        if edge.get("source") in previous_ids and edge.get("target") != document_node
    }
    links = [edge for edge in graph["links"] if edge.get("source") not in previous_ids]
    for edge in links:
        if edge["target"] in previous_ids:
            edge["target"] = document_node
    retained_edges = {(edge["source"], edge["target"]) for edge in links}
    used_nodes = {endpoint for edge in links for endpoint in (edge["source"], edge["target"])}
    managed_types = {"ipv4", "topic_tag", "technical_indicator"}
    nodes = []
    for node in graph["nodes"]:
        node_id = node["id"]
        if node_id in previous_ids:
            continue
        if node_id in old_related and node.get("type") in managed_types and node_id not in used_nodes:
            continue
        nodes.append(node)

    nodes.append({"id": document_node, "type": "document", "metadata": metadata})
    new_edges = []
    for tag in metadata["hashtags"]:
        new_edges.append(("topic_tag:" + tag.casefold(), "topic_tag", tag))
    for ip in metadata["ip_indicators"]:
        new_edges.append((_target_node_id("ipv4", ip), "ipv4", ip))
    for indicator in metadata["technical_indicators"]:
        new_edges.append((_target_node_id("technical_indicator", indicator), "technical_indicator", indicator))
    for target_name in metadata["wiki_links"]:
        new_edges.append((_doc_node_id(target_name), "document", target_name))
    node_ids = {node["id"] for node in nodes}
    for target_id, node_type, label in new_edges:
        if target_id not in node_ids:
            nodes.append({"id": target_id, "type": node_type, "label": label})
            node_ids.add(target_id)
        pair = (document_node, target_id)
        if pair not in retained_edges:
            links.append({"source": pair[0], "target": pair[1]})
            retained_edges.add(pair)

    nodes_by_id = {node["id"]: node for node in nodes}
    nodes = [nodes_by_id[key] for key in sorted(nodes_by_id, key=str.casefold)]
    links_by_pair = {(edge["source"], edge["target"]): edge for edge in links}
    updated = {"nodes": nodes, "links": [links_by_pair[key] for key in sorted(links_by_pair)]}
    backup_vault.validate_graph(updated)
    changed = updated != graph
    if changed:
        backup_vault.execute_pre_mutation_backup(GRAPH_PATH, VAULT / "Backups")
        backup_vault.atomic_write_graph(updated, GRAPH_PATH)
        backup_vault.enforce_retention_rotation(VAULT / "Backups")
    _write_targets_index(updated)
    return {"document": metadata, "graph": updated, "changed": changed}


def reindex_all() -> list[dict]:
    results = []
    for path in sorted(TARGETS_DIR.rglob("*")):
        if path.is_file() and path.suffix.casefold() in {".md", ".txt"}:
            results.append(process_identity_mutations(path))
    return results


def process_identity_mutations(target_file_path: str | Path) -> dict:
    with backup_vault.graph_transaction(GRAPH_PATH):
        return _process_identity_mutations(target_file_path)
