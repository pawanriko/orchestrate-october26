"""Deterministic deletion-audit engine — HackerRank Orchestrate October'26.

"Ghost Data Still Exists": for each deletion request, decide whether the
user's personal data is truly gone (COMPLETE), still present (INCOMPLETE),
or was never requested for deletion (NOT_APPLICABLE), and emit the ordered
remediation / verification steps required by the problem statement.

Design (derived from the 32 sample cases, not from the statement alone):

* Identity: a request email resolves to a user via the current identity
  snapshot, or via a historical value in the audit log. All identifiers
  (current + historical emails, phones, email hashes, user_id) are then
  used to link evidence records to the user. Names are deliberately NOT
  used for linkage (they collide across users).
* State at audit_at: every text evidence file (SQL snapshots, JSON
  exports/bundles, handover txt, readback/support logs) is parsed into
  dated observations (system, resource, category, state, identifiers).
  For each resource linked to the user, the latest observation at or
  before audit_at wins. Activity-stream results are claims, never state.
* Rules: deletion_rules.csv maps each data category to one treatment
  (DELETE / REDACT / ANONYMIZE / RETAIN, plus flow disable / restore
  block). A record whose state already satisfies its treatment only
  earns a verification step; a record that does not earns
  FINDING -> REMEDIATION -> VERIFICATION.
* Ordering: findings, remediation, verification; within a phase by the
  statement's operation order, then system_id, then resource_id.
* Evidence citation: findings (and COMPLETE-case verifications) cite the
  latest evidence file at or before audit_at that mentions the resource;
  if none mentions it, the latest file covering that system; proposed
  remediation and future verification steps cite "".
* Account linkage: the case's account record comes from an
  evidence-linked DELETE candidate first, then the unique
  DELETE_RECORD activity event within +/-2h of reported_at, then a
  >5x-margin nearest candidate, then any evidence-linked account.
  Shared-timestamp collisions are left unassigned rather than guessed.
* NOT_APPLICABLE: conservative. Either the request text carries an
  explicit keep/continue/download/change signal with NO deletion-intent
  wording, or the case's account appears in a CLASSIFY_REQUEST
  "non-deletion" activity event. Anything else is treated as a deletion
  request. Non-Latin-script non-deletion requests are a known gap.

Stdlib only. No LLM calls, no network. Usage:

    python -m src.engine --dataset dataset/ --requests dataset/deletion_requests.csv --output output.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # All dataset times are UTC; naive values (log timestamps without a
    # suffix) are treated as UTC so comparisons stay consistent.
    if parsed.tzinfo is None:
        from datetime import timezone
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def norm_email(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().lower()
    return value or None


def split_sql_values(body: str) -> list[str]:
    """Split one SQL VALUES(...) body on top-level commas, honouring
    single-quoted strings ('' is an escaped quote) and JSON braces."""
    out: list[str] = []
    depth = 0
    in_str = False
    cur: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if in_str:
            if ch == "'":
                if i + 1 < len(body) and body[i + 1] == "'":
                    cur.append("'")
                    i += 2
                    continue
                in_str = False
                i += 1
                continue
            cur.append(ch)
            i += 1
            continue
        if ch == "'":
            in_str = True
            i += 1
            continue
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(ch)
        i += 1
    out.append("".join(cur).strip())
    return out


def sql_literal(token: str):
    token = token.strip()
    if token == "NULL":
        return None
    if token in ("0", "1") and token.isdigit():
        return int(token)
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------

# Canonical states
PRESENT = "PRESENT"
ABSENT = "ABSENT"
IDENTIFIABLE = "IDENTIFIABLE"
ANONYMIZED = "ANONYMIZED"
REDACTED = "REDACTED"
ACTIVE = "ACTIVE"
DISABLED = "DISABLED"
BLOCKED = "BLOCKED"

# Operation order within each phase (statement table order).
FINDING_ORDER = [
    "REPORT_REMAINING_RECORD",
    "REPORT_EXPOSED_PII",
    "REPORT_ACTIVE_DATA_FLOW",
    "REPORT_RESTORE_RISK",
]
REMEDIATION_ORDER = [
    "DISABLE_DATA_FLOW",
    "BLOCK_RESTORE",
    "DELETE_RECORD",
    "REDACT_RECORD",
    "ANONYMIZE_RECORD",
]
VERIFICATION_ORDER = [
    "VERIFY_RECORD_ABSENT",
    "VERIFY_RECORD_PRESENT",
    "VERIFY_RECORD_REDACTED",
    "VERIFY_RECORD_ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED",
    "VERIFY_RESTORE_BLOCKED",
]

# (table name, system, category) for flat SQL tables.
SQL_TABLES: dict[str, tuple[str, str]] = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_profiles_primary": ("account_service", "USER_PROFILE"),
    "customer_profiles_failover_replica": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "search_documents_primary": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_profiles": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_records": ("support_platform", "SUPPORT_MESSAGE"),
    "customer_exports": ("export_service", "USER_EXPORT"),
    "connector_subscriptions": ("integration_service", "DATA_FLOW"),
    "backup_restore_entries": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_records": ("security_service", "SECURITY_AUDIT_LOG"),
}

# collection name -> (system, category) for customer_data_* tables and JSON
# snapshot bundles.
COLLECTIONS: dict[str, tuple[str, str]] = {
    "customer_profiles": ("account_service", "USER_PROFILE"),
    "customer_search_documents": ("search_service", "SEARCH_INDEX_ENTRY"),
    "customer_analytics_reports": ("analytics_platform", "ANALYTICS_PROFILE"),
    "support_conversations": ("support_platform", "SUPPORT_MESSAGE"),
    "ticket_attachments": ("support_platform", "SUPPORT_ATTACHMENT"),
    "customer_export_jobs": ("export_service", "USER_EXPORT"),
    "connector_configurations": ("integration_service", "DATA_FLOW"),
    "backup_catalog": ("backup_service", "BACKUP_ARCHIVE"),
    "security_audit_events": ("security_service", "SECURITY_AUDIT_LOG"),
    "deleted_customer_references": ("identity_service", "ACCOUNT_TOMBSTONE"),
    "retained_order_records": ("legal_service", "LEGAL_HOLD_RECORD"),
}

# Rules from deletion_rules.csv (rule_id -> (category, condition, action)).
# Loaded from the file at runtime; this map is only the fallback.
RULE_ACTIONS: dict[str, str] = {
    "USER_PROFILE": "DELETE",
    "SECONDARY_IDENTIFIER": "DELETE",
    "SEARCH_INDEX_ENTRY": "DELETE",
    "CACHE_ENTRY": "DELETE",
    "SUPPORT_MESSAGE": "REDACT",
    "SUPPORT_ATTACHMENT": "DELETE",
    "ANALYTICS_PROFILE": "ANONYMIZE",
    "PRODUCT_TELEMETRY": "ANONYMIZE",
    "USER_EXPORT": "DELETE",
    "MARKETING_PROFILE": "DELETE",
    "EMAIL_DELIVERY_LOG": "REDACT",
    "SECURITY_AUDIT_LOG": "RETAIN",
    "LEGAL_HOLD_RECORD": "RETAIN",
    "BACKUP_ARCHIVE": "RETAIN_BLOCK",
    "ACCOUNT_TOMBSTONE": "REDACT",
    "DATA_FLOW": "DISABLE",
}

@dataclass
class Observation:
    file_id: str
    observed_at: datetime | None
    system_id: str
    resource_id: str
    category: str
    state: str
    identifiers: set[str] = field(default_factory=set)
    retention_until: datetime | None = None
    file_captured_at: datetime | None = None


@dataclass
class ResourceState:
    system_id: str
    resource_id: str
    category: str
    state: str
    evidence_file: str
    retention_until: datetime | None = None


# --------------------------------------------------------------------------
# Evidence parsing
# --------------------------------------------------------------------------

IDENTIFIER_KEYS = (
    "customer_reference", "subject_reference", "subject_ref", "subject_key",
    "lookup_key",
    "match_key", "correlation_key", "matched_value",
    "customer_email", "owner_email", "requester_email",
    "email", "email_hash", "phone", "owner_phone", "requester_phone",
)


def _identifiers_from_mapping(mapping: dict) -> set[str]:
    """Collect identifiers from a record, recursing into nested dicts and
    lists (profile objects, index hits, snapshot payloads). The string
    "null" is not an identifier. Free-text fields (message_text,
    message_excerpt) are also scanned for embedded email addresses."""
    ids: set[str] = set()
    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    def walk(node) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key in IDENTIFIER_KEYS and isinstance(value, str):
                    value = value.strip()
                    if value and value != "null":
                        ids.add(value.lower() if "@" in value else value)
                elif key in ("message_text", "message_excerpt") and isinstance(value, str):
                    for email in email_re.findall(value):
                        ids.add(email.lower())
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(mapping)
    return ids


def _identifiers_present(mapping: dict) -> bool:
    for key in ("email", "customer_email", "owner_email", "requester_email",
                "phone", "owner_phone", "requester_phone", "email_hash",
                "full_name", "display_name", "requester_name", "name"):
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return True
    # Free-text message bodies count when they embed a direct identifier.
    for key in ("message_text", "message_excerpt"):
        value = mapping.get(key)
        if isinstance(value, str) and "@" in value:
            return True
    return False


def parse_sql_file(path: Path, file_id: str, captured_at: datetime | None) -> list[Observation]:
    text = path.read_text(errors="ignore")
    observations: list[Observation] = []
    tables: dict[str, list[str]] = {}
    for match in re.finditer(r"CREATE TABLE\s+\"?(\w+)\"?\s*\((.*?)\);", text, re.S):
        # Split top-level commas only: CHECK (...) constraints contain
        # commas and parentheses of their own.
        cols = []
        for segment in split_sql_values(match.group(2)):
            segment = segment.strip().strip('"')
            if segment:
                cols.append(segment.split()[0])
        tables[match.group(1)] = cols
    for match in re.finditer(r"INSERT INTO\s+\"?(\w+)\"?\s*VALUES\s*\((.*?)\);", text, re.S):
        table, body = match.group(1), match.group(2)
        if table == "snapshot_scope":
            continue
        values = [sql_literal(tok) for tok in split_sql_values(body)]
        cols = tables.get(table)
        if table in ("customer_data_primary", "customer_data_failover_replica",
                     "customer_data_read_replica", "customer_data_replica_ap_south",
                     "customer_data_replica_eu_west", "customer_data_reporting_replica"):
            # Generic lake table: (resource_id, origin_system, collection, json, updated_at)
            if len(values) < 5:
                continue
            resource_id, system_id, collection, payload, updated = values[:5]
            mapping = COLLECTIONS.get(collection)
            if mapping is None or not isinstance(resource_id, str):
                continue
            _, category = mapping
            try:
                record = json.loads(payload) if isinstance(payload, str) else {}
            except (ValueError, TypeError):
                record = {}
            if not isinstance(record, dict):
                record = {}
            state, retention = _state_from_record(category, record, system_id)
            if state is None:
                continue
            observations.append(Observation(
                file_id=file_id, observed_at=parse_time(updated) or captured_at,
                system_id=system_id, resource_id=resource_id, category=category,
                state=state, identifiers=_identifiers_from_mapping(record),
                retention_until=retention,
            ))
            continue
        mapping = SQL_TABLES.get(table)
        if mapping is None or cols is None or len(values) != len(cols):
            continue
        system_id, category = mapping
        record = dict(zip(cols, values))
        resource_id = record.get("resource_id")
        if not isinstance(resource_id, str):
            continue
        state, retention = _state_from_record(category, record, system_id)
        if state is None:
            continue
        observations.append(Observation(
            file_id=file_id, observed_at=parse_time(record.get("updated_at")) or captured_at,
            system_id=system_id, resource_id=resource_id, category=category,
            state=state, identifiers=_identifiers_from_mapping(record),
            retention_until=retention,
        ))
    return observations


def _state_from_record(category: str, record: dict, system_id: str) -> tuple[str | None, datetime | None]:
    """Map one parsed record to a canonical state + retention deadline."""
    retention = parse_time(record.get("retention_until") or record.get("retained_until"))
    status = record.get("account_status")
    if isinstance(status, str):
        if status == "DELETED":
            return ABSENT, retention
        if status in ("ACTIVE", "DELETION_PENDING"):
            return PRESENT, retention
    if category == "ANALYTICS_PROFILE" or category == "PRODUCT_TELEMETRY":
        return (IDENTIFIABLE if _identifiers_present(record) else ANONYMIZED), retention
    if category == "ACCOUNT_TOMBSTONE":
        return (IDENTIFIABLE if _identifiers_present(record) else REDACTED), retention
    if category == "DATA_FLOW":
        enabled = record.get("enabled")
        if enabled is True or enabled == 1 or enabled == "1" or enabled == "true":
            return ACTIVE, retention
        if enabled is False or enabled == 0 or enabled == "0" or enabled == "false":
            return DISABLED, retention
        return None, retention
    if category == "BACKUP_ARCHIVE":
        allowed = record.get("restore_allowed")
        if allowed is True or allowed == 1 or allowed == "1" or allowed == "true":
            return ACTIVE, retention
        if allowed is False or allowed == 0 or allowed == "0" or allowed == "false":
            return BLOCKED, retention
        return None, retention
    if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
        return PRESENT, retention
    if category == "SUPPORT_MESSAGE":
        return (IDENTIFIABLE if _identifiers_present(record) else REDACTED), retention
    if category == "SUPPORT_ATTACHMENT":
        # An attachment row existing means the file is still there.
        return PRESENT, retention
    # USER_PROFILE, SEARCH_INDEX_ENTRY, USER_EXPORT, MARKETING_PROFILE,
    # SECONDARY_IDENTIFIER, CACHE_ENTRY, EMAIL_DELIVERY_LOG: a row means present.
    if category in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT",
                    "MARKETING_PROFILE", "SECONDARY_IDENTIFIER", "CACHE_ENTRY",
                    "EMAIL_DELIVERY_LOG"):
        return PRESENT, retention
    return None, retention


def _walk_json(node, system_hint: str | None, category_hint: str | None,
                file_id: str, file_time: datetime | None,
                observations: list[Observation]) -> None:
    """Generic recursive walk: any dict with resource_id is an observation.
    Collection names (bundle snapshots, export-job files) resolve to a
    (system, category) pair that child records inherit."""
    if isinstance(node, dict):
        if "collection" in node and isinstance(node["collection"], str):
            mapping = COLLECTIONS.get(node["collection"])
            if mapping is not None:
                system_hint, category_hint = mapping
        if isinstance(node.get("data_store"), str):
            system_hint = node["data_store"]
        if "resource_id" in node and isinstance(node["resource_id"], str):
            system_id = node.get("system_id") or node.get("data_store") or node.get("origin_system") or system_hint or "unknown"
            category = node.get("category") or node.get("collection") or category_hint
            if category is None:
                # Infer from section context via system + record shape.
                category = _infer_category(system_id, node)
            if category is not None:
                observed = parse_time(node.get("observed_at") or node.get("captured_at") or node.get("updated_at")) or file_time
                state = _state_from_json_record(category, node)
                if state is not None:
                    observations.append(Observation(
                        file_id=file_id, observed_at=observed, system_id=system_id,
                        resource_id=node["resource_id"], category=category, state=state,
                        identifiers=_identifiers_from_mapping(node),
                        retention_until=parse_time(node.get("retention_until") or node.get("retained_until")),
                    ))
            # Do not descend into an already-consumed record.
            return
        # Section dispatch for service exports: keys are system names.
        for key, value in node.items():
            hint = key if key in (
                "account_service", "search_service", "analytics_platform",
                "support_platform", "export_service", "integration_service",
                "backup_service", "security_service", "identity_service",
                "legal_service", "marketing_platform", "cache_service",
                "email_delivery_service",
            ) else system_hint
            if key in ("snapshots",) and isinstance(value, list):
                for snap in value:
                    if isinstance(snap, dict):
                        snap_system = snap.get("data_store") or hint
                        snap_category = COLLECTIONS.get(snap.get("collection", ""), (None, None))[1]
                        snap_time = parse_time(snap.get("captured_at")) or file_time
                        for rec in snap.get("records", []):
                            if isinstance(rec, dict) and "resource_id" in rec:
                                cat = snap_category or _infer_category(snap_system, rec)
                                if cat is None:
                                    continue
                                state = _state_from_json_record(cat, rec)
                                if state is None:
                                    continue
                                observations.append(Observation(
                                    file_id=file_id, observed_at=snap_time, system_id=snap_system,
                                    resource_id=rec["resource_id"], category=cat, state=state,
                                    identifiers=_identifiers_from_mapping(rec),
                                    retention_until=parse_time(rec.get("retention_until") or rec.get("retained_until")),
                                ))
                continue
            _walk_json(value, hint, category_hint, file_id, file_time, observations)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, system_hint, category_hint, file_id, file_time, observations)


def _infer_category(system_id: str | None, record: dict) -> str | None:
    if system_id == "account_service":
        return "USER_PROFILE"
    if system_id == "search_service":
        return "SEARCH_INDEX_ENTRY"
    if system_id == "analytics_platform":
        return "ANALYTICS_PROFILE"
    if system_id == "support_platform":
        return "SUPPORT_MESSAGE"
    if system_id == "export_service":
        return "USER_EXPORT"
    if system_id == "integration_service":
        return "DATA_FLOW"
    if system_id == "backup_service":
        return "BACKUP_ARCHIVE"
    if system_id == "security_service":
        return "SECURITY_AUDIT_LOG"
    if system_id == "identity_service":
        return "ACCOUNT_TOMBSTONE"
    if system_id == "legal_service":
        return "LEGAL_HOLD_RECORD"
    if system_id == "marketing_platform":
        return "MARKETING_PROFILE"
    if system_id == "cache_service":
        return "CACHE_ENTRY"
    if system_id == "email_delivery_service":
        return "EMAIL_DELIVERY_LOG"
    return None


def _state_from_json_record(category: str, record: dict) -> str | None:
    if "status_code" in record:
        if record["status_code"] == 404:
            return ABSENT
        profile = record.get("profile")
        if isinstance(profile, dict):
            return PRESENT if _identifiers_present(profile) else ABSENT
        return PRESENT
    if "hits" in record and isinstance(record["hits"], dict):
        docs = record["hits"].get("documents", [])
        if docs:
            return PRESENT
        return None
    if category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
        return IDENTIFIABLE if _identifiers_present(record) else ANONYMIZED
    if category == "ACCOUNT_TOMBSTONE":
        return IDENTIFIABLE if _identifiers_present(record) else REDACTED
    if category == "DATA_FLOW":
        enabled = record.get("enabled")
        if enabled is True or enabled == "true":
            return ACTIVE
        if enabled is False or enabled == "false":
            return DISABLED
        return None
    if category == "BACKUP_ARCHIVE":
        allowed = record.get("restore_allowed")
        if allowed is True or allowed == "true":
            return ACTIVE
        if allowed is False or allowed == "false":
            return BLOCKED
        return None
    if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
        return PRESENT
    if category == "SUPPORT_MESSAGE":
        return IDENTIFIABLE if _identifiers_present(record) else REDACTED
    if category in ("USER_PROFILE", "SEARCH_INDEX_ENTRY", "USER_EXPORT",
                    "MARKETING_PROFILE", "SECONDARY_IDENTIFIER", "CACHE_ENTRY",
                    "EMAIL_DELIVERY_LOG", "SUPPORT_ATTACHMENT"):
        return PRESENT
    return None


def parse_json_file(path: Path, file_id: str, captured_at: datetime | None) -> list[Observation]:
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except ValueError:
        return []
    observations: list[Observation] = []
    _walk_json(data, None, None, file_id, captured_at, observations)
    return observations


HANDOVER_RE = re.compile(
    r"^\s*-?\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s*\|\s*([A-Z_]+)\s*\|\s*([A-Z_]+)\s*\|\s*(.+?)\s*$"
)
HANDOVER_STATE = {
    "NOT_FOUND": ABSENT,
    "FOUND": PRESENT,
    "IDENTIFIABLE": IDENTIFIABLE,
    "ANONYMIZED": ANONYMIZED,
    "REDACTED": REDACTED,
    "ACTIVE": ACTIVE,
    "DISABLED": DISABLED,
    "BLOCKED": BLOCKED,
}


def parse_txt_file(path: Path, file_id: str, captured_at: datetime | None) -> list[Observation]:
    observations: list[Observation] = []
    for line in path.read_text(errors="ignore").splitlines():
        match = HANDOVER_RE.match(line)
        if not match:
            continue
        timestamp, system_id, resource_id, category, status, identifier = match.groups()
        state = HANDOVER_STATE.get(status)
        if state is None:
            continue
        ids: set[str] = set()
        identifier = identifier.strip()
        if identifier and identifier != "no direct identifier":
            ids.add(identifier.lower() if "@" in identifier else identifier)
        observations.append(Observation(
            file_id=file_id, observed_at=parse_time(timestamp) or captured_at,
            system_id=system_id, resource_id=resource_id, category=category,
            state=state, identifiers=ids,
        ))
    return observations


KV_RE = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")
SYSLOG_RE = re.compile(r"^\S+\s+<\d+>\d+\s+\S+\s+(\S+)\s+\S+\s+-\s+-")
ISO_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


def _kv_fields(line: str) -> dict:
    # Some files embed a second, backslash-escaped log line inside a
    # message="..." value; unescape it so its fields parse normally.
    if '\\"' in line:
        line = line.replace('\\"', '"')
    return dict((k, v.strip('"')) for k, v in KV_RE.findall(line))


def _line_time(line: str, captured_at: datetime | None) -> datetime | None:
    match = ISO_TS_RE.match(line)
    if match:
        return parse_time(match.group(0))
    return captured_at


def _line_system(line: str, fields: dict) -> str | None:
    if fields.get("system"):
        return fields["system"]
    if fields.get("service"):
        service = fields["service"]
        # Replica/collector service names map to their canonical system.
        return {"support_replica": "support_platform"}.get(service, service)
    if fields.get("function"):
        return fields["function"]
    match = SYSLOG_RE.match(line)
    if match:
        return match.group(1)
    return None


def _field_identifiers(fields: dict) -> set[str]:
    ids: set[str] = set()
    for key in IDENTIFIER_KEYS:
        value = fields.get(key)
        if value and value != "null":
            ids.add(value.lower() if "@" in value else value)
    return ids


def _bool_field(fields: dict, key: str) -> bool | None:
    value = fields.get(key)
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def parse_log_file(path: Path, file_id: str, captured_at: datetime | None) -> list[Observation]:
    """Two-pass log parse. Pass 1 collects trace_id -> identifiers from
    EVERY line (started lines carry lookup_key/match_key/subject_key but
    often have no resource_id). Pass 2 emits one observation per
    state-bearing event, using the union of the line's own identifiers
    and its trace's identifiers. JSONL lines (timestamp + one JSON
    object) are parsed as field dicts."""
    raw_lines = path.read_text(errors="ignore").splitlines()
    parsed: list[tuple[str, dict]] = []
    trace_lines: list[tuple[str, dict]] = []
    for line in raw_lines:
        fields: dict | None = None
        brace = line.find("{")
        if brace > 0 and line[brace:].strip().startswith("{"):
            try:
                obj = json.loads(line[brace:])
                if isinstance(obj, dict):
                    fields = {str(k): (v if isinstance(v, str) else json.dumps(v))
                              for k, v in obj.items()}
            except ValueError:
                fields = None
        if fields is None:
            if "resource_id" not in line and "event=" not in line and "trace_id" not in line \
               and "requestId" not in line:
                continue
            fields = _kv_fields(line)
        trace = fields.get("trace_id") or fields.get("requestId")
        if trace:
            trace_lines.append((line, fields))
        if not fields.get("resource_id"):
            continue
        parsed.append((line, fields))

    trace_ids: dict[str, set[str]] = {}
    for line, fields in trace_lines:
        trace = fields.get("trace_id") or fields.get("requestId")
        if trace:
            trace_ids.setdefault(trace, set()).update(_field_identifiers(fields))

    observations: list[Observation] = []
    seen: set[tuple] = set()
    for line, fields in parsed:
        event = (fields.get("event") or "").strip('"')
        resource_id = fields["resource_id"]
        system_id = _line_system(line, fields) or "unknown"
        observed = _line_time(line, captured_at)
        trace = fields.get("trace_id") or fields.get("requestId")
        ids = _field_identifiers(fields)
        if trace and trace in trace_ids:
            ids |= trace_ids[trace]
        category: str | None = None
        state: str | None = None
        retention = parse_time(fields.get("retention_until"))

        if event in ("profile_lookup_completed",):
            rows, http_status = fields.get("rows"), fields.get("http_status")
            state = ABSENT if rows == "0" or http_status == "404" else PRESENT
            category = "USER_PROFILE"
        elif event in ("analytics_profile_read_completed", "analytics_profile_read"):
            if _bool_field(fields, "direct_identifiers") is False or (
                fields.get("direct_identifiers") == "0"
            ):
                state = ANONYMIZED
            elif any(fields.get(k) and fields[k] != "null"
                     for k in ("email", "phone", "email_hash", "customer_reference")):
                state = IDENTIFIABLE
            elif fields.get("direct_identifiers") not in (None, "0"):
                state = IDENTIFIABLE
            else:
                state = ANONYMIZED
            category = "ANALYTICS_PROFILE"
        elif event == "audit_record_read_completed":
            if fields.get("rows") not in (None, "0"):
                state, category = PRESENT, "SECURITY_AUDIT_LOG"
        elif event in ("connector_config_read_completed", "connector_config_loaded"):
            enabled = _bool_field(fields, "enabled")
            if enabled is not None:
                state = ACTIVE if enabled else DISABLED
                category = "DATA_FLOW"
        elif event in ("restore_policy_read_completed", "restore_authorization_completed"):
            if event == "restore_authorization_completed":
                decision = fields.get("decision")
                state = BLOCKED if decision == "deny" else ACTIVE if decision == "allow" else None
            else:
                allowed = _bool_field(fields, "restore_allowed")
                state = ACTIVE if allowed else BLOCKED if allowed is not None else None
            category = "BACKUP_ARCHIVE"
        elif event in ("support_ticket_read_completed", "message_read"):
            text = fields.get("message_text", "")
            if text == "[REDACTED]":
                state = REDACTED
            elif any(fields.get(k) and fields[k] != "null"
                     for k in ("requester_email", "requester_phone", "requester_name")):
                state = IDENTIFIABLE
            elif text:
                state = IDENTIFIABLE
            else:
                state = REDACTED
            category = "SUPPORT_MESSAGE"
        elif event == "export_metadata_read_completed":
            if fields.get("available") != "false" and fields.get("owner_email"):
                state, category = PRESENT, "USER_EXPORT"
        elif event == "export_download_check_completed":
            if fields.get("available") == "true":
                state, category = PRESENT, "USER_EXPORT"
        elif event == "index_query_completed":
            result = fields.get("result")
            if result == "hit":
                state, category = PRESENT, "SEARCH_INDEX_ENTRY"
            elif result == "miss":
                state, category = ABSENT, "SEARCH_INDEX_ENTRY"
        elif event == "contact_query_completed":
            if fields.get("rows") not in (None, "0"):
                state, category = PRESENT, "SUPPORT_ATTACHMENT"
        elif event == "contact_lookup_completed":
            if fields.get("rows") not in (None, "0"):
                state, category = PRESENT, "ANALYTICS_PROFILE"
        elif event == "deletion_marker_check":
            marker = fields.get("marker_found")
            if marker == "false":
                state, category = PRESENT, "SUPPORT_ATTACHMENT"
            elif marker == "true":
                state, category = ABSENT, "SUPPORT_ATTACHMENT"
        elif event == "message_pii_scan":
            if fields.get("matched_value"):
                state, category = IDENTIFIABLE, "SUPPORT_MESSAGE"
        elif event == "attachment_pii_scan":
            if fields.get("matched_value"):
                state, category = PRESENT, "SUPPORT_ATTACHMENT"
        elif event == "analytics_identity_scan":
            if fields.get("matched_value"):
                state, category = IDENTIFIABLE, "ANALYTICS_PROFILE"
        elif event == "connector_heartbeat":
            enabled = _bool_field(fields, "enabled")
            if enabled is not None:
                state = ACTIVE if enabled else DISABLED
                category = "DATA_FLOW"
        elif event == "record_lookup":
            result = fields.get("result")
            record_type = fields.get("record_type")
            if result and record_type:
                state = PRESENT if result == "FOUND" else ABSENT
                category = record_type
                if system_id == "search_index_service":
                    system_id = fields.get("system") or system_id
        elif event == "restore_candidate_evaluated":
            blocked = _bool_field(fields, "deletion_block")
            if blocked is True:
                state = BLOCKED
            elif fields.get("eligible") == "true":
                state = ACTIVE
            category = "BACKUP_ARCHIVE"
        if state is None or category is None:
            continue
        key = (file_id, str(observed), system_id, resource_id, category, state)
        if key in seen:
            continue
        seen.add(key)
        observations.append(Observation(
            file_id=file_id, observed_at=observed, system_id=system_id,
            resource_id=resource_id, category=category, state=state,
            identifiers=ids, retention_until=retention,
        ))
    return observations


# --------------------------------------------------------------------------
# Extracted evidence (PDF / image transcriptions)
# --------------------------------------------------------------------------
# PDFs and screenshots cannot be parsed by the text parsers above, so
# their content is extracted once (see scripts/extract_evidence.py) and
# checked in as evidence/extracted/<file_id>.txt (human-readable
# transcription) plus evidence/extracted/<file_id>.records (machine
# RECORD lines). The engine reads ONLY the RECORD lines: the free-text
# transcription is audit material, never parsed, so a stray resource ID
# or email in a narrative sentence can never become an observation.
# A RECORD line is:
#   RECORD system_id=...; resource_id=...; category=...; state=...;
#          identifiers=<id|id|...>; retention_until=<ISO, optional>
# Only the page's attributable records are listed: a resource appears
# only when the document itself ties it to identifiers (a header, a
# detail panel, a table row with an owner/selector column). Secondary
# mentions without their own identifier context (an order number, a
# linked ticket in a sidebar) are transcribed but deliberately NOT
# emitted as observations — attributing them would be guessing.
# Malformed lines are skipped with a stderr warning, never silently
# repaired: a bad extraction must be visible, not quietly reinterpreted.

EXTRACTED_SYSTEMS = {
    "account_service", "search_service", "analytics_platform",
    "support_platform", "export_service", "integration_service",
    "backup_service", "security_service", "identity_service",
    "legal_service", "marketing_platform", "cache_service",
    "email_delivery_service", "object_storage",
}
EXTRACTED_CATEGORIES = {
    "USER_PROFILE", "SECONDARY_IDENTIFIER", "SEARCH_INDEX_ENTRY",
    "CACHE_ENTRY", "USER_EXPORT", "MARKETING_PROFILE", "SUPPORT_MESSAGE",
    "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE", "PRODUCT_TELEMETRY",
    "EMAIL_DELIVERY_LOG", "SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD",
    "BACKUP_ARCHIVE", "ACCOUNT_TOMBSTONE", "DATA_FLOW",
}
EXTRACTED_STATES = {
    "PRESENT", "IDENTIFIABLE", "ACTIVE", "ANONYMIZED", "REDACTED",
    "ABSENT", "DISABLED", "BLOCKED",
}


def parse_extracted_records(path: Path, file_id: str,
                            captured_at: datetime | None) -> list[Observation]:
    """Parse a checked-in <file_id>.records file into observations.

    observed_at is the source file's capture time: a screenshot or
    document shows the state at capture, exactly like a snapshot file.
    """
    observations: list[Observation] = []
    for lineno, raw in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not line.startswith("RECORD "):
            print(f"warning: {path.name}:{lineno}: ignoring non-RECORD line",
                  file=sys.stderr)
            continue
        fields: dict[str, str] = {}
        for part in line[len("RECORD "):].split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                fields = {}
                break
            key, value = part.split("=", 1)
            fields[key.strip()] = value.strip()
        system_id = fields.get("system_id", "")
        resource_id = fields.get("resource_id", "")
        category = fields.get("category", "")
        state = fields.get("state", "")
        if (not fields or system_id not in EXTRACTED_SYSTEMS
                or not resource_id or category not in EXTRACTED_CATEGORIES
                or state not in EXTRACTED_STATES):
            print(f"warning: {path.name}:{lineno}: skipping malformed "
                  f"RECORD line: {line!r}", file=sys.stderr)
            continue
        identifiers = set()
        for ident in fields.get("identifiers", "").split("|"):
            ident = ident.strip()
            if ident:
                identifiers.add(ident.lower() if "@" in ident else ident)
        observations.append(Observation(
            file_id=file_id, observed_at=captured_at, system_id=system_id,
            resource_id=resource_id, category=category, state=state,
            identifiers=identifiers,
            retention_until=parse_time(fields.get("retention_until")),
        ))
    return observations


# --------------------------------------------------------------------------
# Dataset loading
# --------------------------------------------------------------------------

@dataclass
class Dataset:
    rules: dict[str, str]  # category -> action
    identities: dict[str, dict]
    audit_log: list[dict]
    activity: list[dict]
    evidence_manifest: dict[str, dict]  # file_id -> row
    observations: list[Observation]
    file_systems: dict[str, set[str]]  # file_id -> systems it covers
    classify_non_deletion_accounts: set[str]


def default_extracted_dir() -> Path:
    """Checked-in extractions live beside the code, not in the dataset:
    evidence/extracted/ under the repo root (the engine file's parent)."""
    return Path(__file__).resolve().parents[1] / "evidence" / "extracted"


def load_dataset(dataset_dir: Path,
                 extracted_dir: Path | None = None) -> Dataset:
    def read_csv(name: str) -> list[dict]:
        with open(dataset_dir / name, newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))

    rules = {}
    for row in read_csv("deletion_rules.csv"):
        rules[row["data_category"]] = row["required_action"]
    identities = {row["user_id"]: row for row in read_csv("user_identities.csv")}
    audit_log = read_csv("user_audit_log.csv")
    activity = read_csv("system_activity.csv")
    manifest_rows = read_csv("evidence_files.csv")
    manifest = {row["file_id"]: row for row in manifest_rows}

    observations: list[Observation] = []
    file_systems: dict[str, set[str]] = {}
    for row in manifest_rows:
        file_id = row["file_id"]
        rel = row["file_path"]
        path = dataset_dir / rel
        captured = parse_time(row["captured_at"])
        if not path.exists():
            continue
        suffix = path.suffix.lower()
        if suffix == ".sql":
            parsed = parse_sql_file(path, file_id, captured)
        elif suffix == ".json":
            parsed = parse_json_file(path, file_id, captured)
        elif suffix == ".txt":
            parsed = parse_txt_file(path, file_id, captured)
        elif suffix == ".log":
            parsed = parse_log_file(path, file_id, captured)
        elif suffix in (".pdf", ".png"):
            # Pre-extracted content: the engine reads only the curated
            # RECORD lines, never raw transcription text. A missing
            # extraction is a loud warning, not a silent skip.
            if extracted_dir is None:
                extracted_dir = default_extracted_dir()
            records_path = extracted_dir / f"{file_id}.records"
            if records_path.exists():
                parsed = parse_extracted_records(records_path, file_id, captured)
            else:
                print(f"warning: no extraction for {file_id} "
                      f"({rel}); evidence not usable by the engine",
                      file=sys.stderr)
                parsed = []
        else:
            parsed = []
        for obs in parsed:
            obs.file_captured_at = captured
        observations.extend(parsed)
        file_systems[file_id] = {obs.system_id for obs in parsed}

    classify_accounts = {
        row["resource_id"]
        for row in activity
        if row["event_type"] == "CLASSIFY_REQUEST" and "non-deletion" in row["details"]
    }
    return Dataset(
        rules=rules, identities=identities, audit_log=audit_log,
        activity=activity, evidence_manifest=manifest,
        observations=observations, file_systems=file_systems,
        classify_non_deletion_accounts=classify_accounts,
    )


def resolve_user(data: Dataset, email: str) -> str | None:
    target = email.strip().lower()
    for user_id, row in data.identities.items():
        if (row.get("email") or "").strip().lower() == target:
            return user_id
    for row in data.audit_log:
        if (row.get("old_value") or "").strip().lower() == target or \
           (row.get("new_value") or "").strip().lower() == target:
            return row["user_id"]
    return None


def user_identifier_set(data: Dataset, user_id: str) -> set[str]:
    row = data.identities.get(user_id, {})
    ids: set[str] = {user_id}
    for key in ("email", "phone", "email_hash"):
        value = (row.get(key) or "").strip()
        if value:
            ids.add(value.lower() if key == "email" else value)
    for entry in data.audit_log:
        if entry["user_id"] != user_id:
            continue
        for key in ("old_value", "new_value"):
            value = (entry.get(key) or "").strip()
            if value:
                ids.add(value.lower() if "@" in value else value)
    return ids


# --------------------------------------------------------------------------
# Per-case audit
# --------------------------------------------------------------------------

DELETION_INTENT = re.compile(
    r"delet|eras|remov|clos|suppress|elimin|borrar|supprim|exclus|eliminar|"
    r"cancell|olvid|oubli|forget|effac|retir|del et|close my|shut down",
    re.I,
)
NON_DELETION_SIGNALS = [
    re.compile(p, re.I) for p in [
        r"leave (the )?account (active|as it is|in place)",
        r"keep (the )?account",
        r"continue using",
        r"download my (account )?(information|data)",
        r"portable format",
        r"copy of .* invoices",
        r"change the email",
        r"update .* (phone|email|number)",
        r"replace it with the new one",
        r"leave my profile",
        r"leave .* in place",
    ]
]


def is_non_deletion_text(text: str) -> bool:
    if DELETION_INTENT.search(text):
        return False
    return any(pattern.search(text) for pattern in NON_DELETION_SIGNALS)


def latest_state_at(observations: list[Observation], audit_at: datetime) -> ResourceState | None:
    """Latest observation at or before audit_at (inclusive: a snapshot
    stamped exactly at the audit instant counts — the samples confirm
    this for handover lines and bundle snapshots at 12:00:00)."""
    candidates = [o for o in observations
                  if o.observed_at is not None and o.observed_at <= audit_at]
    if not candidates:
        return None
    best = candidates[-1]
    for obs in candidates:
        if obs.observed_at > best.observed_at:
            best = obs
    return ResourceState(
        system_id=best.system_id, resource_id=best.resource_id,
        category=best.category, state=best.state, evidence_file=best.file_id,
        retention_until=best.retention_until,
    )


def cite_evidence(data: Dataset, resource_id: str, system_id: str,
                  audit_at: datetime, state_file: str | None) -> str:
    """Latest evidence file at/before audit_at mentioning the resource;
    else the latest file covering its system; else the state file itself
    when it predates the audit; else empty."""
    candidates = []
    for obs in data.observations:
        if obs.resource_id != resource_id:
            continue
        captured = parse_time(data.evidence_manifest[obs.file_id]["captured_at"]) \
            if obs.file_id in data.evidence_manifest else None
        if captured is not None and captured <= audit_at:
            candidates.append((captured, obs.file_id))
    if candidates:
        candidates.sort()
        return candidates[-1][1]
    covering = []
    for file_id, systems in data.file_systems.items():
        if system_id in systems:
            captured = parse_time(data.evidence_manifest[file_id]["captured_at"]) \
                if file_id in data.evidence_manifest else None
            if captured is not None and captured <= audit_at:
                covering.append((captured, file_id))
    if covering:
        covering.sort()
        return covering[-1][1]
    if state_file:
        captured = parse_time(data.evidence_manifest[state_file]["captured_at"]) \
            if state_file in data.evidence_manifest else None
        if captured is not None and captured <= audit_at:
            return state_file
    return ""


def identify_account(data: Dataset, user_ids: set[str], case: dict,
                     used_accounts: set[str]) -> str | None:
    """Account resource for the case, in priority order:
    1. an activity DELETE candidate that is evidence-linked to this user;
    2. the unique activity DELETE candidate in the +/-2h window;
    3. the nearest candidate when it beats the runner-up by >5x;
    4. any evidence-linked account.
    Shared-timestamp collisions (several cases, one window) are left
    unassigned rather than guessed: a wrong account costs a false step
    as well as a missing one."""
    audit_at = parse_time(case["audit_at"])
    linked: dict[str, list[Observation]] = {}
    for obs in data.observations:
        if obs.system_id == "account_service" and obs.category == "USER_PROFILE":
            if obs.identifiers & user_ids:
                linked.setdefault(obs.resource_id, []).append(obs)

    reported = parse_time(case["reported_at"])
    candidates: list[tuple[float, str]] = []
    if reported is not None:
        for event in data.activity:
            if event["event_type"] != "DELETE_RECORD" or event["target_system"] != "account_service":
                continue
            resource_id = event["resource_id"]
            if resource_id in used_accounts:
                continue
            event_time = parse_time(event["event_time"])
            if event_time is None:
                continue
            gap = abs((event_time - reported).total_seconds())
            if gap <= 2 * 3600:
                candidates.append((gap, resource_id))
    candidates.sort()
    candidate_ids = {resource_id for _, resource_id in candidates}

    evidence_linked_candidates = [r for _, r in candidates if r in linked]
    if evidence_linked_candidates:
        return evidence_linked_candidates[0]
    if len(candidates) == 1:
        return candidates[0][1]
    if len(candidates) >= 2 and candidates[0][0] > 0 and candidates[1][0] > 5 * candidates[0][0]:
        return candidates[0][1]
    if audit_at is not None:
        for resource_id in sorted(linked):
            if any(o.observed_at is not None and o.observed_at <= audit_at
                   for o in linked[resource_id]):
                return resource_id
    if linked:
        return sorted(linked)[0]
    return None


def audit_case(data: Dataset, case: dict, used_accounts: set[str]) -> tuple[str, list[dict]]:
    audit_at = parse_time(case["audit_at"])
    if audit_at is None:
        return "INCOMPLETE", []

    if is_non_deletion_text(case.get("request_text", "")):
        return "NOT_APPLICABLE", []

    user_id = resolve_user(data, case["email"])
    if user_id is None:
        return "INCOMPLETE", []
    user_ids = user_identifier_set(data, user_id)

    # Phase 1 — link resources to the user via identifier-bearing
    # observations. Phase 2 (below) then uses EVERY observation of a
    # linked resource for state, including identifier-free ones (a 404
    # lookup with no identifiers still describes the linked account).
    linked_keys: set[tuple[str, str]] = set()
    all_obs: dict[tuple[str, str], list[Observation]] = {}
    for obs in data.observations:
        all_obs.setdefault((obs.system_id, obs.resource_id), []).append(obs)
        if obs.identifiers & user_ids:
            linked_keys.add((obs.system_id, obs.resource_id))

    account_id = identify_account(data, user_ids, case, used_accounts)
    if account_id is not None:
        used_accounts.add(account_id)

    if account_id is not None and account_id in data.classify_non_deletion_accounts:
        return "NOT_APPLICABLE", []

    # State at audit_at per resource.
    states: dict[tuple[str, str], ResourceState] = {}
    for key in sorted(linked_keys):
        state = latest_state_at(all_obs.get(key, []), audit_at)
        if state is not None:
            states[key] = state
    # The account resource itself may have no observation at all (pure
    # activity/batch linkage): its state is ABSENT unless evidence
    # contradicts it, which by construction it cannot here.
    if account_id is not None and ("account_service", account_id) not in states:
        states[("account_service", account_id)] = ResourceState(
            system_id="account_service", resource_id=account_id,
            category="USER_PROFILE", state=ABSENT, evidence_file="",
        )

    findings: list[dict] = []
    remediations: list[dict] = []
    verifications: list[dict] = []

    def add_finding(system_id: str, resource_id: str, operation: str,
                    state: str, evidence: str) -> None:
        findings.append({
            "phase": "FINDING", "system_id": system_id, "resource_id": resource_id,
            "operation": operation, "state": state, "evidence_id": evidence,
        })

    def add_fix(system_id: str, resource_id: str, operation: str, state: str) -> None:
        remediations.append({
            "phase": "REMEDIATION", "system_id": system_id, "resource_id": resource_id,
            "operation": operation, "state": state, "evidence_id": "",
        })

    def add_check(system_id: str, resource_id: str, operation: str,
                  state: str, evidence: str) -> None:
        verifications.append({
            "phase": "VERIFICATION", "system_id": system_id, "resource_id": resource_id,
            "operation": operation, "state": state, "evidence_id": evidence,
        })

    for (system_id, resource_id), res in sorted(states.items()):
        category = res.category
        state = res.state
        evidence = cite_evidence(data, resource_id, system_id, audit_at, res.evidence_file)
        is_account = (system_id == "account_service" and resource_id == account_id)

        # State-driven treatment (validated on samples): bare PRESENT means
        # existence-only evidence -> the record still exists, so it is
        # reported and deleted. IDENTIFIABLE means the record's content
        # still carries identifiers -> reported as exposed PII and then
        # redacted (support/tombstone/log) or anonymized (analytics).
        # Already-correct end states earn only a verification step.
        if state == PRESENT:
            if category in ("SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"):
                retained = res.retention_until is None or res.retention_until >= audit_at
                if retained:
                    add_check(system_id, resource_id, "VERIFY_RECORD_PRESENT", PRESENT, "")
                else:
                    add_finding(system_id, resource_id, "REPORT_REMAINING_RECORD", PRESENT, evidence)
                    add_fix(system_id, resource_id, "DELETE_RECORD", ABSENT)
                    add_check(system_id, resource_id, "VERIFY_RECORD_ABSENT", ABSENT, "")
            elif category == "DATA_FLOW":
                add_finding(system_id, resource_id, "REPORT_ACTIVE_DATA_FLOW", ACTIVE, evidence)
                add_fix(system_id, resource_id, "DISABLE_DATA_FLOW", DISABLED)
                add_check(system_id, resource_id, "VERIFY_DATA_FLOW_DISABLED", DISABLED, "")
            elif category == "BACKUP_ARCHIVE":
                add_finding(system_id, resource_id, "REPORT_RESTORE_RISK", ACTIVE, evidence)
                add_fix(system_id, resource_id, "BLOCK_RESTORE", BLOCKED)
                add_check(system_id, resource_id, "VERIFY_RESTORE_BLOCKED", BLOCKED, "")
            else:
                add_finding(system_id, resource_id, "REPORT_REMAINING_RECORD", PRESENT, evidence)
                add_fix(system_id, resource_id, "DELETE_RECORD", ABSENT)
                add_check(system_id, resource_id, "VERIFY_RECORD_ABSENT", ABSENT, "")
        elif state == IDENTIFIABLE:
            add_finding(system_id, resource_id, "REPORT_EXPOSED_PII", PRESENT, evidence)
            if category in ("ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"):
                add_fix(system_id, resource_id, "ANONYMIZE_RECORD", ANONYMIZED)
                add_check(system_id, resource_id, "VERIFY_RECORD_ANONYMIZED", ANONYMIZED, "")
            else:
                add_fix(system_id, resource_id, "REDACT_RECORD", REDACTED)
                add_check(system_id, resource_id, "VERIFY_RECORD_REDACTED", REDACTED, "")
        elif state == ANONYMIZED:
            add_check(system_id, resource_id, "VERIFY_RECORD_ANONYMIZED", ANONYMIZED, "")
        elif state == REDACTED:
            add_check(system_id, resource_id, "VERIFY_RECORD_REDACTED", REDACTED, "")
        elif state == ACTIVE:
            if category == "DATA_FLOW":
                add_finding(system_id, resource_id, "REPORT_ACTIVE_DATA_FLOW", ACTIVE, evidence)
                add_fix(system_id, resource_id, "DISABLE_DATA_FLOW", DISABLED)
                add_check(system_id, resource_id, "VERIFY_DATA_FLOW_DISABLED", DISABLED, "")
            elif category == "BACKUP_ARCHIVE":
                add_finding(system_id, resource_id, "REPORT_RESTORE_RISK", ACTIVE, evidence)
                add_fix(system_id, resource_id, "BLOCK_RESTORE", BLOCKED)
                add_check(system_id, resource_id, "VERIFY_RESTORE_BLOCKED", BLOCKED, "")
            else:
                add_finding(system_id, resource_id, "REPORT_REMAINING_RECORD", PRESENT, evidence)
                add_fix(system_id, resource_id, "DELETE_RECORD", ABSENT)
                add_check(system_id, resource_id, "VERIFY_RECORD_ABSENT", ABSENT, "")
        elif state == DISABLED:
            add_check(system_id, resource_id, "VERIFY_DATA_FLOW_DISABLED", DISABLED, "")
        elif state == BLOCKED:
            add_check(system_id, resource_id, "VERIFY_RESTORE_BLOCKED", BLOCKED, "")
        elif state == ABSENT and is_account:
            add_check(system_id, resource_id, "VERIFY_RECORD_ABSENT", ABSENT, "")
        # Already-absent non-account records earn no step; absent retained
        # records have no remediation operation in the statement's table,
        # so they are left without a step (documented gap).

    status = "INCOMPLETE" if findings else "COMPLETE"
    steps = findings + remediations + verifications
    if status == "COMPLETE":
        # COMPLETE cases carry verification steps only, each citing evidence.
        verified: list[dict] = []
        for step in verifications:
            step = dict(step)
            step["evidence_id"] = cite_evidence(
                data, step["resource_id"], step["system_id"], audit_at, "")
            verified.append(step)
        steps = verified
    else:
        # INCOMPLETE: evidence already attached to findings; remediation and
        # future verification steps stay empty per the statement.
        pass

    ordered = order_steps(steps)
    for index, step in enumerate(ordered, start=1):
        step["step_no"] = index
    return status, ordered


def order_steps(steps: list[dict]) -> list[dict]:
    phase_rank = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
    order_map = {
        "FINDING": FINDING_ORDER,
        "REMEDIATION": REMEDIATION_ORDER,
        "VERIFICATION": VERIFICATION_ORDER,
    }

    def key(step: dict):
        order = order_map[step["phase"]]
        try:
            op_rank = order.index(step["operation"])
        except ValueError:
            op_rank = len(order)
        return (phase_rank[step["phase"]], op_rank, step["system_id"], step["resource_id"])

    return sorted(steps, key=key)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def combined_requests(dataset_dir: Path, requests_rows: list[dict]) -> list[dict]:
    """Requests being processed plus the dataset's other request files
    (evaluation requests + public samples share one evidence pool and
    one generator batch timeline, so window-uniqueness must count all
    of them)."""
    rows = list(requests_rows)
    seen = {r["case_id"] for r in rows}
    for name in ("deletion_requests.csv", "sample_deletion_requests.csv"):
        path = dataset_dir / name
        if not path.exists():
            continue
        with open(path, newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                if row["case_id"] not in seen:
                    rows.append(row)
                    seen.add(row["case_id"])
    return rows


def run(dataset_dir: Path, requests_path: Path, output_path: Path,
        extracted_dir: Path | None = None) -> None:
    data = load_dataset(dataset_dir, extracted_dir)
    with open(requests_path, newline="", encoding="utf-8") as handle:
        cases = list(csv.DictReader(handle))
    used_accounts: set[str] = set()
    rows = []
    for case in sorted(cases, key=lambda c: c["case_id"]):
        status, steps = audit_case(data, case, used_accounts)
        rows.append({
            "case_id": case["case_id"],
            "deletion_status": status,
            "steps_json": json.dumps(steps, sort_keys=True),
        })
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {len(rows)} rows to {output_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deterministic deletion-audit engine")
    parser.add_argument("--dataset", required=True, help="dataset/ directory")
    parser.add_argument("--requests", required=True, help="requests CSV")
    parser.add_argument("--output", required=True, help="output CSV to write")
    parser.add_argument("--extracted", default=None,
                        help="evidence/extracted/ directory "
                             "(default: repo evidence/extracted/)")
    args = parser.parse_args(argv)
    run(Path(args.dataset), Path(args.requests), Path(args.output),
        Path(args.extracted) if args.extracted else None)
    return 0


if __name__ == "__main__":
    sys.exit(main())
