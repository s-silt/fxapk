"""把现有被动网络事实机械转换为统一实体、观测与原子证据。"""

from __future__ import annotations

import math
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, cast

from apkscan.attribution.models import AttributionEvidence
from apkscan.network.entities import NetworkEntity, NetworkEntityType
from apkscan.network.fingerprints import (
    normalize_authority,
    normalize_domain,
    normalize_ip,
    sanitize_absolute_url,
    sanitize_http_path,
    stable_digest,
)
from apkscan.network.observations import Observation

__all__ = [
    "ConversionIssue",
    "ConversionResult",
    "convert_http_requests",
    "convert_mitmproxy_flows",
    "convert_pcap_summary",
    "merge_conversion_results",
]

_DNS_A = 1
_DNS_CNAME = 5
_DNS_NS = 2
_DNS_PTR = 12
_DNS_TXT = 16
_DNS_AAAA = 28
_DNS_DOMAIN_TYPES = {_DNS_NS, _DNS_CNAME, _DNS_PTR}
_REQUEST_HEADER_ALLOWLIST = {
    "accept",
    "accept-encoding",
    "accept-language",
    "content-length",
    "content-type",
    "origin",
    "referer",
    "user-agent",
    "x-requested-with",
}
_RESPONSE_HEADER_ALLOWLIST = {
    "cache-control",
    "content-length",
    "content-type",
    "location",
    "server",
}


@dataclass(frozen=True, kw_only=True)
class ConversionIssue:
    """单条脏事实被隔离后的结构化说明。"""

    stage: str
    index: int
    reason: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "stage", _required_string("stage", self.stage))
        if isinstance(self.index, bool) or not isinstance(self.index, int):
            raise TypeError("issue index must be an int")
        if self.index < 0:
            raise ValueError("issue index must be non-negative")
        object.__setattr__(self, "reason", _required_string("reason", self.reason))

    def to_dict(self) -> dict[str, object]:
        return {"stage": self.stage, "index": self.index, "reason": self.reason}


@dataclass(frozen=True, kw_only=True)
class ConversionResult:
    """一次纯转换的确定性输出；不包含角色或运营者推理。"""

    entities: tuple[NetworkEntity, ...] = ()
    observations: tuple[Observation, ...] = ()
    evidence: tuple[AttributionEvidence, ...] = ()
    issues: tuple[ConversionIssue, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "entities": [item.to_dict() for item in self.entities],
            "observations": [item.to_dict() for item in self.observations],
            "evidence": [item.to_dict() for item in self.evidence],
            "issues": [item.to_dict() for item in self.issues],
        }


def _required_string(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    clean = value.strip()
    if not clean:
        raise ValueError(f"{name} must not be blank")
    return clean


def _optional_reference(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise TypeError("raw_reference must be a string or None")


def _timestamp(value: object, *, allow_none: bool = True) -> float | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("timestamp must be an int, float, or None")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ValueError("timestamp must be finite and non-negative")
    return result


def _integer(name: str, value: object, *, minimum: int = 0, maximum: int | None = None) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be an int")
    if isinstance(value, str):
        if not value or not value.isascii() or not value.isdecimal():
            raise ValueError(f"{name} must be a decimal integer")
        result = int(value)
    elif isinstance(value, int):
        result = value
    else:
        raise TypeError(f"{name} must be an int")
    if result < minimum or (maximum is not None and result > maximum):
        raise ValueError(f"{name} is out of range")
    return result


def _iterable(name: str, value: object) -> list[object]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise TypeError(f"{name} must be a non-string iterable")
    return list(value)


def _attribute(item: object, name: str, default: object = None) -> object:
    if isinstance(item, Mapping):
        return item.get(name, default)
    return getattr(item, name, default)


def _best_effort_strings(value: object, *, label: str) -> tuple[list[str], list[str]]:
    try:
        items = _iterable(label, value)
    except (TypeError, ValueError):
        return [], [f"{label}: ignored invalid collection"]
    result: set[str] = set()
    invalid = 0
    for item in items:
        if not isinstance(item, str):
            invalid += 1
            continue
        clean = item.strip()
        if clean:
            result.add(clean)
    issues = [f"{label}: ignored {invalid} invalid value(s)"] if invalid else []
    return sorted(result), issues


def _best_effort_domains(value: object, *, label: str) -> tuple[list[str], list[str]]:
    try:
        items = _iterable(label, value)
    except (TypeError, ValueError):
        return [], [f"{label}: ignored invalid collection"]
    result: set[str] = set()
    invalid = 0
    for item in items:
        if not isinstance(item, str):
            invalid += 1
            continue
        try:
            result.add(normalize_domain(item))
        except (TypeError, ValueError):
            invalid += 1
    issues = [f"{label}: ignored {invalid} invalid value(s)"] if invalid else []
    return sorted(result), issues


def _entity(kind: NetworkEntityType, value: str, source: str) -> NetworkEntity:
    return NetworkEntity(kind, value, sources=(source,))


def _observation_id(
    artifact_id: str,
    observation_type: str,
    payload: object,
    *,
    source: str,
    raw_reference: str | None,
) -> str:
    return stable_digest(
        f"observation:{artifact_id}:{source}:{raw_reference or ''}:{observation_type}",
        payload,
    )


def _evidence_id(observation_id: str, evidence_type: str, target: NetworkEntity, value: object) -> str:
    return stable_digest(
        f"evidence:{observation_id}:{evidence_type}",
        {"target_type": target.kind.value, "target": target.value, "value": value},
    )


def _make_result(
    *,
    entities: Iterable[NetworkEntity] = (),
    observations: Iterable[Observation] = (),
    evidence: Iterable[AttributionEvidence] = (),
    issues: Iterable[ConversionIssue] = (),
) -> ConversionResult:
    observation_by_id: dict[str, Observation] = {}
    evidence_by_id: dict[str, AttributionEvidence] = {}
    source_map: dict[tuple[NetworkEntityType, str], set[str]] = {}

    all_observations = list(observations)
    all_evidence = list(evidence)
    all_entities = list(entities)
    for observation in all_observations:
        observation_by_id.setdefault(observation.id, observation)
        all_entities.extend(observation.entities)
    for item in all_evidence:
        evidence_by_id.setdefault(item.id, item)
        all_entities.append(item.target)
    for item in all_entities:
        key = (item.kind, item.value)
        source_map.setdefault(key, set()).update(item.sources)

    merged_entities = tuple(
        NetworkEntity(kind, value, sources=tuple(sorted(sources)))
        for (kind, value), sources in sorted(
            source_map.items(), key=lambda pair: (pair[0][0].value, pair[0][1])
        )
    )
    merged_issues = tuple(
        ConversionIssue(stage=stage, index=index, reason=reason)
        for stage, index, reason in sorted(
            {(item.stage, item.index, item.reason) for item in issues}
        )
    )
    return ConversionResult(
        entities=merged_entities,
        observations=tuple(
            sorted(observation_by_id.values(), key=lambda item: (item.type, item.id))
        ),
        evidence=tuple(sorted(evidence_by_id.values(), key=lambda item: (item.type, item.id))),
        issues=merged_issues,
    )


def _new_evidence(
    *,
    observation: Observation,
    evidence_type: str,
    target: NetworkEntity,
    value: str | int | float | bool | None,
) -> AttributionEvidence:
    return AttributionEvidence(
        id=_evidence_id(observation.id, evidence_type, target, value),
        source=observation.source,
        type=evidence_type,
        target=target,
        value=value,
        confidence=1.0,
        timestamp=observation.timestamp,
        raw_reference=observation.raw_reference,
    )


def _validate_artifact_context(artifact_id: object, raw_reference: object) -> tuple[str, str | None]:
    return _required_string("artifact_id", artifact_id), _optional_reference(raw_reference)


def _flow_sort_key(flow: object) -> tuple[object, ...]:
    first_ts = _timestamp(_attribute(flow, "first_ts", 0.0), allow_none=False)
    last_ts = _timestamp(_attribute(flow, "last_ts", 0.0), allow_none=False)
    if first_ts is None or last_ts is None:  # pragma: no cover - guarded above
        raise ValueError("flow timestamps are required")
    flags, _flag_issues = _best_effort_strings(
        _attribute(flow, "flags", ()), label="flags"
    )
    sni, _sni_issues = _best_effort_domains(
        _attribute(flow, "sni", ()), label="sni"
    )
    ja3, _ja3_issues = _best_effort_strings(_attribute(flow, "ja3", ()), label="ja3")
    alpn, _alpn_issues = _best_effort_strings(
        _attribute(flow, "alpn", ()), label="alpn"
    )
    versions, _version_issues = _best_effort_strings(
        _attribute(flow, "quic_versions", ()), label="quic_versions"
    )
    dcids, _dcid_issues = _best_effort_strings(
        _attribute(flow, "quic_dcids", ()), label="quic_dcids"
    )
    scids, _scid_issues = _best_effort_strings(
        _attribute(flow, "quic_scids", ()), label="quic_scids"
    )
    return (
        _required_string("protocol", _attribute(flow, "proto")).lower(),
        normalize_ip(_required_string("src_ip", _attribute(flow, "src_ip"))),
        _integer("src_port", _attribute(flow, "src_port", 0), maximum=65535),
        normalize_ip(_required_string("dst_ip", _attribute(flow, "dst_ip"))),
        _integer("dst_port", _attribute(flow, "dst_port", 0), maximum=65535),
        _integer("packets", _attribute(flow, "packets", 0)),
        _integer("bytes", _attribute(flow, "bytes_", 0)),
        _integer("payload_bytes", _attribute(flow, "payload_bytes", 0)),
        first_ts,
        last_ts,
        tuple(flags),
        tuple(sni),
        tuple(ja3),
        tuple(alpn),
        tuple(versions),
        tuple(dcids),
        tuple(scids),
    )


def _convert_flow(
    flow: object,
    *,
    artifact_id: str,
    raw_reference: str | None,
    occurrence: int,
) -> tuple[
    list[NetworkEntity],
    list[Observation],
    list[AttributionEvidence],
    list[str],
]:
    source = "pcap"
    protocol = _required_string("protocol", _attribute(flow, "proto")).lower()
    src_ip = normalize_ip(_required_string("src_ip", _attribute(flow, "src_ip")))
    dst_ip = normalize_ip(_required_string("dst_ip", _attribute(flow, "dst_ip")))
    src_port = _integer("src_port", _attribute(flow, "src_port"), maximum=65535)
    dst_port = _integer("dst_port", _attribute(flow, "dst_port"), maximum=65535)
    packets = _integer("packets", _attribute(flow, "packets", 0))
    bytes_count = _integer("bytes", _attribute(flow, "bytes_", 0))
    payload_bytes = _integer("payload_bytes", _attribute(flow, "payload_bytes", 0))
    first_ts = _timestamp(_attribute(flow, "first_ts", 0.0), allow_none=False)
    last_ts = _timestamp(_attribute(flow, "last_ts", 0.0), allow_none=False)
    if first_ts is None or last_ts is None:  # pragma: no cover - guarded by allow_none=False
        raise ValueError("flow timestamps are required")
    if last_ts < first_ts:
        raise ValueError("last_ts precedes first_ts")
    flags, flag_issues = _best_effort_strings(
        _attribute(flow, "flags", ()), label="flags"
    )
    sni, sni_issues = _best_effort_domains(
        _attribute(flow, "sni", ()), label="sni"
    )
    ja3, ja3_issues = _best_effort_strings(
        _attribute(flow, "ja3", ()), label="ja3"
    )
    alpn, alpn_issues = _best_effort_strings(
        _attribute(flow, "alpn", ()), label="alpn"
    )
    versions, version_issues = _best_effort_strings(
        _attribute(flow, "quic_versions", ()), label="quic_versions"
    )
    dcids, dcid_issues = _best_effort_strings(
        _attribute(flow, "quic_dcids", ()), label="quic_dcids"
    )
    scids, scid_issues = _best_effort_strings(
        _attribute(flow, "quic_scids", ()), label="quic_scids"
    )
    auxiliary_issues = [
        *flag_issues,
        *sni_issues,
        *ja3_issues,
        *alpn_issues,
        *version_issues,
        *dcid_issues,
        *scid_issues,
    ]

    src_entity = _entity(NetworkEntityType.IP, src_ip, source)
    dst_entity = _entity(NetworkEntityType.IP, dst_ip, source)
    domain_entities = [_entity(NetworkEntityType.DOMAIN, domain, source) for domain in sni]
    entities: list[NetworkEntity] = [src_entity, dst_entity, *domain_entities]
    observations: list[Observation] = []
    evidence: list[AttributionEvidence] = []
    flow_attributes: dict[str, Any] = {
        "bytes": bytes_count,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "first_ts": first_ts,
        "flags": flags,
        "last_ts": last_ts,
        "packets": packets,
        "payload_bytes": payload_bytes,
        "protocol": protocol,
        "src_ip": src_ip,
        "src_port": src_port,
    }
    flow_observation = Observation(
        id=_observation_id(
            artifact_id,
            "network_flow",
            {**flow_attributes, "occurrence": occurrence},
            source=source,
            raw_reference=raw_reference,
        ),
        source=source,
        type="network_flow",
        entities=(src_entity, dst_entity),
        attributes=flow_attributes,
        timestamp=first_ts if first_ts > 0 else None,
        raw_reference=raw_reference,
    )
    observations.append(flow_observation)
    evidence.append(
        _new_evidence(
            observation=flow_observation,
            evidence_type="network_flow",
            target=dst_entity,
            value=f"{protocol}/{dst_port}",
        )
    )

    if sni or ja3 or alpn:
        tls_attributes: dict[str, Any] = {
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "ja3": ja3,
            "offered_alpn": alpn,
            "sni": sni,
            "src_ip": src_ip,
            "transport": protocol,
        }
        tls_observation = Observation(
            id=_observation_id(
                artifact_id,
                "tls_client_hello",
                {**tls_attributes, "occurrence": occurrence},
                source=source,
                raw_reference=raw_reference,
            ),
            source=source,
            type="tls_client_hello",
            entities=(src_entity, dst_entity, *domain_entities),
            attributes=tls_attributes,
            timestamp=first_ts if first_ts > 0 else None,
            raw_reference=raw_reference,
        )
        observations.append(tls_observation)
        for domain_entity in domain_entities:
            evidence.append(
                _new_evidence(
                    observation=tls_observation,
                    evidence_type="tls_sni",
                    target=domain_entity,
                    value=dst_ip,
                )
            )

    if versions or dcids or scids:
        quic_attributes: dict[str, Any] = {
            "dcids": dcids,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "offered_alpn": alpn,
            "scids": scids,
            "sni": sni,
            "src_ip": src_ip,
            "src_port": src_port,
            "versions": versions,
        }
        observations.append(
            Observation(
                id=_observation_id(
                    artifact_id,
                    "quic_connection",
                    {**quic_attributes, "occurrence": occurrence},
                    source=source,
                    raw_reference=raw_reference,
                ),
                source=source,
                type="quic_connection",
                entities=(src_entity, dst_entity, *domain_entities),
                attributes=quic_attributes,
                timestamp=first_ts if first_ts > 0 else None,
                raw_reference=raw_reference,
            )
        )
    return entities, observations, evidence, auxiliary_issues


def _normalize_dns_answer(answer: object) -> dict[str, Any]:
    answer_type = _integer("DNS answer type", _attribute(answer, "type"), maximum=65535)
    ttl = _integer("DNS TTL", _attribute(answer, "ttl", 0), maximum=0xFFFFFFFF)
    raw_value = _required_string("DNS answer value", _attribute(answer, "value"))
    if answer_type in {_DNS_A, _DNS_AAAA}:
        value = normalize_ip(raw_value)
    elif answer_type in _DNS_DOMAIN_TYPES:
        value = normalize_domain(raw_value)
    else:
        value = raw_value
    return {"ttl": ttl, "type": answer_type, "value": value}


def _normalize_dns_answers_best_effort(
    value: object,
) -> tuple[list[dict[str, Any]], list[str]]:
    try:
        raw_answers = _iterable("DNS answers", value)
    except (TypeError, ValueError):
        return [], ["answers: ignored invalid collection"]
    answers: list[dict[str, Any]] = []
    invalid = 0
    for answer in raw_answers:
        try:
            answers.append(_normalize_dns_answer(answer))
        except (AttributeError, TypeError, ValueError):
            invalid += 1
    answers.sort(key=lambda answer: (answer["type"], answer["value"], answer["ttl"]))
    issues = [f"answers: ignored {invalid} invalid answer(s)"] if invalid else []
    return answers, issues


def _dns_sort_key(record: object) -> tuple[str, int, int, int, float, str]:
    answers, _answer_issues = _normalize_dns_answers_best_effort(
        _attribute(record, "answers", ())
    )
    answer_text = repr(
        [
            (
                answer["type"],
                answer["value"],
                answer["ttl"],
            )
            for answer in answers
        ]
    )
    timestamp = _timestamp(_attribute(record, "ts", 0.0), allow_none=False)
    if timestamp is None:  # pragma: no cover - guarded above
        raise ValueError("DNS timestamp is required")
    return (
        normalize_domain(
            _required_string("DNS qname", _attribute(record, "qname"))
        ),
        _integer("DNS qtype", _attribute(record, "qtype", 0), maximum=65535),
        _integer("DNS rcode", _attribute(record, "rcode", 0), maximum=65535),
        _integer("DNS txid", _attribute(record, "txid", 0), maximum=65535),
        timestamp,
        answer_text,
    )


def _convert_dns_record(
    record: object,
    *,
    artifact_id: str,
    raw_reference: str | None,
    occurrence: int,
) -> tuple[
    str,
    list[NetworkEntity],
    list[Observation],
    list[AttributionEvidence],
    list[str],
]:
    source = "pcap"
    qname = normalize_domain(_required_string("DNS qname", _attribute(record, "qname")))
    qtype = _integer("DNS qtype", _attribute(record, "qtype"), maximum=65535)
    rcode = _integer("DNS rcode", _attribute(record, "rcode"), maximum=65535)
    txid = _integer("DNS txid", _attribute(record, "txid", 0), maximum=65535)
    ts = _timestamp(_attribute(record, "ts", 0.0), allow_none=False)
    if ts is None:  # pragma: no cover - guarded by allow_none=False
        raise ValueError("DNS timestamp is required")
    answers, answer_issues = _normalize_dns_answers_best_effort(
        _attribute(record, "answers", ())
    )
    qname_entity = _entity(NetworkEntityType.DOMAIN, qname, source)
    entities: list[NetworkEntity] = [qname_entity]
    observations: list[Observation] = []
    evidence: list[AttributionEvidence] = []
    message_attributes: dict[str, Any] = {
        "answers": answers,
        "qname": qname,
        "qtype": qtype,
        "rcode": rcode,
        "txid": txid,
    }
    message_entities: list[NetworkEntity] = [qname_entity]
    for answer in answers:
        answer_type = answer["type"]
        answer_value = answer["value"]
        if answer_type in {_DNS_A, _DNS_AAAA}:
            message_entities.append(_entity(NetworkEntityType.IP, answer_value, source))
        elif answer_type in _DNS_DOMAIN_TYPES:
            message_entities.append(_entity(NetworkEntityType.DOMAIN, answer_value, source))
    message_observation = Observation(
        id=_observation_id(
            artifact_id,
            "dns_message",
            {**message_attributes, "occurrence": occurrence, "timestamp": ts},
            source=source,
            raw_reference=raw_reference,
        ),
        source=source,
        type="dns_message",
        entities=tuple(message_entities),
        attributes=message_attributes,
        timestamp=ts if ts > 0 else None,
        raw_reference=raw_reference,
    )
    observations.append(message_observation)
    entities.extend(message_entities[1:])

    for ordinal, answer in enumerate(answers):
        answer_type = answer["type"]
        answer_value = answer["value"]
        if answer_type in {_DNS_A, _DNS_AAAA}:
            answer_entity = _entity(NetworkEntityType.IP, answer_value, source)
            attributes = {
                "qname": qname,
                "rcode": rcode,
                "record_type": answer_type,
                "ttl": answer["ttl"],
                "txid": txid,
            }
            resolution = Observation(
                id=_observation_id(
                    artifact_id,
                    "dns_resolution",
                    {
                        **attributes,
                        "answer": answer_value,
                        "message_occurrence": occurrence,
                        "ordinal": ordinal,
                        "timestamp": ts,
                    },
                    source=source,
                    raw_reference=raw_reference,
                ),
                source=source,
                type="dns_resolution",
                entities=(qname_entity, answer_entity),
                attributes=attributes,
                timestamp=ts if ts > 0 else None,
                raw_reference=raw_reference,
            )
            observations.append(resolution)
            evidence.append(
                _new_evidence(
                    observation=resolution,
                    evidence_type="dns_resolution",
                    target=answer_entity,
                    value=qname,
                )
            )
        elif answer_type == _DNS_CNAME:
            alias_entity = _entity(NetworkEntityType.DOMAIN, answer_value, source)
            attributes = {
                "alias": answer_value,
                "qname": qname,
                "ttl": answer["ttl"],
                "txid": txid,
            }
            alias_observation = Observation(
                id=_observation_id(
                    artifact_id,
                    "dns_alias",
                    {
                        **attributes,
                        "message_occurrence": occurrence,
                        "ordinal": ordinal,
                        "timestamp": ts,
                    },
                    source=source,
                    raw_reference=raw_reference,
                ),
                source=source,
                type="dns_alias",
                entities=(qname_entity, alias_entity),
                attributes=attributes,
                timestamp=ts if ts > 0 else None,
                raw_reference=raw_reference,
            )
            observations.append(alias_observation)
            evidence.append(
                _new_evidence(
                    observation=alias_observation,
                    evidence_type="dns_alias",
                    target=qname_entity,
                    value=answer_value,
                )
            )
    return qname, entities, observations, evidence, answer_issues


def convert_pcap_summary(
    summary: object,
    *,
    artifact_id: str,
    raw_reference: str | None = None,
) -> ConversionResult:
    """转换内存中的 ``PcapSummary``；不读文件、不修改输入。"""
    clean_artifact_id, clean_reference = _validate_artifact_context(artifact_id, raw_reference)
    if not all(hasattr(summary, name) for name in ("flows", "dns_records", "dns_queries")):
        raise TypeError("summary must expose flows, dns_records, and dns_queries")
    flows = _iterable("summary.flows", _attribute(summary, "flows"))
    dns_records = _iterable("summary.dns_records", _attribute(summary, "dns_records"))
    dns_queries = _iterable("summary.dns_queries", _attribute(summary, "dns_queries"))

    entities: list[NetworkEntity] = []
    observations: list[Observation] = []
    evidence: list[AttributionEvidence] = []
    issues: list[ConversionIssue] = []
    valid_flows: list[tuple[tuple[object, ...], int, object]] = []
    for index, flow in enumerate(flows):
        try:
            key = _flow_sort_key(flow)
        except (AttributeError, TypeError, ValueError) as exc:
            issues.append(ConversionIssue(stage="pcap.flow", index=index, reason=str(exc)))
            continue
        valid_flows.append((key, index, flow))
    flow_occurrences: dict[tuple[object, ...], int] = {}
    for key, original_index, flow in sorted(valid_flows, key=lambda item: item[0]):
        identity_key = key[:11]
        occurrence = flow_occurrences.get(identity_key, 0)
        try:
            (
                new_entities,
                new_observations,
                new_evidence,
                auxiliary_issues,
            ) = _convert_flow(
                flow,
                artifact_id=clean_artifact_id,
                raw_reference=clean_reference,
                occurrence=occurrence,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            issues.append(
                ConversionIssue(stage="pcap.flow", index=original_index, reason=str(exc))
            )
            continue
        flow_occurrences[identity_key] = occurrence + 1
        entities.extend(new_entities)
        observations.extend(new_observations)
        evidence.extend(new_evidence)
        issues.extend(
            ConversionIssue(
                stage="pcap.flow.aux", index=original_index, reason=reason
            )
            for reason in auxiliary_issues
        )

    record_names: set[str] = set()
    valid_records: list[tuple[tuple[str, int, int, int, float, str], int, object]] = []
    for index, record in enumerate(dns_records):
        try:
            key = _dns_sort_key(record)
        except (AttributeError, TypeError, ValueError) as exc:
            issues.append(ConversionIssue(stage="pcap.dns", index=index, reason=str(exc)))
            continue
        valid_records.append((key, index, record))
    dns_occurrences: dict[tuple[str, int, int, int, float, str], int] = {}
    for key, original_index, record in sorted(valid_records, key=lambda item: item[0]):
        occurrence = dns_occurrences.get(key, 0)
        try:
            (
                qname,
                new_entities,
                new_observations,
                new_evidence,
                answer_issues,
            ) = _convert_dns_record(
                record,
                artifact_id=clean_artifact_id,
                raw_reference=clean_reference,
                occurrence=occurrence,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            issues.append(
                ConversionIssue(stage="pcap.dns", index=original_index, reason=str(exc))
            )
            continue
        dns_occurrences[key] = occurrence + 1
        record_names.add(qname)
        entities.extend(new_entities)
        observations.extend(new_observations)
        evidence.extend(new_evidence)
        issues.extend(
            ConversionIssue(
                stage="pcap.dns.answer", index=original_index, reason=reason
            )
            for reason in answer_issues
        )

    normalized_queries: set[str] = set()
    for index, query in enumerate(sorted(dns_queries, key=repr)):
        try:
            normalized_queries.add(normalize_domain(_required_string("DNS query", query)))
        except (TypeError, ValueError) as exc:
            issues.append(ConversionIssue(stage="pcap.dns_query", index=index, reason=str(exc)))
    for query in sorted(normalized_queries - record_names):
        query_entity = _entity(NetworkEntityType.DOMAIN, query, "pcap")
        attributes: dict[str, Any] = {"qname": query}
        observations.append(
            Observation(
                id=_observation_id(
                    clean_artifact_id,
                    "dns_query",
                    attributes,
                    source="pcap",
                    raw_reference=clean_reference,
                ),
                source="pcap",
                type="dns_query",
                entities=(query_entity,),
                attributes=attributes,
                raw_reference=clean_reference,
            )
        )
        entities.append(query_entity)
    return _make_result(
        entities=entities,
        observations=observations,
        evidence=evidence,
        issues=issues,
    )


def _http_context(
    *,
    artifact_id: object,
    source: object,
    scheme: object,
    raw_reference: object,
    timestamp: object,
) -> tuple[str, str, str, str | None, float | None]:
    clean_artifact_id, clean_reference = _validate_artifact_context(artifact_id, raw_reference)
    clean_source = _required_string("source", source)
    clean_scheme = _required_string("scheme", scheme).lower()
    if clean_scheme not in {"http", "https"}:
        raise ValueError("scheme must be http or https")
    return clean_artifact_id, clean_source, clean_scheme, clean_reference, _timestamp(timestamp)


def _safe_headers(headers: object, allowlist: set[str]) -> dict[str, str]:
    if not isinstance(headers, Mapping):
        if not hasattr(headers, "items"):
            raise TypeError("headers must provide items()")
        items_method = cast(Any, getattr(headers, "items"))
        raw_items = list(items_method())
    else:
        raw_items = list(headers.items())
    result: dict[str, str] = {}
    for key, value in raw_items:
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        normalized_key = key.strip().lower()
        if normalized_key in allowlist:
            clean_value = value.strip()
            if normalized_key in {"origin", "referer"}:
                try:
                    clean_value = (
                        sanitize_absolute_url(clean_value)
                        if urllib.parse.urlsplit(clean_value).scheme
                        else sanitize_http_path(clean_value)
                    )
                except (TypeError, ValueError):
                    continue
            result[normalized_key] = clean_value
    return {key: result[key] for key in sorted(result)}


def _header_items(headers: object) -> list[tuple[str, str]]:
    if hasattr(headers, "items"):
        items_method = cast(Any, getattr(headers, "items"))
        try:
            raw_items = list(items_method(multi=True))
        except TypeError:
            raw_items = list(items_method())
    else:
        raise TypeError("headers must provide items()")
    return [
        (key, value)
        for key, value in raw_items
        if isinstance(key, str) and isinstance(value, str)
    ]


def _cookie_names(headers: object) -> list[str]:
    names: set[str] = set()
    for key, value in _header_items(headers):
        if key.strip().lower() != "set-cookie":
            continue
        pair = value.split(";", 1)[0]
        if "=" not in pair:
            continue
        name = pair.split("=", 1)[0].strip()
        if name:
            names.add(name)
    return sorted(names)


def _content_length(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, str):
        return len(value.encode("utf-8"))
    if isinstance(value, (bytes, bytearray, memoryview)):
        return len(value)
    raise TypeError("raw_content must be bytes, string, or None")


def _authority_with_port(host: str, port_value: object, scheme: str) -> str:
    authority, normalized_host, existing_port, is_ip = normalize_authority(host)
    default_port = 443 if scheme == "https" else 80
    if existing_port is not None:
        if existing_port == default_port:
            return f"[{normalized_host}]" if is_ip and ":" in normalized_host else normalized_host
        return authority
    if port_value in (None, "", 0, "0"):
        return authority
    port = _integer("HTTP port", port_value, minimum=1, maximum=65535)
    return authority if port == default_port else f"{authority}:{port}"


def _http_entities(
    *,
    authority: str,
    url: str,
    source: str,
    dst_ip: str | None,
) -> tuple[list[NetworkEntity], NetworkEntity, str, int | None, bool]:
    normalized_authority, host, port, is_ip = normalize_authority(authority)
    host_entity = _entity(NetworkEntityType.HOST, normalized_authority, source)
    entities: list[NetworkEntity] = [host_entity, _entity(NetworkEntityType.URL, url, source)]
    if is_ip:
        entities.append(_entity(NetworkEntityType.IP, host, source))
    else:
        entities.append(_entity(NetworkEntityType.DOMAIN, host, source))
    if dst_ip is not None:
        entities.append(_entity(NetworkEntityType.IP, dst_ip, source))
    return entities, host_entity, host, port, is_ip


def _convert_http_request_item(
    request: object,
    *,
    artifact_id: str,
    source: str,
    scheme: str,
    raw_reference: str | None,
    timestamp: float | None,
    headers: dict[str, str] | None = None,
    content_length: int | None = None,
    authority_override: str | None = None,
    dst_override: tuple[str, int] | None = None,
    occurrence: int = 0,
) -> tuple[list[NetworkEntity], Observation, AttributionEvidence]:
    raw_host = _required_string("HTTP host", _attribute(request, "host"))
    authority = authority_override or _authority_with_port(raw_host, None, scheme)
    normalized_authority, host, port, _is_ip = normalize_authority(authority)
    method = _required_string("HTTP method", _attribute(request, "method", "")).upper()
    raw_uri = _attribute(request, "uri", _attribute(request, "path", "/"))
    if not isinstance(raw_uri, str):
        raise TypeError("HTTP URI must be a string")
    path = sanitize_http_path(raw_uri)
    url = sanitize_absolute_url(f"{scheme}://{normalized_authority}{path}")
    user_agent_value = _attribute(request, "user_agent", "")
    user_agent = user_agent_value if isinstance(user_agent_value, str) else ""

    dst_ip: str | None = None
    dst_port: int | None = None
    if dst_override is not None:
        dst_ip = normalize_ip(dst_override[0])
        dst_port = _integer("dst_port", dst_override[1], maximum=65535)
    else:
        raw_dst_ip = _attribute(request, "dst_ip", "")
        if isinstance(raw_dst_ip, str) and raw_dst_ip.strip():
            dst_ip = normalize_ip(raw_dst_ip.strip())
        raw_dst_port = _attribute(request, "dst_port", "")
        if raw_dst_port not in (None, ""):
            dst_port = _integer("dst_port", raw_dst_port, maximum=65535)

    entities, host_entity, _host, _port, _is_ip = _http_entities(
        authority=normalized_authority,
        url=url,
        source=source,
        dst_ip=dst_ip,
    )
    attributes: dict[str, Any] = {
        "authority": normalized_authority,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "host": host,
        "method": method,
        "path": path,
        "port": port,
        "scheme": scheme,
        "user_agent": user_agent,
    }
    if headers is not None:
        attributes["headers"] = headers
    if content_length is not None:
        attributes["content_length"] = content_length
    observation = Observation(
        id=_observation_id(
            artifact_id,
            "http_request",
            {**attributes, "occurrence": occurrence, "timestamp": timestamp},
            source=source,
            raw_reference=raw_reference,
        ),
        source=source,
        type="http_request",
        entities=tuple(entities),
        attributes=attributes,
        timestamp=timestamp,
        raw_reference=raw_reference,
    )
    evidence = _new_evidence(
        observation=observation,
        evidence_type="http_request",
        target=host_entity,
        value=f"{method} {path}",
    )
    return entities, observation, evidence


def convert_http_requests(
    requests: Iterable[object],
    *,
    artifact_id: str,
    source: str,
    scheme: str,
    raw_reference: str | None = None,
    timestamp: float | None = None,
) -> ConversionResult:
    """转换 tshark 的结构化 HTTP 请求；不会保留 query 或凭据头。"""
    clean_artifact, clean_source, clean_scheme, clean_reference, fallback_ts = _http_context(
        artifact_id=artifact_id,
        source=source,
        scheme=scheme,
        raw_reference=raw_reference,
        timestamp=timestamp,
    )
    request_items = _iterable("requests", requests)
    entities: list[NetworkEntity] = []
    observations: list[Observation] = []
    evidence: list[AttributionEvidence] = []
    issues: list[ConversionIssue] = []
    occurrences: dict[str, int] = {}
    for index, request in enumerate(request_items):
        try:
            item_timestamp_value = _attribute(request, "timestamp", None)
            item_timestamp = (
                _timestamp(item_timestamp_value)
                if item_timestamp_value is not None
                else fallback_ts
            )
            new_entities, observation, new_evidence = _convert_http_request_item(
                request,
                artifact_id=clean_artifact,
                source=clean_source,
                scheme=clean_scheme,
                raw_reference=clean_reference,
                timestamp=item_timestamp,
                occurrence=0,
            )
            occurrence = occurrences.get(observation.id, 0)
            occurrences[observation.id] = occurrence + 1
            if occurrence:
                new_entities, observation, new_evidence = _convert_http_request_item(
                    request,
                    artifact_id=clean_artifact,
                    source=clean_source,
                    scheme=clean_scheme,
                    raw_reference=clean_reference,
                    timestamp=item_timestamp,
                    occurrence=occurrence,
                )
        except (AttributeError, TypeError, ValueError) as exc:
            issues.append(ConversionIssue(stage="http.request", index=index, reason=str(exc)))
            continue
        entities.extend(new_entities)
        observations.append(observation)
        evidence.append(new_evidence)
    return _make_result(
        entities=entities, observations=observations, evidence=evidence, issues=issues
    )


def _peername(flow: object) -> tuple[str, int] | None:
    server_conn = _attribute(flow, "server_conn", None)
    peername = _attribute(server_conn, "peername", None)
    if peername is None:
        return None
    if isinstance(peername, (str, bytes)) or not isinstance(peername, Iterable):
        raise TypeError("server peername must be a pair")
    values = list(peername)
    if len(values) < 2 or not isinstance(values[0], str):
        raise ValueError("server peername must contain IP and port")
    return normalize_ip(values[0]), _integer("peer port", values[1], maximum=65535)


def _sanitize_location(value: str, base_url: str) -> str:
    absolute = urllib.parse.urljoin(base_url, value)
    return sanitize_absolute_url(absolute)


def _mitm_flow_sort_key(flow: object) -> str:
    """Return a privacy-safe key covering every fact emitted for one MITM flow."""
    request = _attribute(flow, "request", None)
    if request is None:
        return stable_digest("mitm-flow-sort", {"request": "missing"})
    try:
        scheme = _required_string("scheme", _attribute(request, "scheme", "http")).lower()
        if scheme not in {"http", "https"}:
            raise ValueError("scheme must be http or https")
        host = _required_string("HTTP host", _attribute(request, "host"))
        authority = _authority_with_port(host, _attribute(request, "port", None), scheme)
        normalized_authority, normalized_host, port, _is_ip = normalize_authority(authority)
        method = _required_string("HTTP method", _attribute(request, "method", "")).upper()
        raw_uri = _attribute(request, "uri", _attribute(request, "path", "/"))
        if not isinstance(raw_uri, str):
            raise TypeError("HTTP URI must be a string")
        path = sanitize_http_path(raw_uri)
        request_headers = _safe_headers(
            _attribute(request, "headers", {}), _REQUEST_HEADER_ALLOWLIST
        )
        request_ts = _timestamp(_attribute(request, "timestamp_start", None))
        peer = _peername(flow)
        request_content_length = _content_length(
            _attribute(request, "raw_content", None)
        )
        user_agent_value = _attribute(request, "user_agent", "")
        user_agent = user_agent_value if isinstance(user_agent_value, str) else ""
    except (AttributeError, TypeError, ValueError):
        return stable_digest("mitm-flow-sort", {"request": "invalid"})

    request_url = sanitize_absolute_url(
        f"{scheme}://{normalized_authority}{path}"
    )
    request_facts: dict[str, Any] = {
        "authority": normalized_authority,
        "content_length": request_content_length,
        "dst": list(peer) if peer is not None else None,
        "headers": request_headers,
        "host": normalized_host,
        "method": method,
        "path": path,
        "port": port,
        "scheme": scheme,
        "timestamp": request_ts,
        "user_agent": user_agent,
    }

    response = _attribute(flow, "response", None)
    if response is None:
        response_facts: dict[str, Any] | None = None
    else:
        try:
            status = _integer(
                "HTTP status", _attribute(response, "status_code"), maximum=999
            )
            raw_response_headers = _attribute(response, "headers", {})
            response_headers = _safe_headers(
                raw_response_headers, _RESPONSE_HEADER_ALLOWLIST
            )
            location_value = response_headers.get("location")
            sanitized_location: str | None = None
            if location_value:
                try:
                    sanitized_location = _sanitize_location(location_value, request_url)
                except (TypeError, ValueError):
                    response_headers.pop("location", None)
                else:
                    response_headers["location"] = sanitized_location
            response_facts = {
                "content_length": _content_length(
                    _attribute(response, "raw_content", None)
                ),
                "headers": response_headers,
                "redirect": sanitized_location if 300 <= status < 400 else None,
                "set_cookie_names": _cookie_names(raw_response_headers),
                "status": status,
                "timestamp": _timestamp(_attribute(response, "timestamp_start", None)),
            }
        except (AttributeError, TypeError, ValueError):
            response_facts = {"invalid": True}

    return stable_digest(
        "mitm-flow-sort", {"request": request_facts, "response": response_facts}
    )


def convert_mitmproxy_flows(
    flows: Iterable[object],
    *,
    artifact_id: str,
    raw_reference: str | None = None,
) -> ConversionResult:
    """转换 mitmproxy flow 对象；只保存白名单头和 Set-Cookie 名。"""
    clean_artifact, clean_reference = _validate_artifact_context(artifact_id, raw_reference)
    flow_items = _iterable("flows", flows)
    entities: list[NetworkEntity] = []
    observations: list[Observation] = []
    evidence: list[AttributionEvidence] = []
    issues: list[ConversionIssue] = []
    occurrences: dict[str, int] = {}
    sorted_flows = sorted(
        ((_mitm_flow_sort_key(flow), index, flow) for index, flow in enumerate(flow_items)),
        key=lambda item: item[0],
    )
    for _sort_key, index, flow in sorted_flows:
        try:
            request = _attribute(flow, "request", None)
            if request is None:
                raise ValueError("mitm flow has no request")
            scheme = _required_string("scheme", _attribute(request, "scheme", "http")).lower()
            if scheme not in {"http", "https"}:
                raise ValueError("scheme must be http or https")
            host = _required_string("HTTP host", _attribute(request, "host"))
            authority = _authority_with_port(host, _attribute(request, "port", None), scheme)
            request_headers = _safe_headers(
                _attribute(request, "headers", {}), _REQUEST_HEADER_ALLOWLIST
            )
            request_ts = _timestamp(_attribute(request, "timestamp_start", None))
            peer = _peername(flow)
            request_content_length = _content_length(_attribute(request, "raw_content", None))
            new_entities, request_observation, request_evidence = _convert_http_request_item(
                request,
                artifact_id=clean_artifact,
                source="mitmproxy",
                scheme=scheme,
                raw_reference=clean_reference,
                timestamp=request_ts,
                headers=request_headers,
                content_length=request_content_length,
                authority_override=authority,
                dst_override=peer,
                occurrence=0,
            )
            occurrence = occurrences.get(request_observation.id, 0)
            occurrences[request_observation.id] = occurrence + 1
            if occurrence:
                new_entities, request_observation, request_evidence = _convert_http_request_item(
                    request,
                    artifact_id=clean_artifact,
                    source="mitmproxy",
                    scheme=scheme,
                    raw_reference=clean_reference,
                    timestamp=request_ts,
                    headers=request_headers,
                    content_length=request_content_length,
                    authority_override=authority,
                    dst_override=peer,
                    occurrence=occurrence,
                )
            entities.extend(new_entities)
            observations.append(request_observation)
            evidence.append(request_evidence)

            response = _attribute(flow, "response", None)
            if response is None:
                continue
            status = _integer("HTTP status", _attribute(response, "status_code"), maximum=999)
            raw_response_headers = _attribute(response, "headers", {})
            response_headers = _safe_headers(
                raw_response_headers, _RESPONSE_HEADER_ALLOWLIST
            )
            request_url = next(
                item.value for item in new_entities if item.kind is NetworkEntityType.URL
            )
            location_value = response_headers.get("location")
            sanitized_location: str | None = None
            if location_value:
                try:
                    sanitized_location = _sanitize_location(location_value, request_url)
                except (TypeError, ValueError) as exc:
                    response_headers.pop("location", None)
                    issues.append(
                        ConversionIssue(
                            stage="mitm.redirect", index=index, reason=str(exc)
                        )
                    )
                else:
                    response_headers["location"] = sanitized_location
            cookie_names = _cookie_names(raw_response_headers)
            response_ts = _timestamp(_attribute(response, "timestamp_start", None))
            response_attributes: dict[str, Any] = {
                "headers": response_headers,
                "request_observation_id": request_observation.id,
                "set_cookie_names": cookie_names,
                "status": status,
            }
            response_content_length = _content_length(
                _attribute(response, "raw_content", None)
            )
            if response_content_length is not None:
                response_attributes["content_length"] = response_content_length
            host_entity = next(
                item for item in new_entities if item.kind is NetworkEntityType.HOST
            )
            response_entities = [host_entity]
            response_observation = Observation(
                id=_observation_id(
                    clean_artifact,
                    "http_response",
                    {
                        **response_attributes,
                        "timestamp": response_ts,
                    },
                    source="mitmproxy",
                    raw_reference=clean_reference,
                ),
                source="mitmproxy",
                type="http_response",
                entities=tuple(response_entities),
                attributes=response_attributes,
                timestamp=response_ts,
                raw_reference=clean_reference,
            )
            observations.append(response_observation)
            evidence.append(
                _new_evidence(
                    observation=response_observation,
                    evidence_type="http_response",
                    target=host_entity,
                    value=status,
                )
            )

            if sanitized_location is not None and 300 <= status < 400:
                parsed = urllib.parse.urlsplit(sanitized_location)
                target_authority, target_host, _target_port, target_is_ip = normalize_authority(
                    parsed.netloc
                )
                target_url = _entity(
                    NetworkEntityType.URL, sanitized_location, "mitmproxy"
                )
                target_host_entity = _entity(
                    NetworkEntityType.HOST, target_authority, "mitmproxy"
                )
                target_entity = _entity(
                    NetworkEntityType.IP if target_is_ip else NetworkEntityType.DOMAIN,
                    target_host,
                    "mitmproxy",
                )
                redirect_attributes = {
                    "location": sanitized_location,
                    "request_observation_id": request_observation.id,
                    "status": status,
                }
                redirect_observation = Observation(
                    id=_observation_id(
                        clean_artifact,
                        "http_redirect",
                        {
                            **redirect_attributes,
                            "timestamp": response_ts,
                        },
                        source="mitmproxy",
                        raw_reference=clean_reference,
                    ),
                    source="mitmproxy",
                    type="http_redirect",
                    entities=(host_entity, target_url, target_host_entity, target_entity),
                    attributes=redirect_attributes,
                    timestamp=response_ts,
                    raw_reference=clean_reference,
                )
                entities.extend([target_url, target_host_entity, target_entity])
                observations.append(redirect_observation)
                evidence.append(
                    _new_evidence(
                        observation=redirect_observation,
                        evidence_type="http_redirect",
                        target=host_entity,
                        value=sanitized_location,
                    )
                )
        except (AttributeError, StopIteration, TypeError, ValueError) as exc:
            issues.append(ConversionIssue(stage="mitm.flow", index=index, reason=str(exc)))
    return _make_result(
        entities=entities, observations=observations, evidence=evidence, issues=issues
    )


def merge_conversion_results(*results: ConversionResult) -> ConversionResult:
    """以交换、幂等方式合并转换结果并显式合并实体来源。"""
    entities: list[NetworkEntity] = []
    observations: list[Observation] = []
    evidence: list[AttributionEvidence] = []
    issues: list[ConversionIssue] = []
    for result in results:
        if not isinstance(result, ConversionResult):
            raise TypeError("all results must be ConversionResult")
        entities.extend(result.entities)
        observations.extend(result.observations)
        evidence.extend(result.evidence)
        issues.extend(result.issues)
    return _make_result(
        entities=entities, observations=observations, evidence=evidence, issues=issues
    )
