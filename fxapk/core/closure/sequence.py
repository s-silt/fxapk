"""Pure bounded projection of capture rounds; never add evidence across rounds."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy


def evaluate_sequence(records: object, evaluate: Callable[[Mapping[str, object]], dict[str, object]]) -> dict[str, object]:
    if not isinstance(records, list) or not 1 <= len(records) <= 3:
        result = evaluate({})
        result.update(dynamic_status='failed', reason='invalid_capture_sequence',
                      sequence_collection_status='failed', quality_input_source='capture_rounds')
        return result
    qualities: list[tuple[str, dict[str, object], bool]] = []
    gaps: list[str] = []
    not_applicable: list[str] = []
    seen_hashes: set[str] = set()
    for i, row in enumerate(records, 1):
        ref = f'round-{i}'
        if not isinstance(row, Mapping):
            gaps.append(ref)
            continue
        if (row.get('kind') == 'targeted' and row.get('status') == 'skipped'
                and row.get('reason') == 'unpacked_evidence_or_supported_targeted_hook_missing'):
            not_applicable.append(ref)
            continue
        raw = row.get('quality_after_merge')
        raw = dict(raw) if isinstance(raw, Mapping) else {}
        raw.pop('sequence_rounds', None)
        quality = evaluate(raw)
        digest = row.get('runtime_report_sha256')
        sample_hash = row.get('sample_sha256')
        sample_bound = (isinstance(sample_hash, str) and len(sample_hash) == 64
                        and all(c in '0123456789abcdef' for c in sample_hash)
                        and sample_hash == row.get('original_sample_sha256'))
        duplicate = isinstance(digest, str) and digest in seen_hashes
        if isinstance(digest, str):
            seen_hashes.add(digest)
        verified = (sample_bound and not duplicate and row.get('artifact_verified') is True and row.get('merge_status') == 'done'
                    and isinstance(digest, str) and len(digest) == 64
                    and all(c in '0123456789abcdef' for c in digest)
                    and row.get('identity_which') == 'original'
                    and row.get('runtime_variant') == 'original-runtime'
                    and row.get('package_matches') is True)
        if not verified or row.get('status') != 'done' or quality.get('dynamic_status') != 'complete':
            gaps.append(ref)
        qualities.append((ref, quality, verified))
    # Copy a single observation, never create bidirectional/attributed proof by OR.
    def rank(item: tuple[str, dict[str, object], bool]) -> tuple[int, int]:
        _, quality, verified = item
        status = quality.get('dynamic_status')
        return (int(verified), {'complete': 2, 'partial': 1}.get(str(status), 0))
    selected = max(qualities, key=rank) if qualities else None
    result: dict[str, object] = dict(selected[1]) if selected else evaluate({})
    proof_refs = [ref for ref, q, valid in qualities if valid and q.get('dynamic_status') == 'complete']
    observed = any(q.get('dynamic_status') in ('complete', 'partial') for _, q, _ in qualities)
    status = 'complete' if proof_refs and not gaps else ('partial' if observed else 'failed')
    if selected and not selected[2]:
        result['capture_apk_identity_which'] = 'unknown'
    result.update(dynamic_status=status, reason='capture_rounds_evaluated_independently',
                  sequence_collection_status='complete' if not gaps and qualities else 'partial',
                  sequence_business_evidence_status='complete' if proof_refs else ('partial' if observed else 'failed'),
                  proof_round_refs=proof_refs, incomplete_round_refs=gaps,
                  not_applicable_round_refs=not_applicable,
                  selected_round_ref=selected[0] if selected else None,
                  quality_input_source='capture_rounds', sequence_rounds=deepcopy(records))
    return result
