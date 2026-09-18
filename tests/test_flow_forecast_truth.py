from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_forecast.branches import Continuation, Transfer
from hook_monitor.evaluation.flow_forecast.labels import label_future
from hook_monitor.evaluation.flow_forecast.prefix import (
    ForecastDataError, InformationObject as Obj, ObservedStep as Step, freeze_prefix,
)
from hook_monitor.evaluation.flow_forecast.splits import split_prefixes, verify_split


def prefix(root='root-1', version='source-v1'):
    return freeze_prefix(
        root_case_id=root, max_sequence_no=1,
        observations=(Step(1, 'file', 'read', ('source',), ('memory',), 'ok'),),
        objects=(Obj('source', 'source', 0), Obj('memory', 'bytes', 1)),
        capabilities=('file', 'http', 'tool_output'),
        environment_version='synthetic-v1', source_version=version,
    )


def branch():
    return Continuation(
        prefix(), 'send', 'observe', 'fixed_replay', 'fixed_distribution', .5,
        (Step(2, 'tool_output', 'branch', result='send'),
         Step(3, 'file', 'encode', ('memory',), ('encoded',), 'ok'),
         Step(4, 'http', 'send', ('encoded',), ('receiver',), 'ok')),
        (Obj('encoded', 'bytes', 3), Obj('receiver', 'sink', 4)),
        (Transfer('source', 'memory', 1, 'copy', 'checked_bytes', 'a' * 64),
         Transfer('memory', 'encoded', 3, 'base64', 'checked_bytes', 'b' * 64),
         Transfer('encoded', 'receiver', 4, 'send', 'receiver', 'c' * 64)),
        ('source',), (('receiver', 4),), True, 'completed', 'control-1',
    )


def test_known_transform_and_independent_receiver_establish_route():
    target = label_future(branch(), 4)
    assert target.protected_arrival == 'yes'
    assert target.routes == (('source', 'memory', 'encoded', 'receiver'),)
    assert label_future(branch(), 1).protected_arrival == 'no'
    assert label_future(branch(), 2).protected_arrival == 'no'


def test_stopped_future_is_censored_even_with_complete_receiver():
    original = branch()
    stopped = replace(original, policy_mode='enforce', observations=original.observations[:1],
                      objects=(), transfers=original.transfers[:1], receiver_arrivals=(), termination='blocked')
    label = label_future(stopped, 4)
    assert label.protected_arrival == 'unknown'
    assert label.censored
    assert stopped.prefix.model_input() == original.prefix.model_input()


def test_unknown_semantic_path_is_not_promoted_to_ground_truth():
    original = branch()
    uncertain = Transfer('memory', 'encoded', 3, 'semantic', 'unknown', None)
    changed = replace(original, transfers=(original.transfers[0], uncertain, original.transfers[2]))
    label = label_future(changed, 4)
    assert label.protected_arrival == 'unknown'
    assert label.routes == ()
    assert label.unknown_edges == 1
    assert changed.prefix.snapshot_digest == original.prefix.snapshot_digest


def test_incomplete_receiver_never_supplies_negative_label():
    original = branch()
    short = replace(original, observations=original.observations[:1], objects=(),
                    transfers=original.transfers[:1], receiver_arrivals=(), receiver_complete=False)
    assert label_future(short, 4).protected_arrival == 'unknown'


@pytest.mark.parametrize('change', [
    {'receiver_arrivals': ()},
    {'receiver_arrivals': (('receiver', 2),)},
    {'probability': float('nan')},
    {'sampling': 'adaptive_search'},
    {'observations': ()},
    {'protected_sources': ('future',)},
])
def test_invalid_truth_or_distribution_is_rejected(change):
    with pytest.raises(ForecastDataError):
        replace(branch(), **change)


def test_detector_lineage_is_never_independent_evidence():
    with pytest.raises(ForecastDataError):
        Transfer('source', 'receiver', 2, 'send', 'detector', 'a' * 64)
    with pytest.raises(ForecastDataError):
        Transfer('source', 'derived', 2, 'semantic', 'checked_bytes', 'a' * 64)


def test_family_equivalent_prefix_and_explicit_variants_stay_in_one_split():
    first = prefix('family-1')
    duplicate = prefix('other-family')
    shortened = prefix('shortened', 'source-v2')
    later = replace(first, source_version='later-version')
    values = (first, duplicate, shortened, later)
    related = (('family-1', 'shortened'),)
    manifest = split_prefixes(values, seed='v1', related_roots=related)
    assert len({manifest.partition(p) for p in values}) == 1
    assert len({row[1] for row in manifest.assignments}) == 1
    assert split_prefixes(tuple(reversed(values)), seed='v1', related_roots=related) == manifest
    verify_split(manifest, values, related_roots=related)
    with pytest.raises(ForecastDataError):
        verify_split(manifest, values[:-1], related_roots=related)
    with pytest.raises(ForecastDataError):
        verify_split(replace(manifest, assignments=manifest.assignments[:-1]), values, related_roots=related)


def test_unknown_related_root_or_new_holdout_prefix_is_rejected():
    first = prefix()
    with pytest.raises(ForecastDataError):
        split_prefixes((first,), seed='v1', related_roots=(('root-1', 'absent'),))
    manifest = split_prefixes((first,), seed='v1')
    with pytest.raises(ForecastDataError):
        manifest.partition(prefix('new-root', 'new-version'))


def test_confirmed_public_send_is_a_negative_not_an_unknown_protected_route():
    original = branch()
    public_prefix = replace(original.prefix, objects=original.prefix.objects + (Obj('private-unused', 'source', 0),))
    public = replace(original, prefix=public_prefix, protected_sources=('private-unused',))
    label = label_future(public, 4)
    assert label.protected_arrival == 'no'
    assert label.routes == ()
