from dataclasses import replace

import pytest

from hook_monitor.evaluation.flow_forecast.dataset import assemble, read_dataset, write_dataset
from hook_monitor.evaluation.flow_forecast.prefix import ForecastDataError
from research.flow_forecast import partition_bundle
from test_flow_forecast_task_catalog import dataset


def planned(root, group='group', partition='train', snapshot=None):
    data=dataset(root,snapshot)
    return assemble(data.branches,planned=('a'*64,((root,group,partition),)))


def test_root_changes_do_not_change_predeclared_group_or_partition(tmp_path):
    first=planned('one',partition='test')
    second=planned('two',partition='test')
    assert {(g,p) for _,g,p in first.split.assignments} == {(g,p) for _,g,p in second.split.assignments}
    write_dataset(first,tmp_path/'data')
    assert read_dataset(tmp_path/'data') == first
    with pytest.raises(ForecastDataError):
        replace(first,split=replace(first.split,root_assignments=(('one','group','train'),)))


def test_snapshot_equivalence_cannot_cross_declared_groups():
    first=dataset('one','same')
    second=dataset('two','same')
    with pytest.raises(ForecastDataError,match='related_group_conflict'):
        assemble(first.branches+second.branches,planned=('a'*64,(('one','a','train'),('two','b','test'))))


def test_planned_partition_bundle_preserves_assignments(tmp_path):
    pieces=[planned('one','a','train'),planned('two','b','calibration'),planned('three','c','test')]
    combined=partition_bundle.combine(tuple(pieces))
    partition_bundle.write_bundle(combined,tmp_path/'bundle')
    manifest=partition_bundle.read_manifest(tmp_path/'bundle')
    loaded=[partition_bundle.read_partition(tmp_path/'bundle',manifest,p) for p in ('train','calibration','test')]
    restored=partition_bundle.combine(tuple(loaded))
    assert restored.split == combined.split
    with pytest.raises(ForecastDataError,match='inconsistent_cohort_plan'):
        partition_bundle.combine((pieces[0],dataset('legacy')))


def test_missing_duplicate_or_conflicting_root_assignments_refused():
    data=dataset('one')
    for rows in ((),(('other','group','train'),),(('one','group','train'),('one','group','test'))):
        with pytest.raises(ForecastDataError):
            assemble(data.branches,planned=('a'*64,rows))
