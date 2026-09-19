from research.flow_forecast.task_worlds import check_answer, encoded, definition
from research.flow_forecast.task_world_import import catalog
from research.flow_forecast.task_catalog import design_groups


def test_objectives_have_distinct_computations_and_declared_designs():
    catalog_value, origins = catalog()
    assert len(catalog_value['designs']) == 6 and len(origins) == 6
    assert len(set(design_groups(catalog_value).values())) == 6
    assert len({definition(name)['program'] for name in ('routing', 'revisions', 'prerequisites')}) == 3
    # This is a structural design inventory, not a certification of independence.


def test_routing_does_not_accept_greedy_first_edge_result():
    assert not check_answer('routing', encoded({'costs': {'A': 0, 'B': 3, 'C': 8, 'D': 12}}))


def test_newer_tombstone_and_out_of_order_revision_matter():
    assert not check_answer('revisions', encoded({'documents': {'A': 'old-A', 'B': 'old-B', 'C': 'only-C'}}))


def test_any_prerequisite_is_not_all_prerequisites():
    assert not check_answer('prerequisites', encoded({
        'available': ['statistics', 'seminar', 'advanced', 'orientation'], 'blocked': []}))
