from pathlib import Path
import importlib
import sys
import unittest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

try:
    slack = importlib.import_module('sscv.hidden_event_bounds')
    from sscv import sensitivity_base as e7old
    from sscv import order_freedom as ofm
except ModuleNotFoundError:
    slack = None
    e7old = None
    ofm = None


class HiddenEventSlackV13Tests(unittest.TestCase):
    def require_module(self):
        self.assertIsNotNone(slack, 'hidden_event_bounds must exist')

    def deletion_cell(self):
        group = e7old.first_group_for_mechanism('deletion')
        row = next(item for item in group if item['variant'] == 'B0')
        return e7old.build_variant(row)['cell']

    def none_cell(self):
        group = e7old.first_group_for_mechanism('none')
        row = next(item for item in group if item['variant'] == 'B0')
        return e7old.build_variant(row)['cell']

    def test_materialize_exact_slack_preserves_existing_deletion_template(self):
        self.require_module()
        cell = self.deletion_cell()
        original = cell.spec.optional_deleted_events
        self.assertEqual(len(original), 1)
        two = slack.materialize_hidden_event_templates(cell, 2)
        three = slack.materialize_hidden_event_templates(cell, 3)
        self.assertEqual(len(two), 2)
        self.assertEqual(len(three), 3)
        self.assertEqual(two[0], original[0])
        self.assertEqual(three[:2], two)

    def test_non_deletion_slack_is_neutral_and_nested(self):
        self.require_module()
        cell = self.none_cell()
        two = slack.materialize_hidden_event_templates(cell, 2)
        three = slack.materialize_hidden_event_templates(cell, 3)
        self.assertEqual(len(two), 2)
        self.assertEqual(three[:2], two)
        self.assertTrue(all(t.event.activity == slack.NEUTRAL_ACTIVITY for t in three))
        self.assertTrue(all(t.event.case_ids == () for t in three))
        motif_activities = slack.motif_activity_set(cell.motif)
        self.assertTrue(all(t.event.activity not in motif_activities for t in three))

    def test_contract_covers_templates_and_excludes_fillers_from_free_pairs(self):
        self.require_module()
        cell = self.deletion_cell()
        templates = slack.materialize_hidden_event_templates(cell, 3)
        contract = slack.build_order_contract(cell, templates, 4)
        visible = {str(row.event_id) for row in cell.view.rows}
        optional = {str(t.event.event_id) for t in templates}
        self.assertEqual(set(contract['reference_order']), visible | optional)
        filler_ids = set(slack.slack_filler_ids(templates))
        for left, right in contract['eligible_pairs']:
            self.assertNotIn(left, filler_ids)
            self.assertNotIn(right, filler_ids)
        for left, right in contract['selected_pairs']:
            self.assertNotIn(left, filler_ids)
            self.assertNotIn(right, filler_ids)

    def test_e11_declared_slack_can_be_materialized_at_1_2_3(self):
        self.require_module()
        rows = ofm._load(ofm.E11_MATRIX)['cells']
        seen = set()
        for target in (1, 2, 3):
            row = next(r for r in rows if int(r['hidden_event_slack']) == target and r['mechanism'] == 'none')
            cell = ofm.build_e11_cell(row)
            templates = slack.materialize_hidden_event_templates(cell, target)
            self.assertEqual(len(templates), target)
            seen.add(target)
        self.assertEqual(seen, {1, 2, 3})


if __name__ == '__main__':
    unittest.main()
