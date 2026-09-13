# SSCV Amendment V1.3: Hidden-Event Slack Operational Repair

Date: 2026-09-11
Status: FROZEN AFTER REVIEW, BEFORE CORRECTIVE E7/E11 OUTCOMES
Trigger: independent pre-G7 experiment review

## 1. Defect being repaired

The frozen E7 and E11 matrices declare `hidden_event_slack`, but V1.2 execution code did not materialize that bound into the completion event universe. The generator exposed at most one mechanism-specific optional deleted event, while E7 declared slack 2/3 and E11 declared slack 1/2/3.

Historical E7 V1.2 and E11 V1.2 artifacts remain immutable. They are not deleted or overwritten. Their realized results remain usable only inside the narrower workload they actually executed.

## 2. Operational semantics of hidden-event slack

For corrective V1.3 synthetic E7/E11 runs, `hidden_event_slack = k` means:

- the completion specification contains exactly `k` distinct hidden-event candidate templates;
- every candidate is independently optional, so a completion may contain any subset of the `k` candidates;
- if the original frozen mechanism already supplies a motif-relevant optional deleted event, that event is retained as the first candidate and counts toward `k`;
- the remaining candidates required to reach `k` are deterministic motif-neutral slack events;
- motif-neutral slack events use an activity label that does not match any SMF-1 motif activity in the cell and therefore cannot create or remove a motif verdict solely by their activity;
- motif-neutral slack events receive deterministic unique IDs and latent object IDs and have no case assignment.

This repair tests the declared completion-event capacity without silently changing the frozen ambiguity-mechanism condition. In deletion cells, the original motif-relevant deleted event remains active exactly as before. In non-deletion cells, additional event slack increases completion-state size but remains motif-neutral.

## 3. Isolation from order freedom

Synthetic slack-fill events must not alter the declared order-freedom factor.

- Each filler receives a deterministic reference-order position after the original completion event universe.
- Order-free pair selection excludes every pair containing a V1.3 slack-fill event.
- Existing visible and mechanism-specific optional events remain eligible under the same priority rule used by V1.2.
- Therefore E7 `B+E` changes only hidden-event candidate capacity, while E7 `B+P` changes only selected order-free pairs.

## 4. E7 corrective contract

Reuse the exact 108 frozen E7 base cells and exact five variants from `E7_BOUND_SENSITIVITY_MATRIX_V1_1.json`.

- B0 materializes exactly 2 optional hidden-event candidates.
- B+E materializes exactly 3 candidates.
- B+O/B+R/B+P materialize exactly 2 candidates.
- All other frozen factor values, base cell IDs, pair seeds, motifs, case views, and source generators remain unchanged.
- A V1.3 structural qualification gate must prove 108/108 B+E variants have exactly one more hidden-event candidate than their paired B0 and that all non-E dimensions are unchanged.

## 5. E11 corrective contract

Reuse the exact 216 frozen E11 cell identities, visible-event sizes, motif/view/mechanism/replicate assignments, and resource envelope from `E11_SCALING_MATRIX_V1_1.json`.

- sizes 4/8 materialize exactly 1 hidden-event candidate per cell;
- sizes 12/16 materialize exactly 2;
- sizes 24/32 materialize exactly 3;
- the same six warmups, timing-sentinel rule, staircase advance rule, 30-second existence-query budget, 60-second witness-materialization budget, one solver thread, and 16 GiB process envelope remain in force;
- no result from V1.2 is used to change cell selection, timeouts, bounds, or stopping rules.

## 6. Claim boundary

V1.3 supersedes V1.2 only for claims that depend on the declared hidden-event slack dimension or the combined E11 workload that includes it. Historical V1.2 outputs remain provenance evidence.

Neutral filler events measure capacity/search-space burden while preserving mechanism isolation. They do not support a claim that arbitrary hidden security-relevant event types were exhaustively modeled.

## 7. Anti-rescue rule

The V1.3 repair is defect-driven, not outcome-driven. Corrective results must be reported even if they weaken earlier runtime or sensitivity conclusions. Unknowns, timeouts, and failed staircase tiers remain in the denominator and may not be replaced.
