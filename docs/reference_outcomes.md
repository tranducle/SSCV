# Reference outcomes

These values are the frozen reference outcomes for the experiments reported in **Assessing Case-Centric Views for Security Analysis in Enterprise Information Systems**. Runtime values may vary by host. Semantic decisions, frozen denominators, paired transitions, and witness validity are the primary replication criteria.

## Controlled paired-view study

- 648 cells from 324 paired executions.
- Decisions: 162 sound, 486 unsound, 0 unknown.
- 486 ambiguity witnesses returned, with 0 invalid witnesses.
- Paired transitions: 54 sound-to-sound, 0 sound-to-unsound, 54 unsound-to-sound, and 216 unsound-to-unsound.

## Context restoration

Primary single-mechanism restoration:

- binding context: 18/18 restored.
- relation context: 18/18 restored.
- order context: 9/9 restored.
- deleted-event context: 18/18 restored.

Supplementary joint restoration: 18/18.

## Bounded sensitivity

- 108 bases x 5 variants = 540 rows.
- 0 unknown outcomes and 0 invalid witnesses.
- Expanding the hidden-event candidate capacity from 2 to 3 occurs for 108/108 paired settings in the corresponding expansion.
- No sound-to-unsound transitions occur for the four one-step expansions tested.

## Procure-to-Payment public-source study

Evaluation sample:

- 500 anchors x 2 views = 1,000 rows.
- Direct view: 158 sound, 342 unsound, 0 unknown.
- Relation-aware view: 500 sound, 0 unsound, 0 unknown.
- Paired sound-rate change: 0.684.

Cluster bootstrap:

- 420 overlap clusters.
- 2,000 replicates with seed 20260911.
- Delta-sound percentile interval approximately [0.6343361205, 0.7334742578].

Schema stress sample, 100 nested anchors:

- Direct view: 26 sound-to-unsound and 74 unsound-to-unsound.
- Relation-aware view: 100 sound-to-sound.

## Order Management public-source study

Evaluation sample:

- 500 anchors x 2 views = 1,000 rows.
- Direct view: 500/500 unsound.
- Relation-aware view: 500/500 sound.
- Paired transition: 500/500 unsound-to-sound.

Schema stress sample, 100 nested anchors:

- Direct view: 100/100 unsound-to-unsound.
- Relation-aware view: 100/100 sound-to-unsound.
- Every returned schema-stress witness validates independently.

## Witness study

- 30/30 explicit-oracle and SMT decisions/verdict-existence sets agree.
- 30/30 returned exact-subset witnesses validate.
- 26/30 SMT witness objectives equal the exact global-minimum objective.

The study does not claim universal witness minimality.

## Bounded scaling

Primary denominator: 216 cells, with 36 cells at each visible-event size 4, 8, 12, 16, 24, and 32.

- 36/36 operationally complete at every size.
- 0 unknown primary decisions.
- Hidden-event candidate counts: 1, 1, 2, 2, 3, 3 across the six size tiers.
- 36/36 predeclared witness-overhead cells measured with valid witnesses.

Reference runtime at visible-event size 32 on the reviewed host:

- median approximately 0.06036 s.
- p95 approximately 0.07375 s.

Runtime is hardware-dependent and is not an exact replication equality criterion.
