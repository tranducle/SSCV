from __future__ import annotations

from typing import Any

from . import completion_models as fb
from . import explicit_oracle as explicit
from . import witness_validation as iwv
from . import order_management_runner as public
from . import smt_verifier as smt
ALT_ITEM_ID = '__OM_V2_SCHEMA_ALT_ITEM__'
BOUND_ID = 'OM8428112_M2_PACKAGE_PICK_RSCHEMA_B1'


def schema_mode(audit: public.RObsAudit) -> str:
    if audit.constructor_id == 'CV-R1':
        return 'R_SCHEMA_VISIBLE_PICK_BINDING_PLUS_ONE_ITEM'
    return 'R_SCHEMA_NO_ADDITIONAL_VISIBLE_BINDING_EXPANSION'


def schema_spec(audit: public.RObsAudit) -> fb.Spec:
    if audit.constructor_id != 'CV-R1':
        return audit.spec
    widened = []
    control_set = set(audit.control_event_ids)
    for event_id, choices in audit.spec.hidden_binding_domains:
        choices = tuple(tuple(str(value) for value in choice) for choice in choices)
        if str(event_id) in control_set:
            if len(choices) != 1 or len(choices[0]) != 1:
                raise ValueError(f'expected one exact source item binding for {event_id}: {choices}')
            widened.append((str(event_id), (choices[0], (ALT_ITEM_ID,))))
        else:
            widened.append((str(event_id), choices))
    return fb.Spec(
        hidden_binding_domains=tuple(widened),
        hidden_relation_domain=tuple(audit.spec.hidden_relation_domain),
        optional_deleted_events=tuple(audit.spec.optional_deleted_events),
        max_completions=audit.spec.max_completions,
        reference_order=audit.spec.reference_order,
        order_free_pairs=audit.spec.order_free_pairs,
        required_deleted_event_ids=tuple(getattr(audit.spec, 'required_deleted_event_ids', ())),
    )


def verify_explicit_schema(audit: public.RObsAudit):
    return explicit.verify_explicit(audit.view, schema_spec(audit), audit.motif)


def verify_smt_schema(audit: public.RObsAudit):
    return smt.verify_smt(audit.view, schema_spec(audit), audit.motif, query_order=('safe', 'violation'))


def validate_schema_witness(audit: public.RObsAudit, result: Any):
    if result.witness is None:
        raise ValueError('schema result has no witness')
    return iwv.validate_witness(
        audit.view,
        schema_spec(audit),
        audit.motif,
        result.witness.safe_execution,
        result.witness.violating_execution,
    )
