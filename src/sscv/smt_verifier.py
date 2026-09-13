from __future__ import annotations

from dataclasses import dataclass
from ctypes import CDLL, byref, c_char_p, c_uint, c_void_p
from ctypes.util import find_library
import re
from typing import Any, Iterable


@dataclass(frozen=True)
class SMTEvent:
    event_id: str
    activity: str
    actor: str | None
    case_ids: tuple[str, ...] = ()
    hidden_objects: tuple[str, ...] = ()


@dataclass(frozen=True)
class SMTExecution:
    events: tuple[SMTEvent, ...]
    order: tuple[str, ...]
    hidden_relations: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class SMTWitness:
    safe_execution: SMTExecution
    violating_execution: SMTExecution
    valid: bool
    minimal: bool = False


@dataclass(frozen=True)
class SMTVerificationResult:
    decision: str
    verdicts: tuple[bool, ...]
    complete: bool
    solver_statuses: tuple[str, ...]
    witness: SMTWitness | None = None
    unknown_reason: str | None = None
    backend: str | None = None


class Z3EvalSolver:
    """Portable adapter around libz3's SMT-LIB2 evaluator.

    SMT-LIB2 is the contract boundary so the scientific encoding is not tied to
    the Python z3-solver package. A CLI or normal Python binding can replace this
    adapter without changing SSCV's bounded semantics.
    """

    def __init__(self, library_path: str | None = None):
        candidates = [
            library_path,
            find_library("z3"),
            "libz3.so.4",
            "libz3.so",
            "libz3.dylib",
            "libz3.dll",
            "z3.dll",
        ]
        last_error: Exception | None = None
        self.lib = None
        for candidate in candidates:
            if not candidate:
                continue
            try:
                self.lib = CDLL(candidate)
                self.library_path = candidate
                break
            except OSError as exc:
                last_error = exc
        if self.lib is None:
            raise RuntimeError(f"libz3 unavailable: {last_error}")

        self.lib.Z3_mk_config.restype = c_void_p
        self.lib.Z3_mk_context.argtypes = [c_void_p]
        self.lib.Z3_mk_context.restype = c_void_p
        self.lib.Z3_del_config.argtypes = [c_void_p]
        self.lib.Z3_del_context.argtypes = [c_void_p]
        self.lib.Z3_eval_smtlib2_string.argtypes = [c_void_p, c_char_p]
        self.lib.Z3_eval_smtlib2_string.restype = c_char_p
        self.lib.Z3_get_version.argtypes = [
            c_void_p,
            c_void_p,
            c_void_p,
            c_void_p,
        ]

    @property
    def name(self) -> str:
        return f"z3-ctypes:{self.library_path}"

    @property
    def version(self) -> str:
        major = c_uint()
        minor = c_uint()
        build = c_uint()
        revision = c_uint()
        self.lib.Z3_get_version(
            byref(major),
            byref(minor),
            byref(build),
            byref(revision),
        )
        return f"{major.value}.{minor.value}.{build.value}.{revision.value}"

    def _eval(self, query: str) -> str:
        cfg = self.lib.Z3_mk_config()
        ctx = self.lib.Z3_mk_context(cfg)
        self.lib.Z3_del_config(cfg)
        try:
            raw = self.lib.Z3_eval_smtlib2_string(ctx, query.encode("utf-8"))
            return raw.decode("utf-8", errors="replace") if raw else ""
        finally:
            self.lib.Z3_del_context(ctx)

    def solve(self, smt2: str, variables: Iterable[str]) -> tuple[str, dict[str, Any]]:
        # Check satisfiability in a first context. Do not request a model from an
        # UNSAT context: Z3 reports model-unavailable as a fatal evaluator error.
        check_text = self._eval(smt2 + "\n(check-sat)\n")
        first = check_text.strip().splitlines()[0].strip() if check_text.strip() else "error"
        if first not in {"sat", "unsat", "unknown"}:
            return "error", {}
        if first != "sat":
            return first, {}

        variable_list = list(variables)
        if not variable_list:
            return "sat", {}

        model_text = self._eval(
            smt2 + "\n(check-sat)\n(get-value (" + " ".join(variable_list) + "))\n"
        )
        values: dict[str, Any] = {}
        for name, value in re.findall(
            r"\(([A-Za-z_][A-Za-z0-9_]*)\s+([^()\s]+)\)", model_text
        ):
            if value == "true":
                values[name] = True
            elif value == "false":
                values[name] = False
            else:
                try:
                    values[name] = int(value)
                except ValueError:
                    values[name] = value
        return "sat", values


def default_solver() -> Z3EvalSolver | None:
    try:
        return Z3EvalSolver()
    except Exception:
        pass

    try:
        import z3
        from pathlib import Path

        package_dir = Path(z3.__file__).resolve().parent
        bundled_candidates = (
            package_dir / "lib" / "libz3.dll",
            package_dir / "lib" / "libz3.so",
            package_dir / "lib" / "libz3.dylib",
        )
        for candidate in bundled_candidates:
            if candidate.exists():
                return Z3EvalSolver(str(candidate))
    except Exception:
        pass

    return None


def view_canonical(view: Any) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (r.case_id, int(r.rank), r.event_id, r.activity, r.actor)
            for r in view.rows
        )
    )


def flatten_canonical(execution: SMTExecution) -> tuple[tuple[Any, ...], ...]:
    pos = {eid: i for i, eid in enumerate(execution.order)}
    rows: list[tuple[Any, ...]] = []
    case_ids = sorted({c for e in execution.events for c in e.case_ids})
    for case_id in case_ids:
        evs = [e for e in execution.events if case_id in e.case_ids]
        evs.sort(key=lambda e: (pos[e.event_id], e.event_id))
        for rank, event in enumerate(evs):
            rows.append((case_id, rank, event.event_id, event.activity, event.actor))
    return tuple(sorted(rows))


def _records(view: Any) -> tuple[dict[str, dict[str, Any]], bool]:
    records: dict[str, dict[str, Any]] = {}
    consistent = True
    for row in view.rows:
        rec = records.get(row.event_id)
        if rec is None:
            records[row.event_id] = {
                "activity": row.activity,
                "actor": row.actor,
                "case_ids": {row.case_id},
            }
        else:
            if rec["activity"] != row.activity or rec["actor"] != row.actor:
                consistent = False
            rec["case_ids"].add(row.case_id)
    return records, consistent


def _visible_precedence(view: Any) -> set[tuple[str, str]]:
    by_case: dict[str, list[Any]] = {}
    for row in view.rows:
        by_case.setdefault(row.case_id, []).append(row)
    edges: set[tuple[str, str]] = set()
    for rows in by_case.values():
        ordered = sorted(rows, key=lambda r: (r.rank, r.event_id))
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                if left.event_id != right.event_id:
                    edges.add((left.event_id, right.event_id))
    return edges


def _and(parts: Iterable[str]) -> str:
    xs = [part for part in parts if part != "true"]
    if any(part == "false" for part in xs):
        return "false"
    if not xs:
        return "true"
    if len(xs) == 1:
        return xs[0]
    return "(and " + " ".join(xs) + ")"


def _or(parts: Iterable[str]) -> str:
    xs = [part for part in parts if part != "false"]
    if any(part == "true" for part in xs):
        return "true"
    if not xs:
        return "false"
    if len(xs) == 1:
        return xs[0]
    return "(or " + " ".join(xs) + ")"


def _not(expr: str) -> str:
    if expr == "true":
        return "false"
    if expr == "false":
        return "true"
    return f"(not {expr})"


def _order_pair_key(left: str, right: str) -> tuple[str, str]:
    return tuple(sorted((left, right)))


def _precedence_closure(
    event_ids: Iterable[str], edges: Iterable[tuple[str, str]]
) -> dict[str, set[str]]:
    ids = tuple(event_ids)
    reach = {event_id: set() for event_id in ids}
    for left, right in edges:
        if left in reach and right in reach:
            reach[left].add(right)
    changed = True
    while changed:
        changed = False
        for left in ids:
            expanded: set[str] = set()
            for right in tuple(reach[left]):
                expanded.update(reach[right])
            old_count = len(reach[left])
            reach[left].update(expanded)
            if len(reach[left]) != old_count:
                changed = True
    return reach


def _motif_kind(motif: Any) -> str:
    if hasattr(motif, "first_activity") and hasattr(motif, "second_activity"):
        return "pair"
    if hasattr(motif, "sensitive_activity") and hasattr(motif, "control_activity"):
        return "missing_control"
    raise ValueError(f"unsupported motif object: {type(motif).__name__}")


class Encoding:
    """Independent bounded SMT encoding for the current SMF-1 smoke subset."""

    def __init__(self, view: Any, spec: Any, motif: Any):
        self.view = view
        self.spec = spec
        self.motif = motif
        self.records, self.consistent = _records(view)
        self.visible_ids = sorted(self.records)
        self.deleted_templates = list(getattr(spec, "optional_deleted_events", ()))
        self.deleted_ids = [template.event.event_id for template in self.deleted_templates]
        self.required_deleted_ids = tuple(getattr(spec, "required_deleted_event_ids", ()))
        if len(set(self.visible_ids + self.deleted_ids)) != len(
            self.visible_ids
        ) + len(self.deleted_ids):
            self.consistent = False
        if (
            len(self.required_deleted_ids) != len(set(self.required_deleted_ids))
            or not set(self.required_deleted_ids).issubset(set(self.deleted_ids))
        ):
            self.consistent = False
        self.all_ids = self.visible_ids + self.deleted_ids
        self.index = {event_id: i for i, event_id in enumerate(self.all_ids)}
        self.bind_domains = dict(getattr(spec, "hidden_binding_domains", ()))
        self.relation_domain = tuple(getattr(spec, "hidden_relation_domain", ())) or ((),)
        self.reference_order: tuple[str, ...] | None = None
        self.reference_positions: dict[str, int] = {}
        self.order_free_pairs: set[tuple[str, str]] = set()
        self.order_mandatory_edges: set[tuple[str, str]] = set()
        self.order_mandatory_reach: dict[str, set[str]] = {}
        self._prepare_order_contract()
        self.vars: list[str] = []
        self.lines: list[str] = ["(set-logic QF_LIA)"]
        self._build_base()
        self.violation = self._build_violation()

    def active(self, event_id: str) -> str:
        if event_id in self.visible_ids:
            return "true"
        return f"present_{self.index[event_id]}"

    def pos(self, event_id: str) -> str:
        return f"pos_{self.index[event_id]}"

    def bind_var(self, event_id: str) -> str | None:
        return (
            f"bind_{self.index[event_id]}"
            if event_id in self.visible_ids
            else None
        )

    def binding_choices(self, event_id: str) -> list[tuple[str, tuple[str, ...]]]:
        if event_id in self.visible_ids:
            domain = tuple(self.bind_domains.get(event_id, ((),)))
            return [
                (f"(= {self.bind_var(event_id)} {j})", tuple(sorted(objects)))
                for j, objects in enumerate(domain)
            ]
        template = self.deleted_templates[self.deleted_ids.index(event_id)]
        return [("true", tuple(sorted(template.event.hidden_objects)))]

    def _prepare_order_contract(self) -> None:
        reference = getattr(self.spec, "reference_order", None)
        free_pairs = getattr(self.spec, "order_free_pairs", None)
        if reference is None and free_pairs is None:
            return
        if reference is None or free_pairs is None:
            self.consistent = False
            return
        reference = tuple(reference)
        if len(reference) != len(set(reference)) or set(reference) != set(self.all_ids):
            self.consistent = False
            return
        positions = {event_id: index for index, event_id in enumerate(reference)}
        mandatory = set(_visible_precedence(self.view))
        for template in self.deleted_templates:
            event_id = template.event.event_id
            if template.before_event_id is not None:
                mandatory.add((event_id, template.before_event_id))
            if template.after_event_id is not None:
                mandatory.add((template.after_event_id, event_id))
        if any(
            left not in positions
            or right not in positions
            or positions[left] >= positions[right]
            for left, right in mandatory
        ):
            self.consistent = False
            return
        reach = _precedence_closure(self.all_ids, mandatory)
        normalized: set[tuple[str, str]] = set()
        for raw_pair in tuple(free_pairs):
            pair = tuple(raw_pair)
            if (
                len(pair) != 2
                or pair[0] == pair[1]
                or pair[0] not in positions
                or pair[1] not in positions
            ):
                self.consistent = False
                return
            key = _order_pair_key(pair[0], pair[1])
            if key in normalized:
                self.consistent = False
                return
            left, right = key
            if right in reach[left] or left in reach[right]:
                self.consistent = False
                return
            normalized.add(key)
        self.reference_order = reference
        self.reference_positions = positions
        self.order_free_pairs = normalized
        self.order_mandatory_edges = mandatory
        self.order_mandatory_reach = reach

    def _build_base(self) -> None:
        if not self.consistent or not self.visible_ids:
            return
        count = len(self.all_ids)
        for event_id in self.visible_ids:
            variable = self.bind_var(event_id)
            domain = tuple(self.bind_domains.get(event_id, ((),)))
            if not domain:
                self.consistent = False
                return
            self.lines.append(f"(declare-const {variable} Int)")
            self.lines.append(
                f"(assert (and (<= 0 {variable}) (< {variable} {len(domain)})))"
            )
            self.vars.append(variable)

        self.lines.append("(declare-const rel_choice Int)")
        self.lines.append(
            f"(assert (and (<= 0 rel_choice) (< rel_choice {len(self.relation_domain)})))"
        )
        self.vars.append("rel_choice")

        for event_id in self.all_ids:
            position = self.pos(event_id)
            self.lines.append(f"(declare-const {position} Int)")
            self.lines.append(
                f"(assert (and (<= 0 {position}) (< {position} {max(1, count)})))"
            )
            self.vars.append(position)

        for event_id in self.deleted_ids:
            active = self.active(event_id)
            self.lines.append(f"(declare-const {active} Bool)")
            self.vars.append(active)
            if event_id in self.required_deleted_ids:
                self.lines.append(f"(assert {active})")

        for index, left in enumerate(self.all_ids):
            for right in self.all_ids[index + 1 :]:
                guard = _and([self.active(left), self.active(right)])
                not_equal = f"(not (= {self.pos(left)} {self.pos(right)}))"
                self.lines.append(f"(assert (=> {guard} {not_equal}))")

        for left, right in _visible_precedence(self.view):
            self.lines.append(f"(assert (< {self.pos(left)} {self.pos(right)}))")

        for template in self.deleted_templates:
            event_id = template.event.event_id
            if template.before_event_id is not None:
                self.lines.append(
                    f"(assert (=> {self.active(event_id)} "
                    f"(< {self.pos(event_id)} {self.pos(template.before_event_id)})))"
                )
            if template.after_event_id is not None:
                self.lines.append(
                    f"(assert (=> {self.active(event_id)} "
                    f"(< {self.pos(template.after_event_id)} {self.pos(event_id)})))"
                )

        if self.reference_order is not None:
            for index, left in enumerate(self.all_ids):
                for right in self.all_ids[index + 1 :]:
                    if (
                        right in self.order_mandatory_reach.get(left, set())
                        or left in self.order_mandatory_reach.get(right, set())
                        or _order_pair_key(left, right) in self.order_free_pairs
                    ):
                        continue
                    if self.reference_positions[left] < self.reference_positions[right]:
                        first, second = left, right
                    else:
                        first, second = right, left
                    guard = _and([self.active(first), self.active(second)])
                    self.lines.append(
                        f"(assert (=> {guard} (< {self.pos(first)} {self.pos(second)})))"
                    )

    def event_activity(self, event_id: str) -> str:
        if event_id in self.visible_ids:
            return str(self.records[event_id]["activity"])
        return str(
            self.deleted_templates[self.deleted_ids.index(event_id)].event.activity
        )

    def event_actor(self, event_id: str) -> str | None:
        if event_id in self.visible_ids:
            return self.records[event_id]["actor"]
        return self.deleted_templates[self.deleted_ids.index(event_id)].event.actor

    def shared_object_expr(self, left: str, right: str) -> str:
        terms: list[str] = []
        for guard_left, objects_left in self.binding_choices(left):
            for guard_right, objects_right in self.binding_choices(right):
                if set(objects_left).intersection(objects_right):
                    terms.append(_and([guard_left, guard_right]))
        return _or(terms)

    def relation_expr(self, relation_type: str, left: str, right: str) -> str:
        terms: list[str] = []
        for guard_left, objects_left in self.binding_choices(left):
            for guard_right, objects_right in self.binding_choices(right):
                for relation_index, relations in enumerate(self.relation_domain):
                    has_relation = any(
                        current_type == relation_type
                        and (
                            (first in objects_left and second in objects_right)
                            or (second in objects_left and first in objects_right)
                        )
                        for current_type, first, second in relations
                    )
                    if has_relation:
                        terms.append(
                            _and(
                                [
                                    guard_left,
                                    guard_right,
                                    f"(= rel_choice {relation_index})",
                                ]
                            )
                        )
        return _or(terms)

    def _pair_candidate(self, left: str, right: str) -> str:
        motif = self.motif
        if (
            left == right
            or self.event_activity(left) != motif.first_activity
            or self.event_activity(right) != motif.second_activity
        ):
            return "false"

        parts = [self.active(left), self.active(right)]
        actor_relation = getattr(motif, "actor_relation", "any")
        if actor_relation == "same" and self.event_actor(left) != self.event_actor(right):
            return "false"
        if actor_relation == "different" and self.event_actor(left) == self.event_actor(right):
            return "false"
        if actor_relation not in {"any", "same", "different"}:
            raise ValueError(f"unsupported actor relation: {actor_relation}")

        order_relation = getattr(motif, "order_relation", "any")
        if order_relation == "before":
            parts.append(f"(< {self.pos(left)} {self.pos(right)})")
        elif order_relation == "after":
            parts.append(f"(< {self.pos(right)} {self.pos(left)})")
        elif order_relation != "any":
            raise ValueError(f"unsupported order relation: {order_relation}")

        if getattr(motif, "require_shared_hidden_object", True):
            parts.append(self.shared_object_expr(left, right))

        required_relation = getattr(motif, "required_hidden_relation", None)
        if required_relation is not None:
            parts.append(self.relation_expr(required_relation, left, right))
        return _and(parts)

    def _build_violation(self) -> str:
        if not self.consistent:
            return "false"
        kind = _motif_kind(self.motif)
        if kind == "pair":
            return _or(
                self._pair_candidate(left, right)
                for left in self.all_ids
                for right in self.all_ids
            )

        motif = self.motif
        sensitive_terms: list[str] = []
        for sensitive in self.all_ids:
            if self.event_activity(sensitive) != motif.sensitive_activity:
                continue
            anchor_event_id = getattr(motif, "anchor_event_id", None)
            if anchor_event_id is not None and sensitive != anchor_event_id:
                continue
            protections: list[str] = []
            for control in self.all_ids:
                if (
                    control == sensitive
                    or self.event_activity(control) != motif.control_activity
                ):
                    continue
                parts = [self.active(control)]
                if getattr(motif, "require_shared_hidden_object", True):
                    parts.append(self.shared_object_expr(sensitive, control))
                required_relation = getattr(motif, "required_hidden_relation", None)
                if required_relation is not None:
                    parts.append(
                        self.relation_expr(required_relation, control, sensitive)
                    )
                if getattr(motif, "control_must_be_before", True):
                    parts.append(f"(< {self.pos(control)} {self.pos(sensitive)})")
                protections.append(_and(parts))
            sensitive_terms.append(
                _and([self.active(sensitive), _not(_or(protections))])
            )
        return _or(sensitive_terms)

    def script_for(self, target: str) -> str:
        if target not in {"safe", "violation"}:
            raise ValueError(target)
        assertion = _not(self.violation) if target == "safe" else self.violation
        return "\n".join(self.lines + [f"(assert {assertion})"])

    def reconstruct(self, values: dict[str, Any]) -> SMTExecution:
        events: list[SMTEvent] = []
        for event_id in self.visible_ids:
            domain = tuple(self.bind_domains.get(event_id, ((),)))
            choice = int(values.get(self.bind_var(event_id), 0))
            choice = max(0, min(choice, len(domain) - 1))
            record = self.records[event_id]
            events.append(
                SMTEvent(
                    event_id,
                    str(record["activity"]),
                    record["actor"],
                    tuple(sorted(record["case_ids"])),
                    tuple(sorted(domain[choice])),
                )
            )

        for template in self.deleted_templates:
            event_id = template.event.event_id
            if bool(values.get(self.active(event_id), False)):
                events.append(
                    SMTEvent(
                        event_id,
                        template.event.activity,
                        template.event.actor,
                        tuple(template.event.case_ids),
                        tuple(template.event.hidden_objects),
                    )
                )

        relation_index = int(values.get("rel_choice", 0))
        relation_index = max(0, min(relation_index, len(self.relation_domain) - 1))
        relations = tuple(sorted(self.relation_domain[relation_index]))
        active_ids = {event.event_id for event in events}
        order = tuple(
            sorted(
                active_ids,
                key=lambda event_id: (
                    int(values.get(self.pos(event_id), 0)),
                    event_id,
                ),
            )
        )
        return SMTExecution(tuple(events), order, relations)


def verify_smt(
    view: Any,
    spec: Any,
    motif: Any,
    *,
    solver: Z3EvalSolver | None = None,
    max_queries: int | None = None,
    query_order: tuple[str, ...] = ("safe", "violation"),
) -> SMTVerificationResult:
    records, consistent = _records(view)
    if not consistent:
        return SMTVerificationResult(
            "unknown",
            (),
            True,
            (),
            unknown_reason="inconsistent_replicated_event_fields",
        )
    if not records:
        return SMTVerificationResult(
            "unknown", (), True, (), unknown_reason="no_admissible_completion"
        )
    anchor_event_id = getattr(motif, "anchor_event_id", None)
    if anchor_event_id is not None and anchor_event_id not in records:
        return SMTVerificationResult(
            "unknown",
            (),
            True,
            (),
            unknown_reason="anchor_event_not_in_audit_instance",
        )

    encoding = Encoding(view, spec, motif)
    if not encoding.consistent:
        return SMTVerificationResult(
            "unknown", (), True, (), unknown_reason="invalid_completion_spec"
        )

    solver = solver or default_solver()
    if solver is None:
        return SMTVerificationResult(
            "unknown", (), False, (), unknown_reason="solver_unavailable"
        )

    statuses: list[str] = []
    models: dict[str, SMTExecution] = {}
    targets = list(query_order)
    if max_queries is not None:
        targets = targets[:max_queries]

    for target in targets:
        status, values = solver.solve(encoding.script_for(target), encoding.vars)
        statuses.append(status)
        if status == "sat":
            models[target] = encoding.reconstruct(values)
        elif status in {"unknown", "error"}:
            return SMTVerificationResult(
                "unknown",
                tuple(sorted({name == "violation" for name in models})),
                False,
                tuple(statuses),
                unknown_reason=f"solver_{status}",
                backend=solver.name,
            )

    if max_queries is not None and max_queries < 2:
        verdicts = tuple(sorted({name == "violation" for name in models}))
        return SMTVerificationResult(
            "unknown",
            verdicts,
            False,
            tuple(statuses),
            unknown_reason="operational_query_budget_exhausted",
            backend=solver.name,
        )

    safe_status = (
        statuses[query_order.index("safe")]
        if "safe" in query_order and query_order.index("safe") < len(statuses)
        else None
    )
    violation_status = (
        statuses[query_order.index("violation")]
        if "violation" in query_order
        and query_order.index("violation") < len(statuses)
        else None
    )

    if safe_status == "sat" and violation_status == "sat":
        safe_execution = models["safe"]
        violating_execution = models["violation"]
        valid = (
            flatten_canonical(safe_execution) == view_canonical(view)
            and flatten_canonical(violating_execution) == view_canonical(view)
        )
        witness = SMTWitness(
            safe_execution,
            violating_execution,
            valid=valid,
            minimal=False,
        )
        return SMTVerificationResult(
            "unsound",
            (False, True),
            True,
            tuple(statuses),
            witness=witness,
            unknown_reason=None if valid else "witness_validation_failed",
            backend=solver.name,
        )

    if safe_status == "sat" and violation_status == "unsat":
        return SMTVerificationResult(
            "sound", (False,), True, tuple(statuses), backend=solver.name
        )
    if safe_status == "unsat" and violation_status == "sat":
        return SMTVerificationResult(
            "sound", (True,), True, tuple(statuses), backend=solver.name
        )
    if safe_status == "unsat" and violation_status == "unsat":
        return SMTVerificationResult(
            "unknown",
            (),
            True,
            tuple(statuses),
            unknown_reason="no_admissible_completion",
            backend=solver.name,
        )
    return SMTVerificationResult(
        "unknown",
        (),
        False,
        tuple(statuses),
        unknown_reason="incomplete_solver_state",
        backend=solver.name,
    )
