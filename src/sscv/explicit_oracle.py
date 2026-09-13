from __future__ import annotations
from dataclasses import dataclass
from itertools import permutations, product
from typing import Any

@dataclass(frozen=True)
class ExplicitEvent:
    event_id: str
    activity: str
    actor: str | None
    case_ids: tuple[str, ...] = ()
    hidden_objects: tuple[str, ...] = ()

@dataclass(frozen=True)
class ExplicitExecution:
    events: tuple[ExplicitEvent, ...]
    order: tuple[str, ...]
    hidden_relations: tuple[tuple[str,str,str], ...] = ()

@dataclass(frozen=True)
class ExplicitWitness:
    safe_execution: ExplicitExecution
    violating_execution: ExplicitExecution
    objective: tuple[int,int,int,int,int,int,int]
    valid: bool
    minimal: bool = True

@dataclass(frozen=True)
class ExplicitResult:
    decision: str
    verdicts: tuple[bool, ...]
    explored: int
    complete: bool
    witness: ExplicitWitness | None = None
    unknown_reason: str | None = None


def _records(view: Any):
    records={}; consistent=True
    for row in view.rows:
        r=records.get(row.event_id)
        if r is None:
            records[row.event_id]={'activity':row.activity,'actor':row.actor,'case_ids':{row.case_id}}
        else:
            if r['activity']!=row.activity or r['actor']!=row.actor: consistent=False
            r['case_ids'].add(row.case_id)
    return records,consistent

def _canonical_view(view: Any):
    return tuple(sorted((r.case_id,int(r.rank),r.event_id,r.activity,r.actor) for r in view.rows))

def _flatten(exe: ExplicitExecution):
    if set(exe.order)!={e.event_id for e in exe.events} or len(exe.order)!=len(exe.events): return ()
    pos={eid:i for i,eid in enumerate(exe.order)}
    rows=[]
    for case_id in sorted({c for e in exe.events for c in e.case_ids}):
        evs=sorted((e for e in exe.events if case_id in e.case_ids),key=lambda e:(pos[e.event_id],e.event_id))
        rows.extend((case_id,i,e.event_id,e.activity,e.actor) for i,e in enumerate(evs))
    return tuple(sorted(rows))

def _precedence(view: Any):
    by={}
    for row in view.rows: by.setdefault(row.case_id,[]).append(row)
    edges=set()
    for rows in by.values():
        ordered=sorted(rows,key=lambda r:(int(r.rank),r.event_id))
        for i,a in enumerate(ordered):
            for b in ordered[i+1:]:
                if a.event_id!=b.event_id: edges.add((a.event_id,b.event_id))
    return edges

def _before(exe: ExplicitExecution,a:str,b:str):
    p={eid:i for i,eid in enumerate(exe.order)}
    return a in p and b in p and p[a]<p[b]

def _has_relation(exe: ExplicitExecution, typ:str, left:tuple[str,...], right:tuple[str,...]):
    rel=set(exe.hidden_relations)
    return any((typ,a,b) in rel or (typ,b,a) in rel for a in left for b in right)

def _motif_kind(m:Any):
    if hasattr(m,'first_activity') and hasattr(m,'second_activity'): return 'pair'
    if hasattr(m,'sensitive_activity') and hasattr(m,'control_activity'): return 'missing'
    raise ValueError(type(m).__name__)

def _eval_pair(exe,m):
    for a in exe.events:
        if a.activity!=m.first_activity: continue
        for b in exe.events:
            if a.event_id==b.event_id or b.activity!=m.second_activity: continue
            ar=getattr(m,'actor_relation','any')
            if ar=='same' and a.actor!=b.actor: continue
            if ar=='different' and a.actor==b.actor: continue
            if ar not in {'any','same','different'}: raise ValueError(ar)
            order=getattr(m,'order_relation','any')
            if order=='before' and not _before(exe,a.event_id,b.event_id): continue
            if order=='after' and not _before(exe,b.event_id,a.event_id): continue
            if order not in {'any','before','after'}: raise ValueError(order)
            if getattr(m,'require_shared_hidden_object',True) and not set(a.hidden_objects)&set(b.hidden_objects): continue
            rr=getattr(m,'required_hidden_relation',None)
            if rr is not None and not _has_relation(exe,rr,a.hidden_objects,b.hidden_objects): continue
            return True
    return False

def _eval_missing(exe,m):
    for s in exe.events:
        if s.activity!=m.sensitive_activity: continue
        anchor=getattr(m,'anchor_event_id',None)
        if anchor is not None and s.event_id!=anchor: continue
        protected=False
        for c in exe.events:
            if c.event_id==s.event_id or c.activity!=m.control_activity: continue
            if getattr(m,'require_shared_hidden_object',True) and not set(c.hidden_objects)&set(s.hidden_objects): continue
            rr=getattr(m,'required_hidden_relation',None)
            if rr is not None and not _has_relation(exe,rr,c.hidden_objects,s.hidden_objects): continue
            if getattr(m,'control_must_be_before',True) and not _before(exe,c.event_id,s.event_id): continue
            protected=True; break
        if not protected: return True
    return False

def evaluate(exe,m):
    return _eval_pair(exe,m) if _motif_kind(m)=='pair' else _eval_missing(exe,m)

def _orders(ids,required):
    out=[]
    for order in permutations(ids):
        p={e:i for i,e in enumerate(order)}
        if all(p[a]<p[b] for a,b in required): out.append(tuple(order))
    return tuple(out)

def _pair_key(a,b): return tuple(sorted((a,b)))

def _closure(ids,edges):
    reach={x:set() for x in ids}
    for a,b in edges:
        if a in reach and b in reach: reach[a].add(b)
    changed=True
    while changed:
        changed=False
        for a in ids:
            expanded=set()
            for b in tuple(reach[a]): expanded|=reach[b]
            n=len(reach[a]); reach[a]|=expanded
            if len(reach[a])!=n: changed=True
    return reach

def _order_contract(view,spec,all_possible_ids,templates):
    ref=getattr(spec,'reference_order',None)
    free=getattr(spec,'order_free_pairs',None)
    if ref is None and free is None: return True,None,set(),set()
    if ref is None or free is None: return False,None,set(),set()
    ref=tuple(ref); free=tuple(tuple(x) for x in free)
    if len(ref)!=len(set(ref)) or set(ref)!=set(all_possible_ids): return False,None,set(),set()
    ref_pos={eid:i for i,eid in enumerate(ref)}
    mandatory=set(_precedence(view))
    for t in templates:
        eid=t.event.event_id
        if t.before_event_id is not None: mandatory.add((eid,t.before_event_id))
        if t.after_event_id is not None: mandatory.add((t.after_event_id,eid))
    if any(a not in ref_pos or b not in ref_pos or ref_pos[a]>=ref_pos[b] for a,b in mandatory):
        return False,None,set(),set()
    reach=_closure(tuple(all_possible_ids),mandatory)
    normalized=[]
    for pair in free:
        if len(pair)!=2 or pair[0]==pair[1] or pair[0] not in ref_pos or pair[1] not in ref_pos:
            return False,None,set(),set()
        key=_pair_key(pair[0],pair[1])
        if key in normalized: return False,None,set(),set()
        a,b=key
        if b in reach[a] or a in reach[b]: return False,None,set(),set()
        normalized.append(key)
    return True,ref_pos,set(normalized),mandatory

def _reference_edges_for_active(active_ids,ref_pos,free_pairs,mandatory):
    if ref_pos is None: return set()
    active=tuple(active_ids)
    local_mandatory={edge for edge in mandatory if edge[0] in active and edge[1] in active}
    reach=_closure(active,local_mandatory)
    extra=set()
    for i,a in enumerate(active):
        for b in active[i+1:]:
            if b in reach[a] or a in reach[b] or _pair_key(a,b) in free_pairs: continue
            extra.add((a,b) if ref_pos[a]<ref_pos[b] else (b,a))
    return extra

def enumerate_completions(view,spec):
    records,consistent=_records(view)
    if not consistent or not records: return ()
    ids=tuple(sorted(records))
    domains=dict(getattr(spec,'hidden_binding_domains',()))
    choices=[]
    for eid in ids:
        dom=tuple(tuple(sorted(x)) for x in domains.get(eid,((),)))
        if not dom: return ()
        choices.append(dom)
    templates=tuple(getattr(spec,'optional_deleted_events',()))
    required_deleted=tuple(getattr(spec,'required_deleted_event_ids',()))
    template_ids={t.event.event_id for t in templates}
    if len(required_deleted)!=len(set(required_deleted)) or not set(required_deleted).issubset(template_ids): return ()
    all_possible_ids=tuple(sorted(set(ids+tuple(t.event.event_id for t in templates))))
    order_ok,ref_pos,free_pairs,mandatory_all=_order_contract(view,spec,all_possible_ids,templates)
    if not order_ok: return ()
    presence=list(product(*[((True,) if t.event.event_id in required_deleted else (False,True)) for t in templates])) if templates else [()]
    relation_choices=tuple(getattr(spec,'hidden_relation_domain',())) or ((),)
    out=[]
    for selected in product(*choices):
        bindings=dict(zip(ids,selected))
        for flags in presence:
            included=[t for t,on in zip(templates,flags) if on]
            extra_ids=tuple(t.event.event_id for t in included)
            required=set(_precedence(view))
            for t in included:
                if t.before_event_id is not None: required.add((t.event.event_id,t.before_event_id))
                if t.after_event_id is not None: required.add((t.after_event_id,t.event.event_id))
            active_ids=tuple(sorted(set(ids+extra_ids)))
            required|=_reference_edges_for_active(active_ids,ref_pos,free_pairs,mandatory_all)
            for order in _orders(active_ids,required):
                for rels in relation_choices:
                    events=[]
                    for eid in ids:
                        r=records[eid]
                        events.append(ExplicitEvent(eid,str(r['activity']),r['actor'],tuple(sorted(r['case_ids'])),tuple(bindings[eid])))
                    for t in included:
                        e=t.event
                        events.append(ExplicitEvent(e.event_id,e.activity,e.actor,tuple(e.case_ids),tuple(sorted(e.hidden_objects))))
                    exe=ExplicitExecution(tuple(events),order,tuple(sorted(rels)))
                    if _flatten(exe)==_canonical_view(view): out.append(exe)
    return tuple(out)

def _binding_facts(exe): return {(e.event_id,o) for e in exe.events for o in e.hidden_objects}
def _deleted(view,exe):
    vis={r.event_id for r in view.rows}; return {e.event_id for e in exe.events if e.event_id not in vis}
def _rels(exe): return set(exe.hidden_relations)
def _orders_hidden(view,exe):
    fixed={frozenset((a,b)) for a,b in _precedence(view)}; out=set()
    for i,a in enumerate(exe.order):
        for b in exe.order[i+1:]:
            if frozenset((a,b)) not in fixed: out.add((a,b))
    return out

def objective(view,a,b):
    de=_deleted(view,a)^_deleted(view,b); db=_binding_facts(a)^_binding_facts(b); dr=_rels(a)^_rels(b); do=_orders_hidden(view,a)^_orders_hidden(view,b)
    touched={eid for eid,_ in db}|set(de)
    for x,y in do: touched|={x,y}
    objs={o for _,o in db}
    for _,x,y in dr: objs|={x,y}
    return (len(de)+len(db)+len(dr)+len(do),len(de),len(db),len(dr),len(do),len(touched),len(objs))

def verify_explicit(view,spec,motif):
    anchor=getattr(motif,'anchor_event_id',None)
    if anchor is not None and anchor not in {r.event_id for r in view.rows}:
        return ExplicitResult('unknown',(),0,True,unknown_reason='anchor_event_not_in_audit_instance')
    comps=enumerate_completions(view,spec)
    if not comps: return ExplicitResult('unknown',(),0,True,unknown_reason='no_admissible_completion')
    maxc=getattr(spec,'max_completions',None); complete=True
    if maxc is not None and len(comps)>maxc: comps=comps[:maxc]; complete=False
    verdicts=tuple(sorted({evaluate(e,motif) for e in comps}))
    if verdicts==(False,True):
        safe=[e for e in comps if not evaluate(e,motif)]; viol=[e for e in comps if evaluate(e,motif)]
        pairs=[(objective(view,a,b),a,b) for a in safe for b in viol]
        obj,a,b=min(pairs,key=lambda x:x[0])
        valid=_flatten(a)==_canonical_view(view) and _flatten(b)==_canonical_view(view) and not evaluate(a,motif) and evaluate(b,motif)
        return ExplicitResult('unsound',verdicts,len(comps),complete,ExplicitWitness(a,b,obj,valid,True),None if valid else 'witness_validation_failed')
    if not complete: return ExplicitResult('unknown',verdicts,len(comps),False,unknown_reason='completion_cap_reached')
    return ExplicitResult('sound',verdicts,len(comps),True)
