from __future__ import annotations
from dataclasses import dataclass, asdict
import hashlib, json
from typing import Any
from . import case_views as cvc
@dataclass(frozen=True)
class Event:
    event_id: str
    activity: str
    actor: str | None
    case_ids: tuple[str,...]=()
    hidden_objects: tuple[str,...]=()
@dataclass(frozen=True)
class DeletedEventTemplate:
    event: Event
    before_event_id: str|None=None
    after_event_id: str|None=None
@dataclass(frozen=True)
class Spec:
    hidden_binding_domains: tuple[tuple[str,tuple[tuple[str,...],...]],...]=()
    hidden_relation_domain: tuple[tuple[tuple[str,str,str],...],...]=((),)
    optional_deleted_events: tuple[DeletedEventTemplate,...]=()
    max_completions: int|None=None
    reference_order: tuple[str,...]|None=None
    order_free_pairs: tuple[tuple[str,str],...]|None=None
    required_deleted_event_ids: tuple[str,...]=()
@dataclass(frozen=True)
class PairMotif:
    first_activity: str
    second_activity: str
    actor_relation: str='any'
    order_relation: str='any'
    require_shared_hidden_object: bool=True
    required_hidden_relation: str|None=None
@dataclass(frozen=True)
class MissingControlMotif:
    sensitive_activity: str
    control_activity: str
    require_shared_hidden_object: bool=True
    control_must_be_before: bool=True
    required_hidden_relation: str|None=None
    anchor_event_id: str|None=None
@dataclass(frozen=True)
class SourceObject:
    object_id: str
    object_type: str
@dataclass(frozen=True)
class SourceEvent:
    event_id: str
    activity: str
    actor: str|None
    object_ids: tuple[str,...]
@dataclass(frozen=True)
class SourceExecution:
    events: tuple[SourceEvent,...]
    objects: tuple[SourceObject,...]
    relations: tuple[tuple[str,str,str],...]
    order: tuple[str,...]
@dataclass(frozen=True)
class E2Fixture:
    case_id: str
    motif_id: str
    constructor_id: str
    mechanism: str
    semantic_class: str
    expected_decision: str
    expected_verdicts: tuple[bool,...]
    view: Any
    spec: Spec
    motif: Any
    source_execution: SourceExecution
    constructor: cvc.CaseViewConstructor
    variable_mechanisms: tuple[str,...]
    constructor_support_locked: bool=True


def _relation_tuple(*items): return tuple(items)
def _fixed(*items): return (tuple(items),)

def _pair_motif(mid):
    if mid=='M1': return PairMotif('request','approve','same','before',False,'linked')
    if mid=='M3': return PairMotif('A1','A2','any','before',False,'linked')
    raise ValueError(mid)

def _m2(): return MissingControlMotif('sensitive','control',False,True,'linked')

def _expected(cls):
    if cls=='sound-safe': return 'sound',(False,)
    if cls=='sound-violation': return 'sound',(True,)
    if cls=='unsound': return 'unsound',(False,True)
    raise ValueError(cls)

def _all_hidden_ids(spec):
    ids=set()
    for _,dom in spec.hidden_binding_domains:
        for choice in dom: ids.update(choice)
    for rels in spec.hidden_relation_domain:
        for _,a,b in rels: ids|={a,b}
    for t in spec.optional_deleted_events: ids.update(t.event.hidden_objects)
    return ids

def _source_view(constructor_id, rows, order, spec):
    # rows: (event_id, activity, actor, case_ids)
    all_cases=sorted({c for *_,cases in rows for c in cases})
    hidden_ids=_all_hidden_ids(spec)
    objects=[SourceObject(c,'case') for c in all_cases]
    objects += [SourceObject(h,'latent') for h in sorted(hidden_ids) if h not in all_cases]
    relations=[]; source_events=[]
    first_bind={eid:(dom[0] if dom else ()) for eid,dom in spec.hidden_binding_domains}
    if constructor_id=='CV-D':
        constructor=cvc.CaseViewConstructor.cv_d('case')
        for eid,act,actor,cases in rows:
            object_ids=tuple(dict.fromkeys(tuple(cases)+tuple(first_bind.get(eid,()))))
            source_events.append(SourceEvent(eid,act,actor,object_ids))
    elif constructor_id=='CV-R1':
        constructor=cvc.CaseViewConstructor.cv_r1('case',('case_membership',))
        supports={c:f'SUPPORT_{c}' for c in all_cases}
        objects += [SourceObject(s,'support') for s in supports.values()]
        relations += [('case_membership',supports[c],c) for c in all_cases]
        for eid,act,actor,cases in rows:
            object_ids=tuple(dict.fromkeys(tuple(supports[c] for c in cases)+tuple(first_bind.get(eid,()))))
            source_events.append(SourceEvent(eid,act,actor,object_ids))
    else: raise ValueError(constructor_id)
    # Realized hidden relation choice is source metadata only; constructor ignores it.
    if spec.hidden_relation_domain:
        relations += list(spec.hidden_relation_domain[0])
    src=SourceExecution(tuple(source_events),tuple(objects),tuple(relations),tuple(order))
    view=cvc.flatten_with_constructor(src,constructor)
    return src,constructor,view

def _pair_fixture(mid,view_id,mech,cls):
    motif=_pair_motif(mid); first=motif.first_activity; second=motif.second_activity
    actor1='alice'; actor2='alice' if mid=='M1' else 'bob'
    fwd=[('e1',first,actor1,('C1',)),('e2',second,actor2,('C1',))]
    rev=[('e1',first,actor1,('C1',)),('e2',second,actor2,('C1',))]
    base_bind=(('e1',(('H1',),)),('e2',(('H2',),)))
    linked=(('linked','H1','H2'),)
    rows=fwd; order=('e1','e2'); spec=Spec(base_bind,(linked,)); var=()
    if mech=='none':
        if cls=='sound-safe':
            if mid=='M1': rows=[('e1',first,'alice',('C1',)),('e2',second,'bob',('C1',))]; order=('e1','e2')
            else: order=('e2','e1')
        elif cls!='sound-violation': raise ValueError((mid,mech,cls))
    elif mech=='binding':
        rows=fwd; order=('e1','e2'); var=('binding',)
        bind=(('e1',(('H1',),)),('e2',(('H2',),('H3',))))
        if cls=='sound-safe': rels=((),)
        elif cls=='sound-violation': rels=((('linked','H1','H2'),('linked','H1','H3')),)
        else: rels=((('linked','H1','H2'),),)
        spec=Spec(bind,rels)
    elif mech=='relation':
        rows=fwd; order=('e1','e2'); var=('relation',)
        if cls=='sound-safe': rels=((),(('other','H1','H2'),))
        elif cls=='sound-violation': rels=((('linked','H1','H2'),),(('linked','H1','H2'),('other','H1','H2')))
        else: rels=((),(('linked','H1','H2'),))
        spec=Spec(base_bind,rels)
    elif mech=='order':
        var=('order',); spec=Spec(base_bind,(linked,))
        if cls=='unsound': rows=[('e1',first,actor1,('C1',)),('e2',second,actor2,('C2',))]; order=('e1','e2')
        else:
            rows=fwd+[('noise','noise','nobody',('C2',))]
            order=('e1','e2','noise') if cls=='sound-violation' else (('e1','e2','noise') if mid=='M1' else ('e2','e1','noise'))
            if cls=='sound-safe' and mid=='M1': rows=[('e1',first,'alice',('C1',)),('e2',second,'bob',('C1',)),('noise','noise','nobody',('C2',))]
    elif mech=='deletion':
        var=('deletion',)
        if cls=='unsound':
            rows=[('e1',first,actor1,('C1',))]; order=('e1',)
            deleted=DeletedEventTemplate(Event('e2',second,actor2,(),('H2',)),after_event_id='e1')
            spec=Spec((('e1',(('H1',),)),),(linked,),(deleted,))
        else:
            if cls=='sound-safe':
                if mid=='M1': rows=[('e1',first,'alice',('C1',)),('e2',second,'bob',('C1',))]; order=('e1','e2')
                else: rows=fwd; order=('e2','e1')
            else: rows=fwd; order=('e1','e2')
            deleted=DeletedEventTemplate(Event('noise_del','noise','nobody',(),('HD',)))
            spec=Spec(base_bind,(linked,),(deleted,))
    elif mech=='mixed':
        if mid=='M1':
            var=('binding','relation'); rows=fwd; order=('e1','e2')
            spec=Spec((('e1',(('H1',),)),('e2',(('H2',),('H3',)))),((),(('linked','H1','H2'),)))
        else:
            var=('order','relation'); rows=[('e1',first,actor1,('C1',)),('e2',second,actor2,('C2',))]; order=('e1','e2')
            spec=Spec(base_bind,((),linked))
    else: raise ValueError(mech)
    src,ctor,view=_source_view(view_id,rows,order,spec)
    dec,ver=_expected(cls)
    return E2Fixture(f'E2A|{mid}|{view_id}|{mech}|{cls}',mid,view_id,mech,cls,dec,ver,view,spec,motif,src,ctor,var)

def _m2_fixture(view_id,mech,cls):
    motif=_m2(); good=[('c','control','bob',('C1',)),('s','sensitive','alice',('C1',))]; bad=good
    base_bind=(('c',(('HC',),)),('s',(('HS',),))); linked=(('linked','HC','HS'),)
    rows=good; order=('c','s'); spec=Spec(base_bind,(linked,)); var=()
    if mech=='none':
        order=('c','s') if cls=='sound-safe' else ('s','c')
        if cls=='unsound': raise ValueError((mech,cls))
    elif mech=='binding':
        var=('binding',); order=('c','s')
        bind=(('c',(('HC',),)),('s',(('HS',),('HX',))))
        if cls=='sound-safe': rels=((('linked','HC','HS'),('linked','HC','HX')),)
        elif cls=='sound-violation': rels=((),)
        else: rels=((('linked','HC','HS'),),)
        spec=Spec(bind,rels)
    elif mech=='relation':
        var=('relation',); order=('c','s')
        if cls=='sound-safe': rels=((('linked','HC','HS'),),(('linked','HC','HS'),('other','HC','HS')))
        elif cls=='sound-violation': rels=((),(('other','HC','HS'),))
        else: rels=((),(('linked','HC','HS'),))
        spec=Spec(base_bind,rels)
    elif mech=='order':
        var=('order',); spec=Spec(base_bind,(linked,))
        if cls=='unsound': rows=[('c','control','bob',('C1',)),('s','sensitive','alice',('C2',))]; order=('c','s')
        else:
            rows=good+[('noise','noise','nobody',('C2',))]
            order=('c','s','noise') if cls=='sound-safe' else ('s','c','noise')
    elif mech=='deletion':
        var=('deletion',)
        if cls=='unsound':
            rows=[('s','sensitive','alice',('C1',))]; order=('s',)
            deleted=DeletedEventTemplate(Event('c','control','bob',(),('HC',)),before_event_id='s')
            spec=Spec((('s',(('HS',),)),),(linked,),(deleted,))
        else:
            order=('c','s') if cls=='sound-safe' else ('s','c')
            deleted=DeletedEventTemplate(Event('noise_del','noise','nobody',(),('HD',)))
            spec=Spec(base_bind,(linked,),(deleted,))
    elif mech=='mixed':
        var=('deletion','relation'); rows=[('s','sensitive','alice',('C1',))]; order=('s',)
        deleted=DeletedEventTemplate(Event('c','control','bob',(),('HC',)),before_event_id='s')
        spec=Spec((('s',(('HS',),)),),((),linked),(deleted,))
    else: raise ValueError(mech)
    src,ctor,view=_source_view(view_id,rows,order,spec)
    dec,ver=_expected(cls)
    return E2Fixture(f'E2A|M2|{view_id}|{mech}|{cls}','M2',view_id,mech,cls,dec,ver,view,spec,motif,src,ctor,var)

def build_fixture(mid,view,mech,cls):
    return _m2_fixture(view,mech,cls) if mid=='M2' else _pair_fixture(mid,view,mech,cls)

def build_all_complete_fixtures():
    out=[]
    for mid in ('M1','M2','M3'):
        for view in ('CV-D','CV-R1'):
            for cls in ('sound-safe','sound-violation'):
                out.append(build_fixture(mid,view,'none',cls))
    for mid in ('M1','M2','M3'):
        for view in ('CV-D','CV-R1'):
            for mech in ('binding','relation','order','deletion'):
                for cls in ('sound-safe','sound-violation','unsound'):
                    out.append(build_fixture(mid,view,mech,cls))
    for mid in ('M1','M2','M3'):
        for view in ('CV-D','CV-R1'):
            out.append(build_fixture(mid,view,'mixed','unsound'))
    return tuple(out)

def validate_constructor_provenance(fixture):
    regenerated=cvc.flatten_with_constructor(fixture.source_execution,fixture.constructor)
    return regenerated==fixture.view

def _manifest_item(f):
    return {
        'case_id':f.case_id,'motif':f.motif_id,'case_view':f.constructor_id,
        'mechanism':f.mechanism,'semantic_class':f.semantic_class,
        'expected_decision':f.expected_decision,
        'expected_verdicts':['violation' if x else 'safe' for x in f.expected_verdicts],
        'variable_mechanisms':list(f.variable_mechanisms),
        'constructor_support_locked':f.constructor_support_locked,
        'view_rows':[[r.case_id,int(r.rank),r.event_id,r.activity,r.actor] for r in f.view.rows],
    }
def canonical_manifest():
    obj={'version':'E2A_FIXTURES_V1_2','fixture_count':90,'constructor_contract':'SSCV_V1_2_20260911/AMENDMENT_V1_2_CASE_VIEW_CONSTRUCTORS.md','fixtures':[_manifest_item(f) for f in build_all_complete_fixtures()]}
    return json.dumps(obj,sort_keys=True,separators=(',',':'))
def manifest_sha256(): return hashlib.sha256(canonical_manifest().encode()).hexdigest()
