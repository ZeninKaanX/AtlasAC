"""Killable scan process: a ten minute wall-clock budget includes startup and collectors."""
import multiprocessing as mp
import queue,time
from .engine import now
from .systemscan import system_scan
from . import __version__

MAX_TOTAL_SECONDS=600
MAX_SCAN_SECONDS=590  # Reserve ten seconds for process shutdown and the 5.84-second reveal.

def scan_child(messages,cancel,rules,roots,data_dir,artifacts):
    try:
        report=system_scan(rules,roots,cancel,lambda data:messages.put(('progress',data)),data_dir,artifacts)
        messages.put(('ready',report))
    except Exception as exc:messages.put(('error',str(exc)[:300]))

def run_scan(rules,roots,data_dir,artifacts,cancel,progress,max_seconds=MAX_SCAN_SECONDS,target=scan_child):
    started=time.monotonic();ctx=mp.get_context('spawn');messages=ctx.Queue(maxsize=8);child_cancel=ctx.Event()
    report={'application':'AtlasAC','version':__version__,'started_at':now(),'rule_version':rules['version'],
            'status':'running','roots':list(map(str,roots)),'findings':[],'files':[],'issues':[],'artifacts':{},'components':[],
            'indexed_files':0,'content_files':0,'ignored_files':0,'cache_hits':0,'issues_total':0,'excluded_paths':[],'time_budget_seconds':min(max_seconds,MAX_SCAN_SECONDS)}
    proc=ctx.Process(target=target,args=(messages,child_cancel,rules,roots,data_dir,artifacts),daemon=True)
    limit=max(.01,min(float(max_seconds),MAX_SCAN_SECONDS));cancel_at=None;finished=False
    try:
        proc.start()
        while True:
            elapsed=time.monotonic()-started
            if cancel.is_set():
                child_cancel.set()
                if cancel_at is None:cancel_at=time.monotonic()
                if time.monotonic()-cancel_at>=1:
                    report['status']='cancelled';break
            if elapsed>=limit:
                child_cancel.set();report['status']='partial';report['stop_reason']='time_budget'
                report['issues'].append({'path':'Tarama süresi','reason':f'{limit:g} saniyelik tarama sınırına ulaşıldı; tarama tamamlanmadı.'});break
            try:kind,data=messages.get(timeout=min(.1,max(.001,limit-elapsed)))
            except queue.Empty:
                if not proc.is_alive():
                    report['status']='cancelled' if cancel.is_set() else 'partial'
                    if not cancel.is_set():report['issues'].append({'reason':'Tarama işlemi sonuç üretmeden kapandı'})
                    break
                continue
            if kind=='ready':report=data;finished=True;break
            if kind=='error':report['status']='partial';report['issues'].append({'reason':data});break
            if kind=='progress':
                report['artifacts'].update(data.get('artifact_snapshot',{}))
                if 'components' in data:report['components']=data['components']
                report['findings'].extend(data.get('new_findings',[]))
                report['files']=(report['files']+data.get('recent_files',[]))[-160:]
                for key in ('indexed_files','content_files','ignored_files','cache_hits','archive_reuses','issues_total','index_path','scan_id','excluded_paths','exclusion_reasons','internal_exclusions','scope_note','limits','cpu_target_cores'):
                    source='indexed' if key=='indexed_files' else key
                    if source in data:report[key]=data[source]
                progress(data)
    finally:
        # Never wait for an unresponsive reader after the wall-clock deadline.
        if proc.pid:
            if proc.is_alive():proc.terminate()
            proc.join(timeout=.2)
            if proc.is_alive():proc.kill();proc.join(timeout=.2)
        messages.cancel_join_thread();messages.close()
    if cancel.is_set() and not finished:report['status']='cancelled'
    report.setdefault('finished_at',now());report.setdefault('duration_seconds',round(time.monotonic()-started,3))
    report['issues_total']=max(report.get('issues_total',0),len(report['issues']))
    report['time_budget_seconds']=limit
    report['verdict']='review' if report['findings'] else 'no_match'
    if not finished:report['partial_snapshot']=True
    return report
