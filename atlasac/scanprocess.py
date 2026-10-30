"""Cancellable scan process with an optional explicit wall-clock budget."""
import multiprocessing as mp
import math,queue,time,secrets
from functools import partial
from .cpubudget import cpu_target
from .engine import now
from .systemscan import system_scan
from . import __version__
from .assessment import report_verdict
from .methodcoverage import coverage
from .privacy import minimize_report,sanitize,NOTICE_VERSION
from .integrity import SessionMessages,validate_packet,validate_progress,checked_final,mark_failure,integrity_state,require_official_rules,attach_receipt

def scan_child(messages,cancel,rules,roots,data_dir,artifacts,cpu_cores=None):
    try:
        report=system_scan(rules,roots,cancel,lambda data:messages.put(('progress',data)),data_dir,artifacts,cpu_cores)
        messages.put(('ready',report))
    except Exception as exc:messages.put(('error',str(exc)[:300]))

def session_child(messages,cancel,rules,roots,data_dir,artifacts,session,target):
    target(SessionMessages(messages,session),cancel,rules,roots,data_dir,artifacts)


def run_scan(rules,roots,data_dir,artifacts,cancel,progress,max_seconds=None,target=scan_child,speed='low'):
    require_official_rules(rules)
    cores=cpu_target(speed)
    if speed!='low':target=partial(target,cpu_cores=cores)
    limit=None if max_seconds is None else float(max_seconds)
    if limit is not None and (not math.isfinite(limit) or limit<=0):
        raise ValueError('Tarama süre sınırı pozitif ve sonlu bir saniye değeri olmalı.')
    started=time.monotonic();session=secrets.token_hex(24);sequence=1;ctx=mp.get_context('spawn');messages=ctx.Queue(maxsize=8);child_cancel=ctx.Event()
    report={'application':'AtlasAC','version':__version__,'started_at':now(),'rule_version':rules['version'],
            'status':'running','roots':list(map(str,roots)),'findings':[],'files':[],'issues':[],'artifacts':{},'components':[],
            'indexed_files':0,'content_files':0,'ignored_files':0,'cache_hits':0,'issues_total':0,'excluded_paths':[],'time_budget_seconds':limit}
    proc=ctx.Process(target=session_child,args=(messages,child_cancel,rules,roots,data_dir,artifacts,session,target),daemon=True)
    cancel_at=None;finished=False
    try:
        proc.start()
        while True:
            elapsed=time.monotonic()-started
            if cancel.is_set():
                child_cancel.set()
                if cancel_at is None:cancel_at=time.monotonic()
                if time.monotonic()-cancel_at>=1:
                    report['status']='cancelled';break
            if limit is not None and elapsed>=limit:
                child_cancel.set();report['status']='partial';report['stop_reason']='time_budget'
                report['issues'].append({'path':'Tarama süresi','reason':f'{limit:g} saniyelik tarama sınırına ulaşıldı; tarama tamamlanmadı.'});break
            try:packet=messages.get(timeout=.1 if limit is None else min(.1,max(.001,limit-elapsed)))
            except queue.Empty:
                if not proc.is_alive():
                    report['status']='cancelled' if cancel.is_set() else 'partial'
                    if not cancel.is_set():report['issues'].append({'reason':'Tarama işlemi sonuç üretmeden kapandı'})
                    break
                continue
            try:kind,data=validate_packet(packet,session,sequence);sequence+=1
            except ValueError as exc:mark_failure(report,str(exc));break
            if kind=='ready':
                try:report=checked_final(report,data,rules,roots)
                except (ValueError,TypeError,KeyError) as exc:mark_failure(report,'Final rapor doğrulanamadı: '+str(exc)[:160])
                finished=True;break
            if kind=='error':report['status']='partial';report['issues'].append({'reason':data});break
            if kind=='progress':
                try:validate_progress(data,report)
                except ValueError as exc:mark_failure(report,str(exc));break
                report['artifacts'].update(data.get('artifact_snapshot',{}))
                for key,rows in data.get('artifact_delta',{}).items():report['artifacts'].setdefault(key,[]).extend(rows)
                if 'components' in data:report['components']=data['components']
                report['findings'].extend(data.get('new_findings',[]))
                report['files']=(report['files']+data.get('recent_files',[]))[-160:]
                for key in ('indexed_files','content_files','ignored_files','cache_hits','archive_reuses','issues_total','index_path','scan_id','excluded_paths','exclusion_reasons','internal_exclusions','scope_note','limits','cpu_target_cores','files_seen','discovered_candidates','directories_seen','discovery_complete','processed_candidates','total_candidates','progress_percent','eta_seconds'):
                    source='indexed' if key=='indexed_files' else key
                    if source in data:report[key]=data[source]
                progress(sanitize(data))
    finally:
        # Cancellation and an explicitly requested deadline can kill stuck readers.
        if proc.pid:
            if proc.is_alive():proc.terminate()
            proc.join(timeout=.2)
            if proc.is_alive():proc.kill();proc.join(timeout=.2)
        messages.cancel_join_thread();messages.close()
    if cancel.is_set() and not finished:report['status']='cancelled'
    report.setdefault('finished_at',now());report.setdefault('duration_seconds',round(time.monotonic()-started,3))
    report['issues_total']=max(report.get('issues_total',0),len(report['issues']))
    report['time_budget_seconds']=limit
    report['scan_speed']=speed
    report.setdefault('integrity',integrity_state(rules))
    report['scan_session_id']=session
    report['privacy_notice_version']=NOTICE_VERSION
    report['verdict']=report_verdict(report)
    report['artifacts']['method_coverage']=coverage(report)
    if not finished:report['partial_snapshot']=True
    return attach_receipt(report)
