"""Local disk candidates: concurrent discovery, fresh readers and focused metadata."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib,json,os,queue,sqlite3,sys,threading,time,uuid
from statistics import median
from types import SimpleNamespace
import psutil
from . import __version__
from .engine import now
from .fileprobe import probe,fingerprint
from .index import FileIndex
from .collectors import collect_system
from .scope import excluded_locations
from .scanplan import ScanPlan
from .scanprogress import ScanProgress
from .contentcache import ContentCache
from .cpubudget import ScanControl
from .commandtraces import collect_command_traces
from .assessment import classify,name_context,process_context,report_verdict
from .methodcoverage import coverage
from .privacy import minimize_report,sanitize,NOTICE_VERSION
from .securestore import private_directory
from .integrity import integrity_state

VIRTUAL={'proc','sysfs','devtmpfs','devpts','tmpfs','cgroup','cgroup2','overlay','squashfs','autofs','nfs','nfs4','cifs','smbfs','fuse.sshfs'}


def computer_roots():
    if os.name=='nt':
        return [Path(p.mountpoint) for p in psutil.disk_partitions(all=False) if p.fstype and 'cdrom' not in p.opts and 'remote' not in p.opts]
    return [Path('/')]


def excluded_paths():
    result=[Path.home()/'.atlasac']
    if getattr(sys,'frozen',False) and getattr(sys,'_MEIPASS',None):result.append(Path(sys._MEIPASS).resolve())
    if os.name!='nt':
        result += [Path(p) for p in ('/proc','/sys','/dev','/run')]
        for part in psutil.disk_partitions(all=True):
            if part.fstype in VIRTUAL and part.mountpoint!='/':result.append(Path(part.mountpoint))
    return result


def system_scan(rules,roots=None,cancel=None,progress=None,data_dir=None,artifacts=True,cpu_cores=None):
    event=cancel or threading.Event()
    cancel=ScanControl(event) if cpu_cores is None else ScanControl(event,cores=cpu_cores)
    roots=[Path(r).resolve() for r in (computer_roots() if roots is None else roots)]
    base=Path(data_dir or Path.home()/'.atlasac');private_directory(base)
    started=time.monotonic();scan_id=uuid.uuid4().hex
    report={'application':'AtlasAC','version':__version__,'started_at':now(),'rule_version':rules['version'],'roots':list(map(str,roots)),'status':'completed','files':[],'findings':[],'issues':[],'artifacts':{'review_signals':[],'name_context':[]},'components':[],
            'cpu_target_cores':cancel.cores,'index_path':str(base/'file-index.sqlite3'),'scan_id':scan_id,'indexed_files':0,'content_files':0,'ignored_files':0,'cache_hits':0,'archive_reuses':0,'bytes_read':0,'issues_total':0,
            'limits':['Sanal dosya sistemleri, ağ bağlantıları, sembolik bağlantılar ve uygulamanın kendi kayıtları ve çalışan paketin geçici kaynakları hariç yerel diskler dolaşılır.',f'Okuyucular ve listeleme ortak {cancel.cores:g} çekirdek CPU hedefiyle çalışır; anlık işletim sistemi sınırı değildir.','İçerik: dosya 256 MiB; arşiv ağacı 256 MiB, 30 saniye, 30.000 üye, 2 iç seviye.','SQLite indeksi tanınan dosya biçimlerini ve sorunlu adayları tutar. Diğer adaylar da kontrol edilir; işlenen aday sayısı ayrı tutulur. JSON ve ekrandaki örnek listeler sınırlıdır.','Genel Trojan/bellek/DMA analizi ve Procmon çekirdek/Registry olay izlemesi sağlanmaz.']}
    if not roots:
        report.update(status='partial',finished_at=now(),duration_seconds=0,verdict='no_match',issues_total=1)
        report['issues'].append({'path':'Diskler','reason':'Taranabilecek yerel disk bulunamadı'});return report
    index=FileIndex(report['index_path']);skipped=excluded_locations();excluded=excluded_paths()+[base.resolve()]
    report['internal_exclusions']=list(map(str,excluded));report['excluded_paths']=list(map(str,skipped));report['exclusion_reasons']={str(p):reason+' — JAR/ZIP taranır, diğer dosyalar atlanır' for p,reason in skipped.items()};report['scope_note']='Oyun kütüphaneleri ve geliştirme önbelleklerinde yalnızca JAR/ZIP taranır. Diğer alanlarda aday dosya uzantıları incelenir; resim/video/belge uzantıları atlanır.'
    report['artifacts']['method_coverage']=coverage(report)
    pending_names=[]
    def issue(path,reason):
        report['issues_total']+=1
        if len(report['issues'])<2000:report['issues'].append({'path':str(path),'reason':str(reason)[:220]})
    index_enabled=True
    def disable_index(exc):
        nonlocal index_enabled
        index_enabled=False;report['index_available']=False;issue('Dosya indeksi',exc)
        index.buffer.clear();index.pending=0
        try:index.db.rollback()
        except sqlite3.Error:pass
    def flush_index():
        if index_enabled:
            try:index.flush()
            except (OSError,sqlite3.Error) as exc:disable_index(exc)
    # UI releases do not invalidate unchanged content inspection results.
    token=hashlib.sha256(('0.3.1-icons'+json.dumps(rules,sort_keys=True)).encode()).hexdigest()
    content_cache=ContentCache(signature_sizes=frozenset(s['size'] for rule in rules['rules'] for s in rule.get('file_signatures',[])))
    last_update=0;artifact_sent=False;recent=deque(maxlen=160);new_findings=[]
    plan=None;processed=0;estimator=ScanProgress()
    def remember(path,item):
        recent.append({'path':str(path),'status':'Kısmi' if item['issues'] else 'Eşleşme' if item['findings'] else 'İçerik incelendi' if item['file'] else 'Tanınan biçim yok',
                       'format':(item['file'] or {}).get('format',''),'name':', '.join(row['name'] for row in item['findings']),
                       'size':(item['file'] or {}).get('size'),'sha256':(item['file'] or {}).get('sha256')})
        new_findings.extend(item['findings'])
    def update(phase,path='',force=False):
        nonlocal last_update,artifact_sent
        if not force and time.monotonic()-last_update<=.12:return
        if force or time.monotonic()-index.last_flush>=1:flush_index()
        if plan is not None:
            state=plan.snapshot();report.update({k:v for k,v in state.items() if k not in ('discovery_error','discovery_finished')})
            report.update(estimator.update(processed,state['discovered_candidates'],state['discovery_complete'],time.monotonic()))
        payload={'phase':phase,'path':str(path),'indexed':report['indexed_files'],'matches':len(report['findings']),'cache_hits':report['cache_hits'],'elapsed':round(time.monotonic()-started,1),
                  'content_files':report['content_files'],'archive_reuses':report['archive_reuses'],'ignored_files':report['ignored_files'],'issues_total':report['issues_total'],
                  'recent_files':list(recent),'new_findings':list(new_findings),
                  'cpu_target_cores':report['cpu_target_cores'],'internal_exclusions':report['internal_exclusions'],'scope_note':report['scope_note'],'limits':report['limits'],
                  'index_path':report['index_path'],'scan_id':scan_id,'excluded_paths':report['excluded_paths'],'exclusion_reasons':report['exclusion_reasons']}
        for key in ('files_seen','discovered_candidates','directories_seen','discovery_complete','processed_candidates','total_candidates','progress_percent','eta_seconds'):
            if key in report:payload[key]=report[key]
        if not artifact_sent and report['artifacts']:
            payload['artifact_snapshot']={k:list(v) if isinstance(v,list) else v for k,v in report['artifacts'].items()};payload['components']=list(report['components']);artifact_sent=True
        if pending_names and 'artifact_snapshot' not in payload:payload['artifact_delta']={'name_context':list(pending_names)}
        pending_names.clear()
        if progress:progress(sanitize(payload))
        recent.clear();new_findings.clear()
        last_update=time.monotonic()
    def accept(entry,item,error=None):
        nonlocal processed
        path=Path(entry['path']);st=SimpleNamespace(st_size=entry['size'],st_mtime_ns=entry['modified_ns'])
        processed+=1
        try:
            if error:raise ValueError(error)
            classify(item['findings'])
            if index_enabled and (item['file'] or item['findings'] or item['issues']):
                try:index.put(path,st,scan_id,token,item);report['indexed_files']+=1
                except (OSError,sqlite3.Error) as exc:disable_index(exc)
            report['archive_reuses']+=int(item.get('archive_reused',False));report['bytes_read']+=item['bytes_read'];report['cache_hits']+=int(item['cache_hit'])
            if item['file']:
                report['content_files']+=1
                if len(report['files'])<2000:report['files'].append(item['file'])
            report['findings'].extend(item['findings']);remember(path,item)
            for row in item['issues']:issue(row['path'],row['reason'])
        except Exception as exc:issue(path,exc)
        update('Dosyalar taranıyor',path)
    try:
        if artifacts and not cancel.is_set():
            update('Komut geçmişi ve iz silme belirtileri okunuyor',force=True)
            records,alerts,component=collect_command_traces(cancel)
            report['artifacts'].update(records);report['components'].append(component)
            report['artifacts']['review_signals']=alerts
            report['artifacts']['method_coverage']=coverage(report);artifact_sent=False
            recent.extend({'path':a['path'],'status':'İnceleme sinyali; hile kanıtı değil','name':a['name']} for a in alerts)
            update('Komut kayıtları incelendi',force=True)
        plan=ScanPlan(roots,skipped,excluded,cancel,base)
        results=queue.Queue(maxsize=64);reader_stop=threading.Event()
        def send(record):
            while not reader_stop.is_set():
                try:results.put(record,timeout=.05);return
                except queue.Full:pass
        def read_candidates():
            try:
                while not reader_stop.is_set() and not cancel.is_set():
                    batch=plan.take(16)
                    if not batch:
                        if plan.exhausted():break
                        plan.wait();continue
                    for entry in batch:
                        if reader_stop.is_set() or cancel.is_set():break
                        if entry['kind']!='file':send((entry,None,None));continue
                        try:item=probe(Path(entry['path']),rules,cancel,None,content_cache)
                        except Exception as exc:send((entry,None,str(exc)[:220]))
                        else:send((entry,item,None))
            except Exception as exc:send(({'kind':'issue','path':'Dosya okuyucu','reason':str(exc)[:220]},None,None))
            finally:send((None,None,None))
        reader_limit=min(4,os.cpu_count() or 1);workers=min(2,reader_limit);opening=deque(maxlen=64)
        report['io_readers']=workers
        with ThreadPoolExecutor(max_workers=reader_limit) as pool:
            readers=[pool.submit(read_candidates) for _ in range(workers)];finished=0
            try:
                while finished<len(readers):
                    try:entry,item,error=results.get(timeout=.1)
                    except queue.Empty:
                        state=plan.snapshot()
                        update('Dosyalar taranıyor' if state['discovery_complete'] else 'Dosyalar listeleniyor ve taranıyor')
                        continue
                    if entry is None:finished+=1;continue
                    if entry['kind']=='issue':issue(entry['path'],entry['reason']);continue
                    if entry['kind']=='context':context=entry['row']
                    else:context=name_context(Path(entry['path']))
                    if context and len(report['artifacts']['name_context'])<1000:
                        report['artifacts']['name_context'].append(context);pending_names.append(context)
                    if entry['kind']=='file':
                        accept(entry,item,error)
                        if item is not None and 'open_seconds' in item:opening.append(item['open_seconds'])
                        # Extra readers help slow opens/antivirus waits, not CPU-bound archives.
                        # Their CPU still shares the same process-wide pacing allowance.
                        if len(readers)<reader_limit and len(opening)>=32 and median(opening)>=.001:
                            readers.extend(pool.submit(read_candidates) for _ in range(reader_limit-len(readers)))
                            report['io_readers']=len(readers)
            finally:reader_stop.set()
        state=plan.snapshot()
        if state['discovery_error']:issue('Dosya listesi',state['discovery_error'])
        update('Dosya incelemesi tamamlandı',force=True)
        if artifacts and not cancel.is_set():
            update('Sistem kayıtları inceleniyor')
            records,components=collect_system(roots,cancel,lambda phase:update(phase))
            report['artifacts'].update(records);report['components'].extend(components)
            report['artifacts'].update(process_context(records.get('processes',[])))
        if cancel.is_set():report['status']='cancelled'
        elif report['issues_total'] or any(c['status'] in ('partial','unavailable','error') for c in report['components']):report['status']='partial'
    finally:
        if plan is not None:plan.close()
        report['artifacts']['method_coverage']=coverage(report);artifact_sent=False
        update('Durduruluyor' if cancel.is_set() else 'Dosya incelemesi tamamlandı',force=True)
        try:index.close()
        except (OSError,sqlite3.Error) as exc:
            issue('Dosya indeksi',exc)
            if report['status']=='completed':report['status']='partial'
    if report['status']=='completed' and report['issues_total']:report['status']='partial'
    report['finished_at']=now();report['duration_seconds']=round(time.monotonic()-started,3);report['verdict']=report_verdict(report)
    report['integrity']=integrity_state(rules)
    report['privacy_notice_version']=NOTICE_VERSION
    return minimize_report(report)
