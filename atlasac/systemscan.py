"""Whole local computer scan: bounded content readers, full metadata traversal, local cache."""
from collections import deque
from concurrent.futures import ThreadPoolExecutor,wait,FIRST_COMPLETED
from pathlib import Path
import hashlib,json,os,stat,sys,threading,time,uuid
import psutil
from . import __version__
from .engine import now
from .fileprobe import probe,fingerprint
from .index import FileIndex
from .collectors import collect_system
from .scope import excluded_locations
from .filepolicy import candidate,directory_priority
from .contentcache import ContentCache
from .cpubudget import ScanControl
from .commandtraces import collect_command_traces
from .assessment import classify,name_context,process_context,report_verdict
from .methodcoverage import coverage
from .privacy import minimize_report,sanitize,NOTICE_VERSION
from .securestore import private_directory

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


def system_scan(rules,roots=None,cancel=None,progress=None,data_dir=None,artifacts=True):
    cancel=ScanControl(cancel or threading.Event());roots=[Path(r).resolve() for r in (computer_roots() if roots is None else roots)]
    base=Path(data_dir or Path.home()/'.atlasac');private_directory(base)
    started=time.monotonic();scan_id=uuid.uuid4().hex
    report={'application':'AtlasAC','version':__version__,'started_at':now(),'rule_version':rules['version'],'roots':list(map(str,roots)),'status':'completed','files':[],'findings':[],'issues':[],'artifacts':{'review_signals':[],'name_context':[]},'components':[],
            'cpu_target_cores':cancel.cores,'index_path':str(base/'file-index.sqlite3'),'scan_id':scan_id,'indexed_files':0,'content_files':0,'ignored_files':0,'cache_hits':0,'archive_reuses':0,'bytes_read':0,'issues_total':0,
            'limits':['Sanal dosya sistemleri, ağ bağlantıları, sembolik bağlantılar ve uygulamanın kendi kayıtları ve çalışan paketin geçici kaynakları hariç yerel diskler dolaşılır.','Okuyucular ortak CPU hedefiyle çalışır: mantıksal işlemci başına %5, toplam en fazla 0,6 çekirdek; anlık işletim sistemi sınırı değildir.','İçerik: dosya 256 MiB; arşiv ağacı 256 MiB, 30 saniye, 30.000 üye, 2 iç seviye.','Dosya listesi SQLite indeksindedir. JSON ve ekrandaki örnek listeler sınırlıdır; toplam sayaçlar ayrıca tutulur.','Genel Trojan/bellek/DMA analizi ve Procmon çekirdek/Registry olay izlemesi sağlanmaz.']}
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
    # UI releases do not invalidate unchanged content inspection results.
    token=hashlib.sha256(('0.3.1-icons'+json.dumps(rules,sort_keys=True)).encode()).hexdigest()
    content_cache=ContentCache();last_update=0;artifact_sent=False;recent=deque(maxlen=160);new_findings=[]
    def remember(path,item):
        recent.append({'path':str(path),'status':'Kısmi' if item['issues'] else 'Eşleşme' if item['findings'] else 'İçerik incelendi' if item['file'] else 'İndekslendi',
                       'format':(item['file'] or {}).get('format',''),'name':', '.join(row['name'] for row in item['findings'])})
        new_findings.extend(item['findings'])
    def update(phase,path='',force=False):
        nonlocal last_update,artifact_sent
        if progress and (force or time.monotonic()-last_update>.12):
            index.flush()
            payload={'phase':phase,'path':str(path),'indexed':report['indexed_files'],'matches':len(report['findings']),'cache_hits':report['cache_hits'],'elapsed':round(time.monotonic()-started,1),
                      'content_files':report['content_files'],'archive_reuses':report['archive_reuses'],'ignored_files':report['ignored_files'],'issues_total':report['issues_total'],
                      'recent_files':list(recent),'new_findings':list(new_findings),
                      'cpu_target_cores':report['cpu_target_cores'],'internal_exclusions':report['internal_exclusions'],'scope_note':report['scope_note'],'limits':report['limits'],
                      'index_path':report['index_path'],'scan_id':scan_id,'excluded_paths':report['excluded_paths'],'exclusion_reasons':report['exclusion_reasons']}
            if not artifact_sent and report['artifacts']:
                payload['artifact_snapshot']={k:list(v) if isinstance(v,list) else v for k,v in report['artifacts'].items()};payload['components']=list(report['components']);artifact_sent=True
            if pending_names and 'artifact_snapshot' not in payload:payload['artifact_delta']={'name_context':list(pending_names)}
            pending_names.clear()
            progress(sanitize(payload))
            recent.clear();new_findings.clear()
            last_update=time.monotonic()
    def accept(future):
        path,st=futures.pop(future);item=None
        try:
            item=future.result();classify(item['findings']);index.put(path,st,scan_id,token,item)
            report['archive_reuses']+=int(item.get('archive_reused',False));report['indexed_files']+=1;report['bytes_read']+=item['bytes_read'];report['cache_hits']+=int(item['cache_hit'])
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
        with ThreadPoolExecutor(max_workers=min(2,os.cpu_count() or 1)) as pool:
            futures={};stack=[(p,any(p==folder or p.is_relative_to(folder) for folder in skipped)) for p in reversed(roots)]
            while stack and not cancel.is_set():
                directory,archives_only=stack.pop();children=[]
                try:
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            if cancel.is_set():break
                            path=Path(entry.path)
                            if any(path==p for p in excluded):continue
                            try:
                                if entry.is_file(follow_symlinks=False) and not candidate(path,archives_only):
                                    report['ignored_files']+=1;update('Aday dosyalar aranıyor');continue
                                st=entry.stat(follow_symlinks=False)
                                if entry.is_symlink() or getattr(st,'st_file_attributes',0)&0x400:
                                    issue(path,'Bağlantı / yeniden yönlendirme izlenmedi');continue
                                if len(report['artifacts']['name_context'])<1000:
                                    context=name_context(path)
                                    if context:report['artifacts']['name_context'].append(context);pending_names.append(context)
                                if stat.S_ISDIR(st.st_mode):children.append((path,archives_only or path in skipped))
                                elif stat.S_ISREG(st.st_mode):
                                    cached=index.cached(path,token)
                                    # Unix ctime catches restored mtimes; Windows uses native ChangeTime in probe().
                                    stamp=fingerprint(st) if os.name!='nt' else None
                                    if cached and stamp and cached.get('fingerprint')==stamp:
                                        classify(cached['findings']);cached['cache_hit']=True;cached['bytes_read']=0
                                        index.put(path,st,scan_id,token,cached);report['indexed_files']+=1;report['cache_hits']+=1
                                        if cached['file']:
                                            report['content_files']+=1
                                            if len(report['files'])<2000:report['files'].append(cached['file'])
                                        report['findings'].extend(cached['findings']);remember(path,cached);update('Önbellek doğrulanıyor',path)
                                    else:futures[pool.submit(probe,path,rules,cancel,cached,content_cache)]=(path,st)
                                    if len(futures)>=24:
                                        done,_=wait(futures,return_when=FIRST_COMPLETED)
                                        for future in done:accept(future)
                            except OSError as exc:issue(path,exc)
                except OSError as exc:issue(directory,exc)
                stack.extend(sorted(children,key=lambda pair:directory_priority(*pair),reverse=True))
            while futures:
                done,_=wait(futures,return_when=FIRST_COMPLETED)
                for future in done:accept(future)
        if artifacts and not cancel.is_set():
            update('Sistem kayıtları inceleniyor')
            records,components=collect_system(roots,cancel,lambda phase:update(phase))
            report['artifacts'].update(records);report['components'].extend(components)
            report['artifacts'].update(process_context(records.get('processes',[])))
        if cancel.is_set():report['status']='cancelled'
        elif report['issues_total'] or any(c['status'] in ('partial','unavailable','error') for c in report['components']):report['status']='partial'
    finally:
        report['artifacts']['method_coverage']=coverage(report);artifact_sent=False
        update('Durduruluyor' if cancel.is_set() else 'Dosya incelemesi tamamlandı',force=True)
        index.close()
    report['finished_at']=now();report['duration_seconds']=round(time.monotonic()-started,3);report['verdict']=report_verdict(report)
    report['privacy_notice_version']=NOTICE_VERSION
    return minimize_report(report)
