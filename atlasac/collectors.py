"""Read-only platform artefacts. No credentials/cookies, deletion or external uploads."""
from pathlib import Path
from datetime import datetime,timezone,timedelta
import configparser,csv,io,json,os,sqlite3,subprocess,tempfile,time,threading,shutil,hashlib
import psutil
from .engine import now


def run(argv,timeout=20):
    result=subprocess.run(argv,capture_output=True,timeout=timeout,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode:raise OSError(result.stderr.decode('utf-8',errors='replace')[-500:])
    return result.stdout.decode('utf-8-sig',errors='replace')


def browser_profiles():
    home=Path.home();profiles=[]
    homes=[home]
    if os.name=='nt':
        users=Path(os.environ.get('SystemDrive','C:')+'/Users')
        if users.is_dir():homes=[p for p in users.iterdir() if p.is_dir() and p.name not in ('Public','Default','Default User','All Users')]
    for user in homes:
        if os.name=='nt':
            local=user/'AppData/Local';roam=user/'AppData/Roaming'
            chromium=[('Chrome',local/'Google/Chrome/User Data'),('Edge',local/'Microsoft/Edge/User Data'),('Brave',local/'BraveSoftware/Brave-Browser/User Data'),('Vivaldi',local/'Vivaldi/User Data'),('Opera',roam/'Opera Software/Opera Stable')]
            firefox=[roam/'Mozilla/Firefox/Profiles']
        else:
            chromium=[(n,user/p) for n,p in [('Chrome','.config/google-chrome'),('Chromium','.config/chromium'),('Brave','.config/BraveSoftware/Brave-Browser'),('Vivaldi','.config/vivaldi'),('Opera','.config/opera')]]
            firefox=[user/'.mozilla/firefox',user/'.var/app/org.mozilla.firefox/.mozilla/firefox']
        for name,root in chromium:
            if root.exists():
                candidates=[root]+list(root.glob('Default'))+list(root.glob('Profile *'))
                profiles.extend((name,p.name,p/'History','chromium') for p in candidates if (p/'History').is_file())
        for root in firefox:
            if root.exists():profiles.extend(('Firefox',p.name,p/'places.sqlite','firefox') for p in root.iterdir() if p.is_dir() and (p/'places.sqlite').is_file())
    return list(dict.fromkeys(profiles))


def snapshot_database(path,cancel,timeout=10):
    path=Path(path)
    temp=tempfile.TemporaryDirectory(prefix='atlasac-history-');target=Path(temp.name)/'snapshot.sqlite'
    source=dest=None;deadline=time.monotonic()+timeout
    def progress(*args):
        if cancel.is_set() or time.monotonic()>deadline:raise TimeoutError('Canlı veritabanı anlık kopyası zaman aşımı')
    try:
        source=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True,timeout=.3)
        dest=sqlite3.connect(target);source.backup(dest,pages=128,progress=progress,sleep=.02)
    except (sqlite3.Error,TimeoutError):
        if source:source.close()
        if dest:dest.close()
        temp.cleanup()
        if cancel.is_set():raise InterruptedError('Tarama durduruldu')
        # Chromium may keep an EXCLUSIVE SQLite lock. Clone a stable database plus
        # WAL/rollback journal; SQLite recovers ONLY this private copy, never the source.
        for attempt in range(2):
            temp=tempfile.TemporaryDirectory(prefix='atlasac-history-');target=Path(temp.name)/'snapshot.sqlite'
            try:
                sources=[(path,target)]
                for suffix in ('-wal','-journal'):
                    side=Path(str(path)+suffix)
                    if side.exists():sources.append((side,Path(str(target)+suffix)))
                before={str(src):(src.stat().st_ino,src.stat().st_size,src.stat().st_mtime_ns,src.stat().st_ctime_ns) for src,_ in sources}
                if any(v[1]>256*1024*1024 for v in before.values()):raise ValueError('Tarayıcı kayıt kopyası boyut sınırı')
                for src,dst in sources:
                    if cancel.is_set():raise InterruptedError('Tarama durduruldu')
                    shutil.copyfile(src,dst)
                after={str(src):(src.stat().st_ino,src.stat().st_size,src.stat().st_mtime_ns,src.stat().st_ctime_ns) for src,_ in sources}
                if before!=after or any(Path(str(path)+suffix).exists()!=any(str(src)==str(path)+suffix for src,_ in sources) for suffix in ('-wal','-journal')):
                    raise OSError('Tarayıcı veritabanı kopyalama sırasında değişti')
                for src,dst in sources:
                    with open(src,'rb') as original,open(dst,'rb') as copied:
                        if hashlib.file_digest(original,'sha256').digest()!=hashlib.file_digest(copied,'sha256').digest():
                            raise OSError('Tarayıcı veritabanı kopyalama sırasında değişti')
                check=sqlite3.connect(target)
                try:
                    if check.execute('PRAGMA quick_check(1)').fetchone()[0]!='ok':raise OSError('Tarayıcı kopyası bütünlük denetimi başarısız')
                finally:check.close()
                temp.atlasac_snapshot_method='stable-copy'
                return temp,target
            except (OSError,sqlite3.Error,ValueError):
                temp.cleanup()
                if attempt:raise
    finally:
        if source:source.close()
        if dest:dest.close()
    return temp,target


def timestamp(value,kind):
    try:
        if not value:return ''
        if kind=='chrome':return (datetime(1601,1,1,tzinfo=timezone.utc)+timedelta(microseconds=int(value))).isoformat()
        return datetime.fromtimestamp(float(value)/(1e6 if kind=='firefox' else 1),timezone.utc).isoformat()
    except (ValueError,OverflowError,OSError):return str(value)


def collect_browsers(cancel):
    history=[];downloads=[];errors=[]
    try:profiles=browser_profiles()
    except OSError as exc:return {'history':[],'downloads':[]},[str(exc)],0
    for browser,profile,path,kind in profiles:
        if cancel.is_set():break
        temp=None
        try:
            temp,snapshot=snapshot_database(path,cancel)
            if getattr(temp,'atlasac_snapshot_method','')=='stable-copy':errors.append(f'{browser}/{profile}: SQLite kilidi; değişiklik denetimli yerel kopya kullanıldı, atomik snapshot değildir')
            db=sqlite3.connect(snapshot)
            try:
                if kind=='chromium':
                    for url,title,visited,count in db.execute('SELECT url,title,last_visit_time,visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 3000'):
                        history.append({'browser':browser,'profile':profile,'url':url,'title':title,'visited_at':timestamp(visited,'chrome'),'visits':count})
                    columns={row[1] for row in db.execute('PRAGMA table_info(downloads)')}
                    if columns:
                        fields=[x for x in ('id','target_path','current_path','start_time','end_time','received_bytes','total_bytes','state','tab_url') if x in columns]
                        chains={}
                        if db.execute("SELECT 1 FROM sqlite_master WHERE name='downloads_url_chains'").fetchone():
                            for ident,url in db.execute('SELECT id,url FROM downloads_url_chains ORDER BY chain_index'):chains[ident]=url
                        for row in db.execute('SELECT '+','.join(fields)+' FROM downloads ORDER BY start_time DESC LIMIT 3000'):
                            item=dict(zip(fields,row));item.update(browser=browser,profile=profile,url=chains.get(item.get('id'),item.get('tab_url','')))
                            for f in ('start_time','end_time'):
                                if f in item:item[f]=timestamp(item[f],'chrome')
                            downloads.append(item)
                else:
                    for url,title,visited,count in db.execute('SELECT url,title,last_visit_date,visit_count FROM moz_places WHERE last_visit_date IS NOT NULL ORDER BY last_visit_date DESC LIMIT 3000'):
                        history.append({'browser':browser,'profile':profile,'url':url,'title':title,'visited_at':timestamp(visited,'firefox'),'visits':count})
                    tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    if {'moz_annos','moz_anno_attributes'}<=tables:
                        query='SELECT p.url,p.title,a.content,a.lastModified,n.name FROM moz_annos a JOIN moz_anno_attributes n ON n.id=a.anno_attribute_id JOIN moz_places p ON p.id=a.place_id WHERE n.name LIKE ? LIMIT 3000'
                        for url,title,content,modified,name in db.execute(query,('downloads/%',)):
                            downloads.append({'browser':browser,'profile':profile,'url':url,'title':title,'data':content,'type':name,'modified_at':timestamp(modified,'firefox')})
            finally:db.close()
        except (OSError,sqlite3.Error,TimeoutError,ValueError) as exc:errors.append(f'{browser}/{profile}: {exc}')
        finally:
            if temp:temp.cleanup()
    return {'history':history,'downloads':downloads},errors,len(profiles)


def processes(cancel):
    result=[];modules=[];denied=0
    for proc in psutil.process_iter(['pid','ppid','name','exe','cmdline','username','create_time','memory_info','num_threads'],ad_value=None):
        if cancel.is_set():break
        try:
            info=dict(proc.info);mem=info.pop('memory_info',None);info['rss']=mem.rss if mem else None
            info['started_at']=timestamp(info.pop('create_time',None),'unix');result.append(info)
            # DLL/map inspection is relevant for launchers/games and this tool, not every protected service.
            if any(s in (info.get('name') or '').lower() for s in ('java','minecraft','prism','atlasac')):
                try:
                    for item in proc.memory_maps(grouped=True):
                        if item.path and not item.path.startswith('['):modules.append({'pid':proc.pid,'process':info['name'],'path':item.path,'rss':getattr(item,'rss',None)})
                except (psutil.Error,OSError):denied+=1
        except (psutil.Error,OSError):denied+=1
    return {'processes':result,'modules':modules},denied


def linux_records(cancel):
    startup=[];usb=[];events=[];errors=[]
    for root in [Path('/etc/xdg/autostart'),Path.home()/'.config/autostart']:
        for p in root.glob('*.desktop'):
            try:
                cfg=configparser.ConfigParser(interpolation=None,strict=False);cfg.read(p,encoding='utf-8');section=cfg['Desktop Entry']
                startup.append({'source':str(p),'name':section.get('Name',p.stem),'command':section.get('Exec',''),'hidden':section.get('Hidden','false')})
            except (OSError,configparser.Error) as exc:errors.append(str(exc))
    for root in [Path('/etc/systemd/system'),Path('/usr/lib/systemd/system'),Path.home()/'.config/systemd/user']:
        try:
            for folder in root.glob('*.wants'):
                for p in folder.iterdir():startup.append({'source':str(p),'name':p.name,'target':str(p.resolve())})
        except OSError as exc:errors.append(str(exc))
    for p in Path('/sys/bus/usb/devices').glob('*'):
        if (p/'idVendor').exists():
            item={'source':str(p)}
            for key in ['idVendor','idProduct','manufacturer','product','serial']:
                try:item[key]=(p/key).read_text().strip()
                except OSError:pass
            usb.append(item)
    try:
        output=run(['journalctl','--no-pager','-n','500','-o','json'],timeout=10)
        for line in output.splitlines():
            try:
                row=json.loads(line);events.append({'timestamp':timestamp(row.get('__REALTIME_TIMESTAMP'),'firefox'),'provider':row.get('_SYSTEMD_UNIT',''),'message':row.get('MESSAGE',''),'pid':row.get('_PID','')})
            except ValueError:pass
    except (OSError,subprocess.SubprocessError) as exc:errors.append('journalctl: '+str(exc))
    return {'startup':startup,'usb':usb,'events':events},errors


def collect_system(roots,cancel,progress):
    data={};components=[]
    progress('İşlemler ve modüller okunuyor');rows,denied=processes(cancel);data.update(rows)
    components.append({'name':'İşlemler / oyun modülleri','status':'partial' if denied else 'completed','records':len(rows['processes'])+len(rows['modules']),'detail':f'{denied} korumalı veya kapanmış süreç; modüller oyun/launcher/AtlasAC süreçlerinde okunur.'})
    if cancel.is_set():return data,components
    progress('Tarayıcı kayıtları okunuyor');rows,errors,count=collect_browsers(cancel);data.update(rows)
    components.append({'name':'Tarayıcı geçmişi / indirmeler','status':'partial' if errors else 'completed','records':len(rows['history'])+len(rows['downloads']),'detail':f'{count} profil; profil başına son 3000 kayıt. '+ '; '.join(errors)[:800]})
    if os.name=='nt':
        from .winrecords import windows_records
        progress('Windows başlangıç, USB ve etkinlik kayıtları okunuyor');rows,more=windows_records(roots,cancel);data.update(rows);components+=more
    else:
        progress('Başlangıç, USB ve günlükler okunuyor');rows,errors=linux_records(cancel);data.update(rows)
        components.append({'name':'Linux başlangıç / USB / journal','status':'partial' if errors else 'completed','records':sum(map(len,rows.values())),'detail':'; '.join(errors)[:800] or 'USB: şu an bağlı aygıtlar. Journal: erişilebilen son 500 olay.'})
        components.append({'name':'USN / Windows Prefetch','status':'not_applicable','records':0,'detail':'Windows kayıt biçimleri; Linux üzerinde eşdeğer Windows kaydı yok.'})
    components.append({'name':'Procmon çekirdek izleme','status':'unavailable','records':0,'detail':'Çekirdek dosya/Registry/stack yakalama sürücüsü eklenmedi. Bu kayıtlar canlı Procmon yakalaması değildir.'})
    return data,components
