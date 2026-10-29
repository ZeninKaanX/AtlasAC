"""Bounded, read-only command artefacts; history and patterns are not proof of intent."""
from datetime import datetime,timezone
import psutil
import base64
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET

MAX_COMMAND=4096
MAX_RECORDS=1200
EVENT_LIMIT=200
NS={'e':'http://schemas.microsoft.com/win/2004/08/events/event'}
SOURCES=(
    ('Windows PowerShell',(400,800)),
    ('Microsoft-Windows-PowerShell/Operational',(4103,4104)),
    ('Security',(1102,4688)),
    ('System',(104,)),
    ('PowerShellCore/Operational',(4103,4104)),
    ('Microsoft-Windows-Sysmon/Operational',(1,)),
)
# Commands at a statement boundary, rather than arbitrary quoted tutorial text.
BOUNDARY=r'(?:^|[;\n|&])\s*(?:&\s*)?'
PATTERNS=(
    ('log-clear-command','Olay günlüğü temizleme komutu',r'(?:wevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|Clear-EventLog\b)'),
    ('history-clear-command','Komut geçmişi temizleme komutu',r'(?:Clear-History\b|history\s+-[a-z]*c\b|Set-PSReadLineOption\b[^;\n]{0,300}-HistorySaveStyle\s+[\'"]?SaveNothing\b)'),
    ('trace-file-delete','İz dosyası silme komutu',r'(?:Remove-Item|Clear-Content|del|erase|rm|truncate)\b[^;\n]{0,800}(?:PSReadLine|(?:_history|\.bash_history|\.zsh_history|ConsoleHost_history)\b|Prefetch[\\/]|\.evtx\b)'),
    ('journal-delete-command','USN günlüğü silme komutu',r'fsutil(?:\.exe)?\s+usn\s+deletejournal\b'),
    ('free-space-wipe-command','Boş alan üzerine yazma komutu',r'cipher(?:\.exe)?\s+/w(?::|\s|$)'),
    ('audit-disable-command','Denetim kaydını kapatma komutu',r'auditpol(?:\.exe)?\s+(?:/clear\b|/set\b[^;\n]{0,400}/(?:success|failure):disable\b)'),
)
COMPILED=[(rule,name,re.compile(BOUNDARY+body,re.I)) for rule,name,body in PATTERNS]

def redact(text):
    return re.sub(r'(?i)((?:password|passwd|token|api[_-]?key|secret)\s*[=:]\s*)(?:"[^"\n]*"|\'[^\'\n]*\'|[^\s;]+)',r'\1[REDACTED]',str(text))[:MAX_COMMAND]

def command_body(text):
    text=str(text)[:65536].strip()
    # A launch command may wrap the script in a single -Command argument.
    match=re.match(r'(?is)^\s*["\']?(?:[^"\'\s]*[\\/])?(?:powershell|pwsh)(?:\.exe)?["\']?\s+.*?-(?:command|c)\s+(.+)$',text)
    if match:
        text=match.group(1).strip()
        if len(text)>1 and text[0]==text[-1] and text[0] in "\"'":text=text[1:-1]
    match=re.match(r'(?is)^\s*(?:[^\s]*[\\/])?cmd(?:\.exe)?\s+/(?:c|k)\s+(.+)$',text)
    if match:text=match.group(1).strip().strip('"')
    return text

def outside_quotes(text,position):
    quote='';comment=False;escape=False
    for ch in text[:position]:
        if escape:escape=False;continue
        if ch=='`':escape=True;continue
        if comment:
            if ch=='\n':comment=False
            continue
        if quote:
            if ch==quote:quote=''
        elif ch in "\"'":quote=ch
        elif ch=='#':comment=True
    return not quote and not comment

def analyze(records,cancel=None):
    findings=[];seen=set()
    for row in records:
        if cancel is not None and cancel.is_set():break
        text=command_body(row.get('command',''));decoded=False
        encoded=re.search(r'(?i)(?:^|\s)-(?:enc|encodedcommand|e)\s+["\']?([A-Za-z0-9+/=]{4,65536})',text)
        if encoded:
            try:
                text=command_body(base64.b64decode(encoded.group(1),validate=True).decode('utf-16-le'));decoded=True
            except (ValueError,UnicodeError):pass
        hits=[]
        if row.get('kind')=='log-cleared':hits.append(('log-cleared','Windows olay günlüğü temizlenmiş'))
        hits.extend((rule,name) for rule,name,pattern in COMPILED if any(outside_quotes(text,m.start()) for m in pattern.finditer(text)))
        for rule,name in hits:
            identity=(rule,row.get('source'),row.get('record_id'),row.get('timestamp'),text)
            if identity in seen:continue
            seen.add(identity)
            findings.append({'rule':rule,'name':name,'category':'anti-forensics','severity':'review',
                'path':row.get('source','Komut kaydı'),'method':row.get('kind','command-pattern'),
                'timestamp':row.get('timestamp',''),'record_id':row.get('record_id',''),
                'evidence':[redact(text) if text else 'Windows Event '+str(row.get('event_id'))],
                'note':('Windows olay kaydı günlük temizlendiğini bildiriyor; nedenini veya hile kullanımını kanıtlamaz.' if row.get('kind')=='log-cleared' else 'Komut deseni; geçmiş değiştirilebilir. Komutun başarılı olduğunu, kötü niyeti veya hile kullanımını kanıtlamaz.')+(' EncodedCommand statik çözüldü; çalıştırılmadı.' if decoded else '')})
    return findings

def parse_events(xml,channel):
    root=ET.fromstring(xml);rows=[]
    events=[root] if root.tag.endswith('Event') else list(root)
    for event in events:
        system=event.find('e:System',NS)
        if system is None:continue
        ident=int(system.findtext('e:EventID','0',NS));provider=system.find('e:Provider',NS)
        provider=provider.get('Name','') if provider is not None else ''
        values={node.get('Name',str(i)):''.join(node.itertext()) for i,node in enumerate(event.findall('e:EventData/e:Data',NS))}
        when=system.find('e:TimeCreated',NS);stamp=when.get('SystemTime','') if when is not None else ''
        common={'source':channel,'event_id':ident,'record_id':system.findtext('e:EventRecordID','',NS),'timestamp':stamp,'provider':provider}
        if ((channel=='Security' and ident==1102) or (channel=='System' and ident==104)) and provider=='Microsoft-Windows-Eventlog':
            rows.append(dict(common,kind='log-cleared',command='',detail='Günlük temizleme olayı; nedeni bu kayıttan belirlenemez.'));continue
        command='';kind='event-command'
        if ident==4104:command=values.get('ScriptBlockText','');kind='script-block'
        elif ident==4103:command=values.get('Payload','');kind='module-log'
        elif ident in (4688,1):
            command=values.get('CommandLine','')
            image=values.get('NewProcessName',values.get('Image','')).lower().replace('\\','/').rsplit('/',1)[-1]
            if image not in ('cmd.exe','powershell.exe','pwsh.exe','wevtutil.exe','fsutil.exe','cipher.exe','auditpol.exe'):continue
        elif ident in (400,800):
            raw='\n'.join(values.values());match=re.search(r'(?im)^\s*HostApplication\s*=\s*(.+)$',raw)
            if match:command=match.group(1)
        if command:
            rows.append(dict(common,kind=kind,command=redact(command),truncated=len(command)>MAX_COMMAND,
                fragment=values.get('MessageNumber',''),fragment_total=values.get('MessageTotal',''),
                detail='Kaydedilmiş metin; komutun başarıyla tamamlandığını göstermez.'))
    return rows

def decode_windows_text(raw):
    if raw.startswith((b'\xff\xfe',b'\xfe\xff')):return raw.decode('utf-16',errors='replace')
    return raw.decode('utf-16-le' if b'\x00' in raw[:40] else 'utf-8-sig',errors='replace')

def live_commands(cancel):
    rows=[]
    for proc in psutil.process_iter(['pid','name','cmdline','create_time'],ad_value=None):
        if cancel.is_set():break
        try:
            info=proc.info
            if (info.get('name') or '').lower() not in ('cmd.exe','powershell.exe','pwsh.exe','pwsh','powershell','bash','zsh','wevtutil.exe'):continue
            args=info.get('cmdline') or []
            if len(args)<2:continue
            command=subprocess.list2cmdline(args) if os.name=='nt' else ' '.join(args)
            stamp=datetime.fromtimestamp(info['create_time'],timezone.utc).isoformat() if info.get('create_time') else ''
            rows.append({'source':'İşlem PID '+str(proc.pid),'kind':'live-command','timestamp':stamp,'record_id':str(proc.pid),'command':redact(command),'truncated':len(command)>MAX_COMMAND,'detail':'Canlı sürecin açılış komut satırı; etkileşimli konsolda yazılan bütün komutlar değildir.'})
            if len(rows)>=100:break
        except (psutil.Error,OSError):continue
    return rows

def event_query(channel,ids,timeout):
    query='*[System[('+ ' or '.join('EventID='+str(i) for i in ids)+') and TimeCreated[timediff(@SystemTime) <= 604800000]]]'
    # Temporary file prevents unbounded stdout capture from very large script blocks.
    with tempfile.TemporaryFile() as output:
        result=subprocess.run(['wevtutil.exe','qe',channel,'/q:'+query,'/c:'+str(EVENT_LIMIT),'/rd:true','/f:xml','/e:Events','/uni:true'],stdout=output,stderr=subprocess.PIPE,timeout=timeout,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if result.returncode:raise OSError(decode_windows_text(result.stderr)[:220])
        if output.tell()>8*1024*1024:raise ValueError('Olay çıktısı 8 MiB sınırında; kanal eksik')
        output.seek(0);raw=output.read()
    if not raw.strip():return [],False
    xml=decode_windows_text(raw)
    rows=parse_events(xml,channel)
    return rows,len(ET.fromstring(xml))>=EVENT_LIMIT

def history_files():
    homes=[Path.home()]
    if os.name=='nt':
        users=Path(os.environ.get('SystemDrive','C:')+'/Users')
        try:homes=list(users.iterdir())[:100]
        except OSError:pass
    for home in homes:
        if os.name=='nt':
            root=home/'AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine'
        else:
            root=Path(os.environ.get('XDG_DATA_HOME',str(home/'.local/share')))/'powershell/PSReadLine'
            for name in ('.bash_history','.zsh_history'):
                if (home/name).is_file():yield home/name
        try:yield from root.glob('*_history.txt')
        except OSError:continue

def read_history(path,remaining):
    # Retain only recent bounded text; mtime is NOT a per-command execution time.
    with path.open('rb') as stream:
        size=stream.seek(0,2);start=max(0,size-1024*1024);stream.seek(start);raw=stream.read(1024*1024)
    lines=raw.decode('utf-8-sig',errors='replace').splitlines()
    if start and lines:lines=lines[1:]
    lines=lines[-min(remaining,1000):];rows=[]
    for i,line in enumerate(lines):
        if not line.strip():continue
        rows.append({'source':str(path),'kind':'history','record_id':'tail-'+str(i+1),'timestamp':'','command':redact(line),'truncated':len(line)>MAX_COMMAND,'detail':'Geçmiş satırı; yürütme/başarı ve komut zamanı kanıtı değildir. Son 1 MiB / 1000 satır.'})
    return rows,size>1024*1024 or len(lines)>=min(remaining,1000)

def collect_command_traces(cancel):
    records=live_commands(cancel);coverage=[];deadline=time.monotonic()+18
    try:paths=list(history_files())[:32]
    except OSError as exc:paths=[];coverage.append({'source':'Komut geçmişi','status':'partial','detail':str(exc)[:200]})
    # Event sources get room even if a history file is long.
    for path in paths:
        if cancel.is_set() or len(records)>=400:
            coverage.append({'source':str(path),'status':'partial','detail':'Geçmiş kayıt sınırı / iptal'});continue
        try:
            rows,limited=read_history(path,400-len(records));records.extend(rows)
            coverage.append({'source':str(path),'status':'partial' if limited else 'completed','records':len(rows),'detail':'Salt okunur geçmiş; satırlar değiştirilebilir.'})
        except OSError as exc:coverage.append({'source':str(path),'status':'unavailable','detail':str(exc)[:200]})
    if not paths:coverage.append({'source':'Komut geçmişi','status':'unavailable','detail':'Geçmiş dosyası bulunamadı; silindiğinin kanıtı değildir.'})
    if os.name=='nt':
        for channel,ids in SOURCES:
            if cancel.is_set() or time.monotonic()>=deadline:
                coverage.append({'source':channel,'status':'partial','detail':'Komut kaydı toplama bütçesi / iptal'});continue
            try:
                rows,limited=event_query(channel,ids,min(3,max(.1,deadline-time.monotonic())))
                room=MAX_RECORDS-len(records);records.extend(rows[:room])
                coverage.append({'source':channel,'status':'partial' if limited or len(rows)>room or any(r.get('truncated') or int(r.get('fragment_total') or 1)>1 for r in rows) else 'completed','records':min(len(rows),room),'detail':'Son 7 gün / en fazla 200 olay. Boş kayıt, etkin denetim veya temiz cihaz kanıtı değildir.'})
            except (OSError,ValueError,ET.ParseError,subprocess.SubprocessError) as exc:coverage.append({'source':channel,'status':'unavailable','detail':str(exc)[:240]})
    findings=analyze(records,cancel)
    component={'name':'Komut geçmişi / iz silme belirtileri','status':'partial' if any(x['status']!='completed' for x in coverage) else 'completed','records':len(records),'detail':'Salt okunur, sınırlı kayıtlar; CMD için kalıcı genel geçmiş garanti edilmez. Kayıt yokluğu silme kanıtı değildir; kodun yapay zekadan geldiği belirlenemez.'}
    return {'commands':records,'command_coverage':coverage},findings,component
