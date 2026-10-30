"""Windows registry, Prefetch and NTFS USN readers. Read handles only."""
import ctypes as c
from pathlib import Path
import json,os,struct,time,subprocess
from datetime import datetime,timezone,timedelta
from .collectors import run


def filetime(value):
    try:
        when=datetime(1601,1,1,tzinfo=timezone.utc)+timedelta(microseconds=int(value)//10)
        return when.isoformat() if datetime(2000,1,1,tzinfo=timezone.utc)<when<datetime.now(timezone.utc)+timedelta(days=1) else ''
    except (ValueError,OverflowError):return ''


def parse_usn(data,volume=''):
    rows=[];offset=8
    while offset+8<=len(data):
        length,major,minor=struct.unpack_from('<IHH',data,offset)
        if length<8 or offset+length>len(data):raise ValueError('Bozuk USN kayıt uzunluğu')
        if major in (2,3):
            minimum=60 if major==2 else 76
            if length<minimum:raise ValueError('Kısa USN kaydı')
            width=8 if major==2 else 16;pos=offset+8+2*width
            usn,stamp,reason=struct.unpack_from('<qQI',data,pos)
            name_len,name_offset=struct.unpack_from('<HH',data,offset+minimum-4)
            if name_offset<minimum or name_len%2 or name_offset+name_len>length:raise ValueError('Bozuk USN dosya adı alanı')
            name=data[offset+name_offset:offset+name_offset+name_len].decode('utf-16-le')
            rows.append({'volume':volume,'name':name,'usn':usn,'timestamp':filetime(stamp),'reason':hex(reason),
                         'file_ref':data[offset+8:offset+8+width].hex(),'parent_ref':data[offset+8+width:offset+8+2*width].hex(),'version':major})
        offset+=length
    return rows


def usn_records(roots,cancel):
    k=c.WinDLL('kernel32',use_last_error=True)
    k.CreateFileW.argtypes=[c.c_wchar_p,c.c_ulong,c.c_ulong,c.c_void_p,c.c_ulong,c.c_ulong,c.c_void_p];k.CreateFileW.restype=c.c_void_p
    k.DeviceIoControl.argtypes=[c.c_void_p,c.c_ulong,c.c_void_p,c.c_ulong,c.c_void_p,c.c_ulong,c.POINTER(c.c_ulong),c.c_void_p];k.DeviceIoControl.restype=c.c_int
    k.CloseHandle.argtypes=[c.c_void_p]
    rows=[];issues=[];truncated=False
    for root in roots:
        volume=Path(root).drive
        if not volume:continue
        handle=k.CreateFileW('\\\\.\\'+volume,0x80000000,3,None,3,0,None)
        if handle==c.c_void_p(-1).value:issues.append(volume+': '+str(c.WinError(c.get_last_error())));continue
        try:
            output=c.create_string_buffer(1024*1024);returned=c.c_ulong()
            if not k.DeviceIoControl(handle,0x900f4,None,0,output,len(output),c.byref(returned),None):raise c.WinError(c.get_last_error())
            journal,first,last=struct.unpack_from('<Qqq',output.raw)
            cursor=first;deadline=time.monotonic()+10
            while cursor<last and not cancel.is_set():
                request=struct.pack('<qIIQQQ',cursor,0xffffffff,0,0,0,journal);buf=c.create_string_buffer(request)
                if not k.DeviceIoControl(handle,0x900bb,buf,len(request),output,len(output),c.byref(returned),None):raise c.WinError(c.get_last_error())
                if returned.value<=8:break
                payload=output.raw[:returned.value];next_usn=struct.unpack_from('<q',payload)[0]
                rows.extend(parse_usn(payload,volume))
                if next_usn<=cursor:break
                cursor=next_usn
                if len(rows)>=20000 or time.monotonic()>deadline:truncated=True;break
        except (OSError,ValueError,struct.error) as exc:issues.append(volume+': '+str(exc))
        finally:k.CloseHandle(handle)
    return rows[:20000],issues,truncated


def decode_prefetch(data):
    if data[:3]==b'MAM':
        if len(data)<8:raise ValueError('Kısa MAM başlığı')
        size=struct.unpack_from('<I',data,4)[0]
        if size>16*1024*1024:raise ValueError('Prefetch açma boyutu sınırı')
        n=c.WinDLL('ntdll');workspace_size=c.c_ulong();fragment=c.c_ulong()
        n.RtlGetCompressionWorkSpaceSize.argtypes=[c.c_ushort,c.POINTER(c.c_ulong),c.POINTER(c.c_ulong)];n.RtlGetCompressionWorkSpaceSize.restype=c.c_long
        status=n.RtlGetCompressionWorkSpaceSize(4,c.byref(workspace_size),c.byref(fragment))
        if status<0:raise ValueError('MAM çalışma alanı okunamadı')
        workspace=c.create_string_buffer(workspace_size.value);output=c.create_string_buffer(size);final=c.c_ulong()
        offset=12 if data[3]&0x80 else 8;source=c.create_string_buffer(data[offset:])
        n.RtlDecompressBufferEx.argtypes=[c.c_ushort,c.c_void_p,c.c_ulong,c.c_void_p,c.c_ulong,c.POINTER(c.c_ulong),c.c_void_p];n.RtlDecompressBufferEx.restype=c.c_long
        status=n.RtlDecompressBufferEx(4,output,size,source,len(data)-offset,c.byref(final),workspace)
        if status<0:raise ValueError('MAM açma başarısız: '+hex(status&0xffffffff))
        data=output.raw[:final.value]
    if len(data)<84 or data[4:8]!=b'SCCA':raise ValueError('Geçersiz Prefetch başlığı')
    version=struct.unpack_from('<I',data)[0];name=data[16:76].decode('utf-16-le').split('\0')[0]
    offsets=[120] if version==17 else [128] if version==23 else list(range(128,192,8)) if version in (26,30,31) else []
    times=[filetime(struct.unpack_from('<Q',data,p)[0]) for p in offsets if p+8<=len(data)]
    return {'name':name,'format_version':version,'recorded_run_times':[s for s in times if s]}


def registry_records():
    import winreg as w
    startup=[];usb=[];activity=[];errors=[]
    def enum(key):
        i=0
        while True:
            try:yield w.EnumKey(key,i);i+=1
            except OSError:break
    def values(hive,path,category):
        try:
            with w.OpenKey(hive,path) as key:
                for i in range(w.QueryInfoKey(key)[1]):
                    name,value,kind=w.EnumValue(key,i)
                    startup.append({'type':category,'source':path,'name':name,'value':value.hex() if isinstance(value,bytes) else value})
        except FileNotFoundError:pass
        except OSError as exc:errors.append(path+': '+str(exc))
    for hive in (w.HKEY_CURRENT_USER,w.HKEY_LOCAL_MACHINE):
        for branch in ['Software/Microsoft/Windows/CurrentVersion/Run','Software/Microsoft/Windows/CurrentVersion/RunOnce','Software/WOW6432Node/Microsoft/Windows/CurrentVersion/Run']:
            values(hive,branch.replace('/','\\'),'Run')
    for path in [r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',r'SYSTEM\CurrentControlSet\Control\Session Manager']:
        values(w.HKEY_LOCAL_MACHINE,path,'Sistem başlangıcı')
    for path in [r'SYSTEM\CurrentControlSet\Enum\USBSTOR',r'SYSTEM\CurrentControlSet\Enum\USB']:
        try:
            with w.OpenKey(w.HKEY_LOCAL_MACHINE,path) as root:
                for device in enum(root):
                    with w.OpenKey(root,device) as dev:
                        for serial in enum(dev):
                            try:
                                with w.OpenKey(dev,serial) as key:
                                    item={'device':device,'source':path,'registry_modified':filetime(w.QueryInfoKey(key)[2])}
                                    for field in ['FriendlyName','DeviceDesc','Mfg']:
                                        try:item[field]=w.QueryValueEx(key,field)[0]
                                        except OSError:pass
                                    usb.append(item)
                            except OSError:pass
        except FileNotFoundError:pass
        except OSError as exc:errors.append(str(exc))
    try:
        path=r'SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
        with w.OpenKey(w.HKEY_LOCAL_MACHINE,path) as root:
            for sid in enum(root):
                with w.OpenKey(root,sid) as key:
                    for i in range(w.QueryInfoKey(key)[1]):
                        name,value,kind=w.EnumValue(key,i)
                        if isinstance(value,bytes) and len(value)>=8:
                            activity.append({'source':'BAM','user':sid,'path':name,'timestamp':filetime(struct.unpack_from('<Q',value)[0])})
    except FileNotFoundError:pass
    except OSError as exc:errors.append('BAM: '+str(exc))
    return {'startup':startup,'usb':usb,'execution':activity},errors


PS_SCRIPT=r'''
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$r = @{}; $errs = @()
try {$r.services = @(Get-CimInstance Win32_Service -ErrorAction Stop | Select-Object Name,DisplayName,PathName,StartMode,State)} catch {$errs += $_.Exception.Message}
try {$r.drivers = @(Get-CimInstance Win32_SystemDriver -ErrorAction Stop | Select-Object Name,PathName,StartMode,State)} catch {$errs += $_.Exception.Message}
try {$r.tasks = @(Get-ScheduledTask -ErrorAction Stop | ForEach-Object { [pscustomobject]@{name=$_.TaskName;path=$_.TaskPath;state=[string]$_.State;actions=@($_.Actions | Select-Object Execute,Arguments,WorkingDirectory)}})} catch {$errs += $_.Exception.Message}
try {$r.events = @(Get-WinEvent -FilterHashtable @{LogName='System';Id=12,13,6005,6006,1074,7001,7002} -MaxEvents 300 -ErrorAction Stop | Select-Object @{n='timestamp';e={$_.TimeCreated.ToUniversalTime().ToString('o')}},Id,ProviderName,Message)} catch {$errs += $_.Exception.Message}
try {$r.connected_usb = @(Get-CimInstance Win32_PnPEntity -Filter "PNPDeviceID LIKE 'USB%'" -ErrorAction Stop | Select-Object Name,Status)} catch {$errs += $_.Exception.Message}
$r.errors = $errs
ConvertTo-Json -InputObject $r -Depth 6 -Compress
'''


def windows_records(roots,cancel):
    rows,errors=registry_records();components=[]
    try:
        extra=json.loads(run(['powershell.exe','-NoProfile','-NonInteractive','-Command',PS_SCRIPT],timeout=90))
        errors+=extra.pop('errors',[]);rows.update(extra)
    except subprocess.TimeoutExpired:errors.append('Windows sistem envanteri 90 saniyede tamamlanamadı')
    except Exception as exc:errors.append('Windows envanteri: '+str(exc)[:400])
    components.append({'name':'Başlangıç / servis / görev / USB / olaylar','status':'partial' if errors else 'completed','records':sum(len(v) for v in rows.values()),'detail':'; '.join(errors)[:1200] or 'Registry ve Windows CIM/Event Log kayıtları salt okunur alındı.'})
    prefetch=[];pf_errors=[]
    folder=Path(os.environ.get('SystemRoot','C:/Windows'))/'Prefetch'
    try:
        for p in folder.glob('*.pf'):
            if cancel.is_set():break
            try:
                if p.stat().st_size>16*1024*1024:raise ValueError('Prefetch boyut sınırı')
                prefetch.append(dict(decode_prefetch(p.read_bytes()),path=str(p)))
            except (OSError,ValueError) as exc:pf_errors.append(p.name+': '+str(exc))
        if not prefetch:
            try:list(folder.iterdir())
            except OSError as exc:pf_errors.append(str(exc))
    except OSError as exc:pf_errors.append(str(exc))
    rows['prefetch']=prefetch
    components.append({'name':'Prefetch','status':'partial' if pf_errors else 'completed','records':len(prefetch),'detail':'; '.join(pf_errors)[:800] or 'SCCA / MAM kayıtları. Zamanlar biçimden okundu; dosya mtime değeri çalışma zamanı sayılmaz.'})
    journal,errors,truncated=usn_records(roots,cancel);rows['journal']=journal
    components.append({'name':'NTFS USN Journal','status':'unavailable' if errors and not journal else 'partial' if errors or truncated else 'completed','records':len(journal),'detail':'; '.join(errors)[:800] or ('20000 kayıt / sürücü başına 10 saniye sınırı; tam günlük değildir.' if truncated else 'USN v2/v3 dosya adı, zaman, neden ve parent/file referansları okundu.')})
    return rows,components
